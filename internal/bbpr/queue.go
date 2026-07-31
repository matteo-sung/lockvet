package bbpr

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// QueueItem is one open dependency-update pull request found by ListQueue.
type QueueItem struct {
	Ref     Ref
	Title   string
	Author  string
	URL     string // html link
	Updated time.Time
}

// DefaultQueueAuthors are the bot identities looked for when the user
// doesn't pass -author. Bitbucket bots frequently run as app users (access
// tokens) whose only name is a display name, so author specs also match
// display names loosely — "renovate-bot" finds "atlassian-renovate-bot".
var DefaultQueueAuthors = []string{"renovate-bot", "dependabot"}

// HasToken reports whether Bitbucket credentials are configured in the
// environment.
func HasToken() bool { return newClient().authed() }

// maxScanPages caps how many 50-item pages of a repo's open PRs are scanned
// for author matches (the author filter is applied client-side).
const maxScanPages = 10

// maxScanRepos caps how many of a workspace's most-recently-updated repos
// are scanned when the by-author endpoint can't be used (author "any", or
// no author spec matched a real username).
const maxScanRepos = 20

// queuePR is the subset of a Bitbucket pull request object the queue needs.
type queuePR struct {
	ID     int    `json:"id"`
	Title  string `json:"title"`
	Author struct {
		Nickname    string `json:"nickname"`
		DisplayName string `json:"display_name"`
		UUID        string `json:"uuid"`
	} `json:"author"`
	UpdatedOn   time.Time `json:"updated_on"`
	Destination struct {
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
	} `json:"destination"`
	Links struct {
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
	} `json:"links"`
}

func (p queuePR) authorName() string {
	if p.Author.Nickname != "" {
		return p.Author.Nickname
	}
	return p.Author.DisplayName
}

// matchAuthor reports whether a PR author matches one of the author specs.
// Specs match the nickname (username) and uuid exactly (case-insensitively)
// and the display name as a substring, because Bitbucket app users have no
// username at all.
func matchAuthor(p queuePR, want []string) bool {
	if len(want) == 0 {
		return true
	}
	nick := strings.ToLower(p.Author.Nickname)
	uuid := strings.ToLower(p.Author.UUID)
	disp := strings.ToLower(p.Author.DisplayName)
	for _, w := range want {
		w = strings.ToLower(w)
		if w == nick || w == uuid || (disp != "" && strings.Contains(disp, w)) {
			return true
		}
	}
	return false
}

// ListQueue finds open pull requests by the given authors in scope on
// Bitbucket Cloud. Scope is "workspace" (all its repositories) or
// "workspace/repo". Authors may be empty to match every open PR. Results
// are most-recently-updated first, capped at limit. The returned string
// describes the scope (e.g. "workspace:atlassian") for display; scanned
// reports whether only the workspace's most-recently-updated repositories
// could be scanned (rather than an exact server-side author search).
//
// Repo scope lists the repo's open PRs (newest first) and filters by
// author client-side. Workspace scope uses the by-author endpoint for
// specs that are real usernames or {uuid}s; when none are (Bitbucket bots
// are often app users), it falls back to scanning the maxScanRepos
// most-recently-updated repositories. A non-empty note explains fallbacks
// and partial results and should be shown to the user.
func ListQueue(scope string, authors []string, limit int) (items []QueueItem, label, note string, err error) {
	c := newClient()
	scope = strings.Trim(scope, "/")
	if scope == "" {
		return nil, "", "", fmt.Errorf("empty scope (want a workspace or workspace/repo path)")
	}
	if strings.Contains(scope, "/") {
		ws, repo, _ := strings.Cut(scope, "/")
		if ws == "" || repo == "" || strings.Contains(repo, "/") {
			return nil, "", "", fmt.Errorf("cannot parse %q (want workspace or workspace/repo)", scope)
		}
		items, err = c.queueRepo(ws, repo, authors, limit)
		return items, "repo:" + scope, "", err
	}

	if len(authors) > 0 {
		items, err = c.queueByAuthor(scope, authors, limit)
		if err != nil {
			return nil, "", "", err
		}
		if len(items) > 0 {
			return items, "workspace:" + scope, "", nil
		}
		// No spec resolved to a username with open PRs — the bot may be
		// an app user; fall through to the repo scan.
		note = "no server-side author match — scanning the workspace's most-recently-updated repositories instead"
	}
	items, scanNote, err := c.queueScanWorkspace(scope, authors, limit)
	if scanNote != "" {
		if note != "" {
			note += "; " + scanNote
		} else {
			note = scanNote
		}
	}
	return items, "workspace:" + scope, note, err
}

const queueFields = "next,values.id,values.title,values.updated_on," +
	"values.author.nickname,values.author.display_name,values.author.uuid," +
	"values.destination.repository.full_name,values.links.html.href"

// queueRepo lists a repository's open PRs, newest-updated first, filtering
// by author client-side.
func (c *client) queueRepo(ws, repo string, authors []string, limit int) ([]QueueItem, error) {
	next := c.api + fmt.Sprintf("repositories/%s/%s/pullrequests?state=OPEN&sort=-updated_on&pagelen=50&fields=%s",
		url.PathEscape(ws), url.PathEscape(repo), url.QueryEscape(queueFields))
	var items []QueueItem
	for page := 1; next != "" && len(items) < limit && page <= maxScanPages; page++ {
		var res struct {
			Next   string    `json:"next"`
			Values []queuePR `json:"values"`
		}
		if err := c.getJSONURL(next, &res); err != nil {
			if strings.Contains(err.Error(), "404") {
				err = fmt.Errorf("%w\nhint: %q wasn't found on bitbucket.org — check the workspace/repo path", err, ws+"/"+repo)
			}
			return nil, err
		}
		for _, pr := range res.Values {
			if !matchAuthor(pr, authors) {
				continue
			}
			items = append(items, queueItemFrom(pr, ws, repo))
			if len(items) >= limit {
				break
			}
		}
		next = res.Next
	}
	return items, nil
}

// queueByAuthor queries the workspace-wide open-PRs-by-author endpoint once
// per author spec. Specs that aren't a real username or {uuid} (404) are
// skipped — Bitbucket app users can't be addressed by name.
func (c *client) queueByAuthor(ws string, authors []string, limit int) ([]QueueItem, error) {
	var items []QueueItem
	seen := map[string]bool{}
	for _, a := range authors {
		next := c.api + fmt.Sprintf("workspaces/%s/pullrequests/%s?sort=-updated_on&pagelen=50&fields=%s",
			url.PathEscape(ws), url.PathEscape(a), url.QueryEscape(queueFields))
		for page := 1; next != "" && len(items) < limit && page <= maxScanPages; page++ {
			var res struct {
				Next   string    `json:"next"`
				Values []queuePR `json:"values"`
			}
			if err := c.getJSONURL(next, &res); err != nil {
				if strings.Contains(err.Error(), "404") {
					// Unknown username — or unknown workspace; probe the
					// workspace so a typo'd workspace still errors.
					if page == 1 {
						var v struct{}
						if werr := c.getJSON("workspaces/"+url.PathEscape(ws)+"?fields=slug", &v); werr != nil {
							return nil, fmt.Errorf("%w\nhint: %q wasn't found on bitbucket.org — check the workspace name", werr, ws)
						}
						break // workspace exists; author doesn't — skip
					}
				}
				return nil, err
			}
			for _, pr := range res.Values {
				ws2, repo, ok := strings.Cut(pr.Destination.Repository.FullName, "/")
				if !ok {
					continue
				}
				it := queueItemFrom(pr, ws2, repo)
				key := fmt.Sprintf("%s/%s#%d", ws2, repo, pr.ID)
				if seen[key] {
					continue
				}
				seen[key] = true
				items = append(items, it)
				if len(items) >= limit {
					break
				}
			}
			next = res.Next
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Updated.After(items[j].Updated) })
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

// queueScanWorkspace lists the workspace's most-recently-updated repos and
// scans the first page of each one's open PRs, filtering by author
// client-side. Hitting the rate limit mid-scan yields the results so far
// plus an explanatory note rather than an error.
func (c *client) queueScanWorkspace(ws string, authors []string, limit int) ([]QueueItem, string, error) {
	var repos struct {
		Values []struct {
			Slug string `json:"slug"`
		} `json:"values"`
	}
	path := fmt.Sprintf("repositories/%s?sort=-updated_on&pagelen=%d&fields=values.slug", url.PathEscape(ws), maxScanRepos)
	if err := c.getJSON(path, &repos); err != nil {
		if strings.Contains(err.Error(), "404") {
			err = fmt.Errorf("%w\nhint: %q wasn't found on bitbucket.org — check the workspace name", err, ws)
		}
		return nil, "", err
	}
	var items []QueueItem
	note := ""
	for i, r := range repos.Values {
		var res struct {
			Values []queuePR `json:"values"`
		}
		p := fmt.Sprintf("repositories/%s/%s/pullrequests?state=OPEN&sort=-updated_on&pagelen=50&fields=%s",
			url.PathEscape(ws), url.PathEscape(r.Slug), url.QueryEscape(queueFields))
		if err := c.getJSON(p, &res); err != nil {
			if strings.Contains(err.Error(), "429") && len(items) > 0 {
				note = fmt.Sprintf("rate limited after scanning %d of %d repositories — results are partial; set BITBUCKET_TOKEN to raise the limit", i, len(repos.Values))
				break
			}
			return items, "", err
		}
		for _, pr := range res.Values {
			if !matchAuthor(pr, authors) {
				continue
			}
			items = append(items, queueItemFrom(pr, ws, r.Slug))
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Updated.After(items[j].Updated) })
	if len(items) > limit {
		items = items[:limit]
	}
	return items, note, nil
}

func queueItemFrom(pr queuePR, ws, repo string) QueueItem {
	u := pr.Links.HTML.Href
	if u == "" {
		u = fmt.Sprintf("https://bitbucket.org/%s/%s/pull-requests/%d", ws, repo, pr.ID)
	}
	return QueueItem{
		Ref:     Ref{Workspace: ws, Repo: repo, ID: pr.ID},
		Title:   pr.Title,
		Author:  pr.authorName(),
		URL:     u,
		Updated: pr.UpdatedOn,
	}
}
