package gtpr

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
	URL     string // html_url
	Updated time.Time
}

// DefaultQueueAuthors are the bot usernames queried when the user doesn't
// pass -author. Gitea/Forgejo have no canonical bot account — self-hosted
// Renovate runs under whatever user it's given (Forgejo's own is
// viceice-bot) — so these are just the common conventions; custom bots
// need an explicit -author.
var DefaultQueueAuthors = []string{"renovate-bot", "dependabot"}

// HasToken reports whether a Gitea/Forgejo API token is configured in the
// environment.
func HasToken() bool {
	return firstEnv("GITEA_TOKEN", "FORGEJO_TOKEN", "CODEBERG_TOKEN") != ""
}

// maxScanPages caps how many 50-item pages of an owner's open PRs are
// scanned for author matches (the search API can't filter by author
// server-side).
const maxScanPages = 10

// ListQueue finds open pull requests by the given authors in scope on a
// Gitea/Forgejo host. Scope is "owner" (user or org; all its repos) or
// "owner/repo". Authors may be empty to match every open PR. Results are
// most-recently-updated first, capped at limit. The returned string
// describes the scope (e.g. "owner:forgejo @ codeberg.org") for display.
//
// Owner scope uses the instance-wide issue search endpoint, which cannot
// filter by author server-side, so up to 10×50 recently-updated open PRs
// are scanned client-side. Repo scope filters server-side (created_by),
// one request per author.
func ListQueue(host, scope string, authors []string, limit int) ([]QueueItem, string, error) {
	c := newClient(host)
	scope = strings.Trim(scope, "/")
	if scope == "" {
		return nil, "", fmt.Errorf("empty scope (want an owner or owner/repo path)")
	}
	if strings.Contains(scope, "/") {
		owner, repo, _ := strings.Cut(scope, "/")
		if owner == "" || repo == "" || strings.Contains(repo, "/") {
			return nil, "", fmt.Errorf("cannot parse %q (want owner or owner/repo)", scope)
		}
		items, err := c.queueRepo(host, owner, repo, authors, limit)
		if err != nil {
			return nil, "", err
		}
		return items, "repo:" + scope + " @ " + c.hostName(), nil
	}
	items, err := c.queueOwner(host, scope, authors, limit)
	if err != nil {
		return nil, "", err
	}
	return items, "owner:" + scope + " @ " + c.hostName(), nil
}

func (c *client) hostName() string {
	h := strings.TrimPrefix(c.base, "https://")
	h = strings.TrimPrefix(h, "http://")
	return strings.TrimSuffix(h, "/api/v1/")
}

// queueIssue is the subset of a Gitea issue object the queue needs. The
// instance-wide search endpoint includes repository; the repo-scoped one
// may not, so the caller falls back to known owner/repo.
type queueIssue struct {
	Number    int       `json:"number"`
	Title     string    `json:"title"`
	HTMLURL   string    `json:"html_url"`
	UpdatedAt time.Time `json:"updated_at"`
	User      struct {
		Login string `json:"login"`
	} `json:"user"`
	Repository *struct {
		Owner    string `json:"owner"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
	} `json:"repository"`
}

func (c *client) queueOwner(host, owner string, authors []string, limit int) ([]QueueItem, error) {
	want := make(map[string]bool, len(authors))
	for _, a := range authors {
		want[strings.ToLower(a)] = true
	}
	var items []QueueItem
	for page := 1; len(items) < limit && page <= maxScanPages; page++ {
		path := fmt.Sprintf("repos/issues/search?type=pulls&state=open&sort=recentupdate&owner=%s&limit=50&page=%d",
			url.QueryEscape(owner), page)
		var res []queueIssue
		if err := c.getJSON(path, &res); err != nil {
			// Nonexistent owners come back as 400 ("user does not
			// exist") on current Gitea/Forgejo, 404 on older ones.
			if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "400") {
				err = fmt.Errorf("%w\nhint: %q wasn't found as a user or organization on %s", err, owner, c.hostName())
			}
			return nil, err
		}
		for _, is := range res {
			if len(want) > 0 && !want[strings.ToLower(is.User.Login)] {
				continue
			}
			it, ok := c.queueItem(host, is, "", "")
			if !ok {
				continue
			}
			items = append(items, it)
			if len(items) >= limit {
				break
			}
		}
		if len(res) < 50 {
			break
		}
	}
	return items, nil
}

func (c *client) queueRepo(host, owner, repo string, authors []string, limit int) ([]QueueItem, error) {
	queries := authors
	if len(queries) == 0 {
		queries = []string{""} // one unfiltered pass
	}
	rp := url.PathEscape(owner) + "/" + url.PathEscape(repo)
	repoKnownOK := false
	var items []QueueItem
	for _, author := range queries {
		for page := 1; page <= 10; page++ {
			per := limit
			if per > 50 {
				per = 50
			}
			path := fmt.Sprintf("repos/%s/issues?type=pulls&state=open&sort=recentupdate&limit=%d&page=%d", rp, per, page)
			if author != "" {
				path += "&created_by=" + url.QueryEscape(author)
			}
			var res []queueIssue
			if err := c.getJSON(path, &res); err != nil {
				if !strings.Contains(err.Error(), "404") {
					return nil, err
				}
				// Gitea 404s an issue listing when the created_by
				// username doesn't exist on the instance. If the repo
				// itself is fine, treat that author as "no PRs".
				if author != "" && !repoKnownOK {
					if c.getJSON("repos/"+rp, &struct{}{}) == nil {
						repoKnownOK = true
					}
				}
				if author != "" && repoKnownOK {
					break // next author
				}
				return nil, fmt.Errorf("%w\nhint: %s/%s wasn't found on %s — check the path (and set GITEA_TOKEN if it's private)", err, owner, repo, c.hostName())
			}
			repoKnownOK = true
			for _, is := range res {
				if it, ok := c.queueItem(host, is, owner, repo); ok {
					items = append(items, it)
				}
			}
			if len(res) < per || len(items) >= limit*len(queries) {
				break
			}
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Updated.After(items[j].Updated) })
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

// queueItem converts an API issue into a QueueItem, resolving the owning
// repository from the payload (or the fallback owner/repo for repo scope).
func (c *client) queueItem(host string, is queueIssue, owner, repo string) (QueueItem, bool) {
	if is.Repository != nil {
		if o, r, ok := strings.Cut(is.Repository.FullName, "/"); ok && o != "" && r != "" && !strings.Contains(r, "/") {
			owner, repo = o, r
		} else if is.Repository.Owner != "" && is.Repository.Name != "" {
			owner, repo = is.Repository.Owner, is.Repository.Name
		}
	}
	if owner == "" || repo == "" || is.Number <= 0 {
		return QueueItem{}, false
	}
	return QueueItem{
		Ref:     Ref{Host: host, Owner: owner, Repo: repo, Index: is.Number},
		Title:   is.Title,
		Author:  is.User.Login,
		URL:     is.HTMLURL,
		Updated: is.UpdatedAt,
	}, true
}
