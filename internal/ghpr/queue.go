package ghpr

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// QueueItem is one open dependency-update pull request found by ListQueue.
type QueueItem struct {
	Ref     Ref
	Title   string
	Author  string // e.g. "dependabot[bot]"
	URL     string // html_url
	Updated time.Time
}

// DefaultQueueAuthors are the bot identities searched for when the user
// doesn't pass -author. The app/ prefix matches GitHub App bot accounts
// (dependabot[bot], renovate[bot]).
var DefaultQueueAuthors = []string{"app/dependabot", "app/renovate"}

// ListQueue finds open pull requests by the given authors in scope, which is
// either "owner/repo" or a user/org name. Authors may be empty ("any") to
// match every open PR. Results are most-recently-updated first, capped at
// limit. The returned string describes the search scope (e.g. "org:grafana")
// for display.
func ListQueue(scope string, authors []string, limit int) ([]QueueItem, string, error) {
	return newClient().listQueue(scope, authors, limit)
}

func (c *client) listQueue(scope string, authors []string, limit int) ([]QueueItem, string, error) {
	var qual string
	if strings.Contains(scope, "/") {
		owner, repo, _ := strings.Cut(scope, "/")
		if owner == "" || repo == "" || strings.Contains(repo, "/") {
			return nil, "", fmt.Errorf("cannot parse %q (want owner/repo or an owner name)", scope)
		}
		qual = "repo:" + scope
	} else {
		// user: and org: are distinct search qualifiers; ask the API
		// which kind of account this is.
		var acct struct {
			Type string `json:"type"`
		}
		if err := c.getJSON("users/"+url.PathEscape(scope), &acct); err != nil {
			return nil, "", fmt.Errorf("looking up %q: %w", scope, err)
		}
		if acct.Type == "Organization" {
			qual = "org:" + scope
		} else {
			qual = "user:" + scope
		}
	}

	q := "is:pr is:open archived:false " + qual
	for _, a := range authors {
		q += " author:" + a // repeated author: qualifiers are OR'd
	}

	var items []QueueItem
	for page := 1; len(items) < limit && page <= 10; page++ {
		per := limit - len(items)
		if per > 100 {
			per = 100
		}
		var res struct {
			TotalCount int `json:"total_count"`
			Items      []struct {
				Number        int       `json:"number"`
				Title         string    `json:"title"`
				HTMLURL       string    `json:"html_url"`
				UpdatedAt     time.Time `json:"updated_at"`
				RepositoryURL string    `json:"repository_url"`
				User          struct {
					Login string `json:"login"`
				} `json:"user"`
				PullRequest *struct{} `json:"pull_request"`
			} `json:"items"`
		}
		path := fmt.Sprintf("search/issues?q=%s&sort=updated&order=desc&per_page=%d&page=%d",
			url.QueryEscape(q), per, page)
		if err := c.getJSON(path, &res); err != nil {
			if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "429") {
				err = fmt.Errorf("%w\nhint: the GitHub search API has a tight per-minute limit — wait a minute and retry", err)
			}
			return nil, "", err
		}
		for _, it := range res.Items {
			if it.PullRequest == nil {
				continue
			}
			owner, repo, ok := splitRepoURL(it.RepositoryURL)
			if !ok {
				continue
			}
			items = append(items, QueueItem{
				Ref:     Ref{Owner: owner, Repo: repo, Number: it.Number},
				Title:   it.Title,
				Author:  it.User.Login,
				URL:     it.HTMLURL,
				Updated: it.UpdatedAt,
			})
		}
		if len(res.Items) < per || len(items) >= res.TotalCount {
			break
		}
	}
	return items, qual, nil
}

// splitRepoURL extracts owner and repo from an API repository_url like
// https://api.github.com/repos/OWNER/REPO.
func splitRepoURL(u string) (owner, repo string, ok bool) {
	_, tail, found := strings.Cut(u, "/repos/")
	if !found {
		return "", "", false
	}
	owner, repo, found = strings.Cut(tail, "/")
	if !found || owner == "" || repo == "" || strings.Contains(repo, "/") {
		return "", "", false
	}
	return owner, repo, true
}
