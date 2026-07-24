package glmr

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

// QueueItem is one open dependency-update merge request found by ListQueue.
type QueueItem struct {
	Ref     Ref
	Title   string
	Author  string
	URL     string // web_url
	Updated time.Time
}

// DefaultQueueAuthors are the bot usernames queried when the user doesn't
// pass -author. GitLab bot identities vary per instance (e.g. gitlab-org's
// Renovate runs as gitlab-dependency-update-bot), so custom bots need an
// explicit -author.
var DefaultQueueAuthors = []string{"renovate-bot", "dependabot"}

// ListQueue finds open merge requests by the given authors in scope, which
// is a project path ("group/project") or a group path ("group" or
// "group/subgroup"; subgroup projects are included). Authors may be empty
// to match every open MR. Results are most-recently-updated first, capped
// at limit. The returned string describes the scope (e.g. "group:gitlab-org")
// for display.
//
// GitLab's author_username filter is single-valued, so one request (per
// page) is made for each author.
func ListQueue(host, scope string, authors []string, limit int) ([]QueueItem, string, error) {
	c := newClient(host)
	scope = strings.Trim(scope, "/")
	if scope == "" {
		return nil, "", fmt.Errorf("empty scope (want a GitLab group or project path)")
	}

	// A path with a slash can be a project or a subgroup; try the project
	// MR endpoint first, fall back to the group one. A single segment can
	// only be a group (user namespaces have no MR listing).
	kinds := []string{"groups"}
	if strings.Contains(scope, "/") {
		kinds = []string{"projects", "groups"}
	}

	var items []QueueItem
	var lastErr error
	for _, kind := range kinds {
		items, lastErr = c.listQueueIn(kind, scope, authors, limit)
		if lastErr == nil {
			label := "group:" + scope
			if kind == "projects" {
				label = "project:" + scope
			}
			if c.host != "gitlab.com" {
				label += " @ " + c.host
			}
			return items, label, nil
		}
		if !strings.Contains(lastErr.Error(), "404") {
			break
		}
	}
	if lastErr != nil && strings.Contains(lastErr.Error(), "404") {
		lastErr = fmt.Errorf("%w\nhint: %q wasn't found as a project or group on %s — check the path (user namespaces aren't supported; pass a group or group/project)", lastErr, scope, c.host)
	}
	return nil, "", lastErr
}

func (c *client) listQueueIn(kind, scope string, authors []string, limit int) ([]QueueItem, error) {
	queries := authors
	if len(queries) == 0 {
		queries = []string{""} // one unfiltered pass
	}
	var items []QueueItem
	for _, author := range queries {
		got, err := c.listQueuePages(kind, scope, author, limit)
		if err != nil {
			return nil, err
		}
		items = append(items, got...)
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].Updated.After(items[j].Updated) })
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (c *client) listQueuePages(kind, scope, author string, limit int) ([]QueueItem, error) {
	var items []QueueItem
	for page := 1; len(items) < limit && page <= 10; page++ {
		per := limit - len(items)
		if per > 100 {
			per = 100
		}
		path := fmt.Sprintf("%s/%s/merge_requests?state=opened&order_by=updated_at&sort=desc&per_page=%d&page=%d",
			kind, url.PathEscape(scope), per, page)
		if kind == "groups" {
			path += "&non_archived=true"
		}
		if author != "" {
			path += "&author_username=" + url.QueryEscape(author)
		}
		var res []struct {
			IID       int       `json:"iid"`
			Title     string    `json:"title"`
			WebURL    string    `json:"web_url"`
			UpdatedAt time.Time `json:"updated_at"`
			Author    struct {
				Username string `json:"username"`
			} `json:"author"`
			References struct {
				Full string `json:"full"` // "group/project!123"
			} `json:"references"`
		}
		if err := c.getJSON(path, &res); err != nil {
			return nil, err
		}
		for _, mr := range res {
			ref := Ref{Host: c.host, Project: scope, IID: mr.IID}
			if proj, _, ok := strings.Cut(mr.References.Full, "!"); ok && proj != "" {
				ref.Project = proj
			} else if r, ok := ParseMR(mr.WebURL); ok {
				ref = r
			}
			items = append(items, QueueItem{
				Ref:     ref,
				Title:   mr.Title,
				Author:  mr.Author.Username,
				URL:     mr.WebURL,
				Updated: mr.UpdatedAt,
			})
		}
		if len(res) < per {
			break
		}
	}
	return items, nil
}
