package adopr

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
	Author  string
	URL     string // web link
	Updated time.Time
}

// DefaultQueueAuthors are the bot identities looked for when the user
// doesn't pass -author. Azure DevOps has no canonical bot account — the
// Dependabot extension and self-hosted Renovate post as whatever identity
// they're given — so author specs match display names loosely:
// "renovate" finds "Renovate Bot".
var DefaultQueueAuthors = []string{"dependabot", "renovate"}

// HasToken reports whether an Azure DevOps token is configured in the
// environment.
func HasToken() bool {
	return firstEnv("AZURE_DEVOPS_TOKEN", "AZURE_DEVOPS_EXT_PAT", "ADO_TOKEN", "SYSTEM_ACCESSTOKEN") != ""
}

// maxQueuePages caps how many 100-item pages of open PRs are scanned for
// author matches (the PR list API can only filter creators by GUID, so
// filtering happens client-side).
const maxQueuePages = 10

// queuePR is the subset of an Azure DevOps pull request object the queue
// needs.
type queuePR struct {
	ID        int    `json:"pullRequestId"`
	Title     string `json:"title"`
	CreatedBy struct {
		DisplayName string `json:"displayName"`
		UniqueName  string `json:"uniqueName"`
	} `json:"createdBy"`
	CreationDate time.Time `json:"creationDate"`
	Repository   struct {
		Name string `json:"name"`
	} `json:"repository"`
}

// matchAuthor reports whether a PR author matches one of the author specs.
// Specs match uniqueName (usually an email or service identity) exactly,
// case-insensitively, and displayName as a substring.
func matchAuthor(pr queuePR, want []string) bool {
	if len(want) == 0 {
		return true
	}
	uniq := strings.ToLower(pr.CreatedBy.UniqueName)
	disp := strings.ToLower(pr.CreatedBy.DisplayName)
	for _, w := range want {
		w = strings.ToLower(w)
		if w == uniq || (disp != "" && strings.Contains(disp, w)) {
			return true
		}
	}
	return false
}

// ListQueue finds open (active) pull requests by the given authors in an
// Azure DevOps project, or a single repository of it when repo is non-empty
// (both URL path segments, possibly percent-encoded). Authors may be empty
// to match every open PR. Results are newest first (Azure DevOps orders by
// creation date and PR objects carry no update time), capped at limit. The
// returned string describes the scope for display.
func ListQueue(instance, project, repo string, authors []string, limit int) ([]QueueItem, string, error) {
	c := newClient(instance, project)
	route := "pullrequests"
	if repo != "" {
		route = "repositories/" + repo + "/pullrequests"
	}
	var items []QueueItem
	for page := 0; len(items) < limit && page < maxQueuePages; page++ {
		var res struct {
			Value []queuePR `json:"value"`
		}
		path := fmt.Sprintf("%s?searchCriteria.status=active&$top=100&$skip=%d&api-version=7.1", route, page*100)
		if err := c.getJSON(path, &res); err != nil {
			if strings.Contains(err.Error(), "404") {
				err = fmt.Errorf("%w\nhint: check the project%s path — e.g. lockvet queue dev.azure.com/ORG/PROJECT", err,
					map[bool]string{true: " and repository", false: ""}[repo != ""])
			}
			return nil, "", err
		}
		for _, pr := range res.Value {
			if !matchAuthor(pr, authors) {
				continue
			}
			r := repo
			if r == "" {
				r = url.PathEscape(pr.Repository.Name)
			}
			ref := Ref{Instance: instance, Project: project, Repo: r, ID: pr.ID}
			items = append(items, QueueItem{
				Ref:     ref,
				Title:   pr.Title,
				Author:  pr.CreatedBy.DisplayName,
				URL:     fmt.Sprintf("%s/%s/_git/%s/pullrequest/%d", instance, project, r, pr.ID),
				Updated: pr.CreationDate,
			})
			if len(items) >= limit {
				break
			}
		}
		if len(res.Value) < 100 {
			break
		}
	}
	host := strings.TrimPrefix(strings.TrimPrefix(instance, "https://"), "http://")
	label := "project:" + host + "/" + pathLabel(project)
	if repo != "" {
		label = "repo:" + host + "/" + pathLabel(project) + "/" + pathLabel(repo)
	}
	return items, label, nil
}
