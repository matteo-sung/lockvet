package adopr

import (
	"encoding/json"
	"fmt"
	"strings"
)

// marker identifies an earlier lockvet comment so reruns update it in
// place. Like Bitbucket, Azure DevOps may show raw HTML comments as text,
// so instead of ghpr.CommentMarker we rely on the report's own stable
// heading (see render.go — keep them in sync).
const marker = "### 🔍 lockvet report"

type thread struct {
	ID       int64 `json:"id"`
	Comments []struct {
		ID        int64  `json:"id"`
		Content   string `json:"content"`
		IsDeleted bool   `json:"isDeleted"`
	} `json:"comments"`
}

// PostComment creates — or, if a lockvet comment already exists, updates —
// the report comment thread on a pull request. The thread is created with
// status "closed" so branch policies that require comment resolution are
// never blocked by a report. Returns the PR's web URL and whether an
// existing comment was updated. Requires a token that can contribute to
// pull requests (AZURE_DEVOPS_TOKEN with Code: Read & Write, or Azure
// Pipelines' SYSTEM_ACCESSTOKEN).
func PostComment(ref Ref, body string) (commentURL string, updated bool, err error) {
	c := newClient(ref.Instance, ref.Project)
	return c.postComment(ref, body)
}

func (c *client) postComment(ref Ref, body string) (string, bool, error) {
	if !c.authed() {
		return "", false, fmt.Errorf("posting a comment requires authentication — set AZURE_DEVOPS_TOKEN to a personal access token with Code: Read & Write (in Azure Pipelines, map SYSTEM_ACCESSTOKEN)")
	}
	webURL := fmt.Sprintf("%s/%s/_git/%s/pullrequest/%d", ref.Instance, ref.Project, ref.Repo, ref.ID)

	var threads struct {
		Value []thread `json:"value"`
	}
	if err := c.getJSON(fmt.Sprintf("repositories/%s/pullRequests/%d/threads?api-version=7.1", ref.Repo, ref.ID), &threads); err != nil {
		return "", false, err
	}
	for _, t := range threads.Value {
		for _, cm := range t.Comments {
			if cm.IsDeleted || !strings.HasPrefix(strings.TrimSpace(cm.Content), marker) {
				continue
			}
			payload, err := json.Marshal(map[string]string{"content": body})
			if err != nil {
				return "", false, err
			}
			err = c.sendJSON("PATCH", fmt.Sprintf("repositories/%s/pullRequests/%d/threads/%d/comments/%d?api-version=7.1",
				ref.Repo, ref.ID, t.ID, cm.ID), payload, nil)
			return webURL, true, err
		}
	}

	payload, err := json.Marshal(map[string]any{
		"comments": []map[string]any{{"parentCommentId": 0, "content": body, "commentType": "text"}},
		"status":   "closed",
	})
	if err != nil {
		return "", false, err
	}
	err = c.sendJSON("POST", fmt.Sprintf("repositories/%s/pullRequests/%d/threads?api-version=7.1", ref.Repo, ref.ID), payload, nil)
	return webURL, false, err
}
