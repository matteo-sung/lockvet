package bbpr

import (
	"encoding/json"
	"fmt"
	"strings"
)

// marker is what identifies an earlier lockvet comment so reruns update it
// in place. Bitbucket Cloud renders HTML comments as visible text, so
// instead of ghpr.CommentMarker we rely on the report's own stable heading
// (see render.go — keep them in sync).
const marker = "### 🔍 lockvet report"

type prComment struct {
	ID      int64 `json:"id"`
	Deleted bool  `json:"deleted"`
	Content struct {
		Raw string `json:"raw"`
	} `json:"content"`
	Links struct {
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
	} `json:"links"`
}

// PostComment creates — or, if a lockvet comment already exists, updates —
// the report comment on a pull request. Returns the comment's URL and
// whether an existing comment was updated. Requires authentication
// (BITBUCKET_TOKEN, or BITBUCKET_USERNAME + BITBUCKET_APP_PASSWORD).
func PostComment(ref Ref, body string) (commentURL string, updated bool, err error) {
	c := newClient()
	return c.postComment(ref, body)
}

func (c *client) postComment(ref Ref, body string) (string, bool, error) {
	if !c.authed() {
		return "", false, fmt.Errorf("posting a comment requires authentication — set BITBUCKET_TOKEN (repository access token with pullrequest:write), or BITBUCKET_USERNAME + BITBUCKET_APP_PASSWORD")
	}
	full := body

	var existing *prComment
	next := c.api + fmt.Sprintf("repositories/%s/%s/pullrequests/%d/comments?pagelen=100",
		ref.Workspace, ref.Repo, ref.ID)
	for i := 0; i < 30 && next != "" && existing == nil; i++ {
		if !strings.HasPrefix(next, c.api) {
			return "", false, fmt.Errorf("Bitbucket API returned an unexpected page URL: %s", next)
		}
		var page struct {
			Values []prComment `json:"values"`
			Next   string      `json:"next"`
		}
		if err := c.getJSONURL(next, &page); err != nil {
			return "", false, err
		}
		for i := range page.Values {
			if !page.Values[i].Deleted && strings.HasPrefix(strings.TrimSpace(page.Values[i].Content.Raw), marker) {
				existing = &page.Values[i]
				break
			}
		}
		next = page.Next
	}

	payload, err := json.Marshal(map[string]any{"content": map[string]string{"raw": full}})
	if err != nil {
		return "", false, err
	}
	var out prComment
	if existing != nil {
		err := c.sendJSON("PUT", fmt.Sprintf("repositories/%s/%s/pullrequests/%d/comments/%d",
			ref.Workspace, ref.Repo, ref.ID, existing.ID), payload, &out)
		return out.Links.HTML.Href, true, err
	}
	err = c.sendJSON("POST", fmt.Sprintf("repositories/%s/%s/pullrequests/%d/comments",
		ref.Workspace, ref.Repo, ref.ID), payload, &out)
	return out.Links.HTML.Href, false, err
}
