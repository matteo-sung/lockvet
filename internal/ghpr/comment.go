package ghpr

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CommentMarker prefixes every comment lockvet posts, so reruns update the
// existing comment instead of stacking new ones. The lockvet GitHub Action
// uses the same marker — CLI and Action never duplicate each other.
const CommentMarker = "<!-- lockvet-report -->"

type issueComment struct {
	ID      int64  `json:"id"`
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
}

// PostComment creates — or, if a lockvet comment already exists, updates —
// the report comment on a pull request. Returns the comment's URL and
// whether an existing comment was updated. Requires an authenticated token.
func PostComment(ref Ref, body string) (commentURL string, updated bool, err error) {
	c := newClient()
	return c.postComment(ref, body)
}

func (c *client) postComment(ref Ref, body string) (string, bool, error) {
	if c.token == "" {
		return "", false, fmt.Errorf("posting a comment requires authentication — set GITHUB_TOKEN (or log in with the gh CLI)")
	}
	full := CommentMarker + "\n\n" + body

	var existing *issueComment
	for page := 1; page <= 30; page++ {
		var cs []issueComment
		if err := c.getJSON(fmt.Sprintf("repos/%s/%s/issues/%d/comments?per_page=100&page=%d",
			ref.Owner, ref.Repo, ref.Number, page), &cs); err != nil {
			return "", false, err
		}
		for i := range cs {
			if strings.HasPrefix(cs[i].Body, CommentMarker) {
				existing = &cs[i]
				break
			}
		}
		if existing != nil || len(cs) < 100 {
			break
		}
	}

	payload, err := json.Marshal(map[string]string{"body": full})
	if err != nil {
		return "", false, err
	}
	var out issueComment
	if existing != nil {
		err := c.sendJSON("PATCH", fmt.Sprintf("repos/%s/%s/issues/comments/%d",
			ref.Owner, ref.Repo, existing.ID), payload, &out)
		return out.HTMLURL, true, err
	}
	err = c.sendJSON("POST", fmt.Sprintf("repos/%s/%s/issues/%d/comments",
		ref.Owner, ref.Repo, ref.Number), payload, &out)
	return out.HTMLURL, false, err
}
