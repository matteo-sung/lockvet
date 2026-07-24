package gtpr

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/matteo-sung/lockvet/internal/ghpr"
)

type issueComment struct {
	ID      int64  `json:"id"`
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
}

// PostComment creates — or, if a lockvet comment already exists, updates —
// the report comment on a Gitea/Forgejo pull request. Returns the
// comment's URL and whether an existing comment was updated. Requires
// GITEA_TOKEN / FORGEJO_TOKEN / CODEBERG_TOKEN with write access.
func PostComment(ref Ref, body string) (commentURL string, updated bool, err error) {
	return newClient(ref.Host).postComment(ref, body)
}

func (c *client) postComment(ref Ref, body string) (string, bool, error) {
	if c.token == "" {
		return "", false, fmt.Errorf("posting a comment requires authentication — set GITEA_TOKEN (or CODEBERG_TOKEN) to a token that can write comments")
	}
	rp := ref.Owner + "/" + ref.Repo
	full := ghpr.CommentMarker + "\n\n" + body

	var existing *issueComment
	for page := 1; page <= 30; page++ {
		var cs []issueComment
		if err := c.getJSON(fmt.Sprintf("repos/%s/issues/%d/comments?page=%d&limit=50",
			rp, ref.Index, page), &cs); err != nil {
			return "", false, err
		}
		for i := range cs {
			if strings.HasPrefix(cs[i].Body, ghpr.CommentMarker) {
				existing = &cs[i]
				break
			}
		}
		if existing != nil || len(cs) < 50 {
			break
		}
	}

	payload, err := json.Marshal(map[string]string{"body": full})
	if err != nil {
		return "", false, err
	}
	var out issueComment
	if existing != nil {
		err := c.sendJSON("PATCH", fmt.Sprintf("repos/%s/issues/comments/%d", rp, existing.ID), payload, &out)
		return out.HTMLURL, true, err
	}
	err = c.sendJSON("POST", fmt.Sprintf("repos/%s/issues/%d/comments", rp, ref.Index), payload, &out)
	return out.HTMLURL, false, err
}
