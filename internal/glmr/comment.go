package glmr

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/matteo-sung/lockvet/internal/ghpr"
)

type mrNote struct {
	ID     int64  `json:"id"`
	Body   string `json:"body"`
	System bool   `json:"system"`
}

// PostComment creates — or, if a lockvet note already exists, updates — the
// report note on a merge request. Returns the note's web URL and whether an
// existing note was updated. Requires GITLAB_TOKEN / GL_TOKEN with api scope
// (CI_JOB_TOKEN cannot use the notes API).
func PostComment(ref Ref, body string) (noteURL string, updated bool, err error) {
	c := newClient(ref.Host)
	return c.postComment(ref, body)
}

func (c *client) postComment(ref Ref, body string) (string, bool, error) {
	if c.token == "" {
		hint := "set GITLAB_TOKEN (a personal or project access token with api scope)"
		if c.jobToken != "" {
			hint = "CI_JOB_TOKEN cannot post notes — " + hint
		}
		return "", false, fmt.Errorf("posting a comment requires authentication — %s", hint)
	}
	proj := url.PathEscape(ref.Project)
	full := ghpr.CommentMarker + "\n\n" + body

	var existing *mrNote
	for page := 1; page <= 30; page++ {
		var ns []mrNote
		if err := c.getJSON(fmt.Sprintf("projects/%s/merge_requests/%d/notes?per_page=100&page=%d",
			proj, ref.IID, page), &ns); err != nil {
			return "", false, err
		}
		for i := range ns {
			if !ns[i].System && strings.HasPrefix(ns[i].Body, ghpr.CommentMarker) {
				existing = &ns[i]
				break
			}
		}
		if existing != nil || len(ns) < 100 {
			break
		}
	}

	payload, err := json.Marshal(map[string]string{"body": full})
	if err != nil {
		return "", false, err
	}
	var out mrNote
	if existing != nil {
		err := c.sendJSON("PUT", fmt.Sprintf("projects/%s/merge_requests/%d/notes/%d",
			proj, ref.IID, existing.ID), payload, &out)
		return c.noteWebURL(ref, out.ID), true, err
	}
	err = c.sendJSON("POST", fmt.Sprintf("projects/%s/merge_requests/%d/notes",
		proj, ref.IID), payload, &out)
	return c.noteWebURL(ref, out.ID), false, err
}

func (c *client) noteWebURL(ref Ref, id int64) string {
	host := ref.Host
	if host == "" {
		host = "gitlab.com"
	}
	return fmt.Sprintf("https://%s/%s/-/merge_requests/%d#note_%d", host, ref.Project, ref.IID, id)
}
