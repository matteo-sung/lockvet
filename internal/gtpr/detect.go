package gtpr

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// IsGiteaHost reports whether host serves a Gitea/Forgejo API. Known hosts
// and obvious names ("gitea.*", "forgejo.*", "gitlab.*") are answered
// without a network call; anything else is probed with one anonymous GET
// of /api/v1/version — Gitea and Forgejo answer it (or demand auth for
// it), while GitLab has no /api/v1 routes at all.
func IsGiteaHost(host string) bool {
	h := strings.ToLower(strings.TrimPrefix(host, "www."))
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	switch h {
	case "codeberg.org", "gitea.com":
		return true
	case "github.com", "gitlab.com", "bitbucket.org":
		return false
	}
	first, _, _ := strings.Cut(h, ".")
	switch {
	case strings.Contains(first, "gitea"), strings.Contains(first, "forgejo"), strings.Contains(first, "codeberg"):
		return true
	case strings.Contains(first, "gitlab"):
		return false
	}
	return probeGitea("https://" + host)
}

func probeGitea(baseURL string) bool {
	cl := &http.Client{Timeout: 8 * time.Second}
	resp, err := cl.Get(baseURL + "/api/v1/version")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var v struct {
			Version string `json:"version"`
		}
		if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&v) == nil && v.Version != "" {
			return true
		}
	case http.StatusUnauthorized, http.StatusForbidden:
		// A sign-in-required Gitea/Forgejo still owns the /api/v1
		// namespace; GitLab would 404 here.
		return true
	}
	return false
}
