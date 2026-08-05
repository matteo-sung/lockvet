package relnotes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

func TestParseReleaseURL(t *testing.T) {
	cases := []struct {
		in               string
		owner, repo, tag string
	}{
		{"https://github.com/BurntSushi/jiff/releases/tag/jiff-0.2.15", "BurntSushi", "jiff", "jiff-0.2.15"},
		{"https://github.com/golang/text/releases/tag/v0.22.0", "golang", "text", "v0.22.0"},
		{"https://github.com/grafana/grafana/releases/tag/pkg%23util/v1.0.0", "grafana", "grafana", "pkg#util/v1.0.0"},
		{"https://github.com/o/r/releases/tag/dir/v1.2.3", "o", "r", "dir/v1.2.3"},
		{"https://gitlab.com/o/r/-/tags/v1.0.0", "", "", ""},
		{"https://github.com/o/r/compare/v1...v2", "", "", ""},
		{"", "", "", ""},
	}
	for _, c := range cases {
		o, r, tag := parseReleaseURL(c.in)
		if o != c.owner || r != c.repo || tag != c.tag {
			t.Errorf("parseReleaseURL(%q) = %q,%q,%q; want %q,%q,%q", c.in, o, r, tag, c.owner, c.repo, c.tag)
		}
	}
}

func TestExcerpt(t *testing.T) {
	if got := Excerpt("<!-- meta -->\r\nFixes stuff\n\n\n\nMore\x1b[31m text\n"); got != "Fixes stuff\n\nMore text" {
		t.Errorf("Excerpt = %q", got)
	}
	long := strings.Repeat("line\n", 40)
	got := Excerpt(long)
	if !strings.HasSuffix(got, "…") || strings.Count(got, "\n") > maxExcerptLines+1 {
		t.Errorf("long excerpt not truncated: %q", got)
	}
	if Excerpt("") != "" {
		t.Error("empty body should stay empty")
	}
}

func srv(t *testing.T, rels map[string][]release, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != 0 {
			if status == 403 {
				w.Header().Set("X-RateLimit-Remaining", "0")
			}
			w.WriteHeader(status)
			return
		}
		// path: /repos/{owner}/{repo}/releases
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		key := parts[1] + "/" + parts[2]
		json.NewEncoder(w).Encode(rels[key])
	}))
}

func change(name, old, new, releaseURL string) diffx.Change {
	return diffx.Change{
		Name: name, Kind: diffx.Upgraded,
		Old: []string{old}, New: []string{new},
		ReleaseURL: releaseURL,
	}
}

func TestAnnotateIntermediates(t *testing.T) {
	s := srv(t, map[string][]release{
		"o/r": {
			{TagName: "v1.4.0", Name: "v1.4.0", Body: "newest", HTMLURL: "u4"},
			{TagName: "v1.3.0", Name: "one point three", Body: "middle", HTMLURL: "u3"},
			{TagName: "v1.2.0", Body: "old side — must not appear", HTMLURL: "u2"},
			{TagName: "v1.3.5", Body: "draft", Draft: true, HTMLURL: "ud"},
			{TagName: "other-2.0.0", Body: "different prefix", HTMLURL: "uo"},
		},
	}, 0)
	defer s.Close()
	old := APIBase
	APIBase = s.URL
	defer func() { APIBase = old }()

	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		change("r", "1.2.0", "1.4.0", "https://github.com/o/r/releases/tag/v1.4.0"),
	}}}
	if w := Annotate(diffs, ""); len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	got := diffs[0].Changes[0].ReleaseNotes
	if len(got) != 2 {
		t.Fatalf("want 2 notes (new + intermediate), got %+v", got)
	}
	if got[0].Tag != "v1.4.0" || got[1].Tag != "v1.3.0" {
		t.Errorf("wrong order/picks: %+v", got)
	}
	if got[0].Title != "" { // title == tag is redundant
		t.Errorf("redundant title kept: %q", got[0].Title)
	}
	if got[1].Title != "one point three" || got[1].Excerpt != "middle" || got[1].URL != "u3" {
		t.Errorf("intermediate mangled: %+v", got[1])
	}
}

func TestAnnotateRateLimit(t *testing.T) {
	s := srv(t, nil, 403)
	defer s.Close()
	old := APIBase
	APIBase = s.URL
	defer func() { APIBase = old }()

	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		change("r", "1.0.0", "1.1.0", "https://github.com/o/r/releases/tag/v1.1.0"),
	}}}
	w := Annotate(diffs, "")
	if len(w) != 1 || !strings.Contains(w[0], "rate limit") {
		t.Errorf("want rate-limit warning, got %v", w)
	}
}

func TestAnnotateSkipsNonGitHub(t *testing.T) {
	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		change("r", "1.0.0", "1.1.0", "https://gitlab.com/o/r/-/tags/v1.1.0"),
		{Name: "x", Kind: diffx.Removed, Old: []string{"1.0.0"}},
	}}}
	if w := Annotate(diffs, ""); len(w) != 0 {
		t.Errorf("warnings: %v", w)
	}
	for _, c := range diffs[0].Changes {
		if len(c.ReleaseNotes) != 0 {
			t.Errorf("unexpected notes: %+v", c)
		}
	}
}

func TestAnnotateFallback(t *testing.T) {
	s := srv(t, map[string][]release{
		"o/r": {
			{TagName: "v2.0.0", Name: "two", Body: "big", HTMLURL: "u2"},
			{TagName: "v1.0.0", Body: "old", HTMLURL: "u1"},
		},
		"o/mono": {
			{TagName: "pkg-v0.3.0", Body: "mono release", HTMLURL: "um"},
		},
	}, 0)
	defer s.Close()
	oldBase := APIBase
	APIBase = s.URL
	defer func() { APIBase = oldBase }()

	mk := func(name, old, new, srcRepo string) diffx.Change {
		c := change(name, old, new, "")
		c.SourceRepo = srcRepo
		return c
	}
	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		mk("r", "1.0.0", "2.0.0", "https://github.com/o/r"),
		mk("pkg", "0.2.0", "0.3.0", "https://github.com/o/mono"),
		mk("g", "1.0.0", "1.1.0", "https://gitlab.com/o/g"), // non-GitHub: skipped
		mk("missing", "1.0.0", "9.9.9", "https://github.com/o/r"),
	}}}

	// Fallback off (the CLI default): nothing without a ReleaseURL is queried.
	if w := Annotate(diffs, ""); len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	for _, c := range diffs[0].Changes {
		if len(c.ReleaseNotes) != 0 {
			t.Fatalf("fallback off but notes fetched: %+v", c)
		}
	}

	Fallback = true
	defer func() { Fallback = false }()
	if w := Annotate(diffs, ""); len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	got := diffs[0].Changes
	if len(got[0].ReleaseNotes) != 1 || got[0].ReleaseNotes[0].Tag != "v2.0.0" {
		t.Errorf("plain v-tag not resolved: %+v", got[0].ReleaseNotes)
	}
	if len(got[1].ReleaseNotes) != 1 || got[1].ReleaseNotes[0].Tag != "pkg-v0.3.0" {
		t.Errorf("release-please tag not resolved: %+v", got[1].ReleaseNotes)
	}
	if len(got[2].ReleaseNotes) != 0 {
		t.Errorf("non-GitHub repo queried: %+v", got[2].ReleaseNotes)
	}
	if len(got[3].ReleaseNotes) != 0 {
		t.Errorf("unmatched version got notes: %+v", got[3].ReleaseNotes)
	}
}

func TestParseGitHubRepo(t *testing.T) {
	cases := []struct {
		in, owner, repo string
	}{
		{"https://github.com/o/r", "o", "r"},
		{"https://github.com/o/r.git", "o", "r"},
		{"https://gitlab.com/o/r", "", ""},
		{"", "", ""},
		{"https://github.com/o", "", ""},
	}
	for _, c := range cases {
		o, r := parseGitHubRepo(c.in)
		if o != c.owner || r != c.repo {
			t.Errorf("parseGitHubRepo(%q) = %q,%q; want %q,%q", c.in, o, r, c.owner, c.repo)
		}
	}
}
