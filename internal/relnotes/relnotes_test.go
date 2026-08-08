package relnotes

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

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
		// paths: /repos/{owner}/{repo}/releases and
		//        /repos/{owner}/{repo}/releases/tags/{tag}
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		key := parts[1] + "/" + parts[2]
		if len(parts) >= 6 && parts[4] == "tags" {
			// By-tag lookups also see releases listed under "{key}@tags"
			// (test stand-in for releases beyond the newest-100 window).
			for _, rel := range append(append([]release{}, rels[key]...), rels[key+"@tags"]...) {
				if rel.TagName == parts[5] {
					json.NewEncoder(w).Encode(rel)
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
			return
		}
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

func TestAnnotateByTagFallback(t *testing.T) {
	s := srv(t, map[string][]release{
		"o/big": { // newest-100 window: only unrelated recent releases
			{TagName: "otherchart-9.9.9", Body: "unrelated", HTMLURL: "uo"},
		},
		"o/big@tags": { // reachable only via /releases/tags/{tag}
			{TagName: "kube-prometheus-stack-66.3.1", Name: "kube-prometheus-stack-66.3.1",
				Body: "mid-history monorepo release", HTMLURL: "ub"},
			{TagName: "drafted-1.0.0", Body: "draft", Draft: true, HTMLURL: "ud"},
		},
	}, 0)
	defer s.Close()
	old := APIBase
	APIBase = s.URL
	defer func() { APIBase = old }()

	mk := func(name, oldV, newV, tag string) diffx.Change {
		c := change(name, oldV, newV, "")
		if tag != "" {
			c.ReleaseURL = "https://github.com/o/big/releases/tag/" + tag
		}
		return c
	}
	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		mk("kube-prometheus-stack", "66.2.1", "66.3.1", "kube-prometheus-stack-66.3.1"),
		mk("drafted", "0.9.0", "1.0.0", "drafted-1.0.0"),
		mk("gone", "1.0.0", "2.0.0", "gone-2.0.0"),
	}}}
	if w := Annotate(diffs, ""); len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	got := diffs[0].Changes
	if len(got[0].ReleaseNotes) != 1 || got[0].ReleaseNotes[0].Excerpt != "mid-history monorepo release" {
		t.Errorf("by-tag fallback missed: %+v", got[0].ReleaseNotes)
	}
	if got[0].ReleaseNotes != nil && got[0].ReleaseNotes[0].Title != "" {
		t.Errorf("redundant title kept: %+v", got[0].ReleaseNotes[0])
	}
	if len(got[1].ReleaseNotes) != 0 {
		t.Errorf("draft release surfaced: %+v", got[1].ReleaseNotes)
	}
	if len(got[2].ReleaseNotes) != 0 {
		t.Errorf("missing tag got notes: %+v", got[2].ReleaseNotes)
	}
}

func TestAnnotateByTagFallbackViaCandidates(t *testing.T) {
	// Playground path: no verified tag, tag resolved by trying naming
	// conventions directly against /releases/tags/{tag}.
	s := srv(t, map[string][]release{
		"o/mono": {
			{TagName: "recent-1.0.0", Body: "unrelated", HTMLURL: "ur"},
		},
		"o/mono@tags": {
			{TagName: "chart-3.2.1", Body: "old mono release", HTMLURL: "um"},
		},
	}, 0)
	defer s.Close()
	old := APIBase
	APIBase = s.URL
	defer func() { APIBase = old }()
	Fallback = true
	defer func() { Fallback = false }()

	c := change("chart", "3.1.0", "3.2.1", "")
	c.SourceRepo = "https://github.com/o/mono"
	diffs := []diffx.FileDiff{{Changes: []diffx.Change{c}}}
	if w := Annotate(diffs, ""); len(w) != 0 {
		t.Fatalf("warnings: %v", w)
	}
	got := diffs[0].Changes[0].ReleaseNotes
	if len(got) != 1 || got[0].Tag != "chart-3.2.1" || got[0].Excerpt != "old mono release" {
		t.Errorf("candidate by-tag fallback missed: %+v", got)
	}
}
