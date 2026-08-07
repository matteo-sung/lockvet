package relnotes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

func TestParseTagURL(t *testing.T) {
	cases := []struct {
		in   string
		f    clForge
		repo string
		tag  string
	}{
		{"https://github.com/phoenixframework/phoenix/releases/tag/v1.8.0", clGitHub, "https://github.com/phoenixframework/phoenix", "v1.8.0"},
		{"https://github.com/o/r/releases/tag/dir/v1.2.3", clGitHub, "https://github.com/o/r", "dir/v1.2.3"},
		{"https://gitlab.com/grp/sub/proj/-/tags/v2.0.0", clGitLab, "https://gitlab.com/grp/sub/proj", "v2.0.0"},
		{"https://codeberg.org/forgejo/forgejo/releases/tag/v11.0.1", clGitea, "https://codeberg.org/forgejo/forgejo", "v11.0.1"},
		{"https://bitbucket.org/ws/repo/src/1.2.3", clBitbucket, "https://bitbucket.org/ws/repo", "1.2.3"},
		{"https://github.com/o/r/compare/v1...v2", clNone, "", ""},
		{"", clNone, "", ""},
	}
	for _, c := range cases {
		f, repo, tag := parseTagURL(c.in)
		if f != c.f || repo != c.repo || tag != c.tag {
			t.Errorf("parseTagURL(%q) = %v,%q,%q; want %v,%q,%q", c.in, f, repo, tag, c.f, c.repo, c.tag)
		}
	}
}

func TestVersionHeading(t *testing.T) {
	cases := []struct {
		in       string
		prefixes []string
		version  string
		ok       bool
	}{
		{"1.8.0 (2025-07-09)", nil, "1.8.0", true},
		{"[1.2.3] - 2024-01-01", nil, "1.2.3", true},
		{"v2.0.0", nil, "2.0.0", true},
		{"Version 1.5.0", nil, "1.5.0", true},
		{"Release 3.1.4:", nil, "3.1.4", true},
		{"Rails 7.1.2 (November 10, 2023)", []string{"rails"}, "7.1.2", true},
		{"Rails 7.1.2", nil, "", false},          // unknown prefix word
		{"Fixed 1.2.3 handling", nil, "", false}, // prose, not a heading
		{"Unreleased", nil, "", false},
		{"2.0.0rc1", nil, "2.0.0rc1", true},
		{"1.2.3.4", nil, "1.2.3.4", true},
		{"0.21-8", nil, "0.21-8", true},
	}
	for _, c := range cases {
		_, v, _, ok := versionHeading(c.in, c.prefixes)
		if ok != c.ok || (ok && v != c.version) {
			t.Errorf("versionHeading(%q) = %q,%v; want %q,%v", c.in, v, ok, c.version, c.ok)
		}
	}
}

const sampleChangelog = `# Changelog

All notable changes.

## [Unreleased]

- something brewing

## [1.4.0] - 2024-03-01

### Added

- big feature

## 1.3.0 (2024-02-01)

- middle fix

## 1.2.0 - 2024-01-01

- old news

[1.4.0]: https://example.com/1.4.0
[1.3.0]: https://example.com/1.3.0
`

func TestParseChangelog(t *testing.T) {
	secs := parseChangelog(sampleChangelog, nil)
	if len(secs) != 3 {
		t.Fatalf("got %d sections: %+v", len(secs), secs)
	}
	if secs[0].version != "1.4.0" || !strings.Contains(secs[0].body, "big feature") {
		t.Errorf("first section wrong: %+v", secs[0])
	}
	if strings.Contains(secs[2].body, "example.com") {
		t.Errorf("link refs must be stripped: %q", secs[2].body)
	}
	if secs[1].title != "2024-02-01" {
		t.Errorf("title = %q", secs[1].title)
	}
}

func TestParseChangelogSetext(t *testing.T) {
	secs := parseChangelog("intro\n\n2.1.0\n-----\n\nnew stuff\n\n2.0.0\n=====\n\nolder\n", nil)
	if len(secs) != 2 || secs[0].version != "2.1.0" || !strings.Contains(secs[0].body, "new stuff") {
		t.Fatalf("setext parse wrong: %+v", secs)
	}
}

func TestClNotesFor(t *testing.T) {
	secs := parseChangelog(sampleChangelog, nil)
	c := &diffx.Change{Name: "pkg", Kind: diffx.Upgraded, Old: []string{"1.2.0"}, New: []string{"1.4.0"}}
	notes := clNotesFor(c, secs, "https://github.com/o/r/blob/v1.4.0/CHANGELOG.md")
	if len(notes) != 2 {
		t.Fatalf("got %d notes: %+v", len(notes), notes)
	}
	if notes[0].Tag != "1.4.0" || notes[1].Tag != "1.3.0" {
		t.Errorf("order/tags wrong: %+v", notes)
	}
	if !strings.Contains(notes[0].Excerpt, "big feature") || notes[0].URL == "" {
		t.Errorf("note content wrong: %+v", notes[0])
	}
	// No section for the new version → no guessing.
	c2 := &diffx.Change{Name: "pkg", Kind: diffx.Upgraded, Old: []string{"1.2.0"}, New: []string{"1.5.0"}}
	if n := clNotesFor(c2, secs, "u"); n != nil {
		t.Errorf("expected nil for unknown version, got %+v", n)
	}
}

// End-to-end: GitHub repo with no releases falls back to CHANGELOG.md at
// the verified tag.
func TestAnnotateChangelogFallbackGitHub(t *testing.T) {
	var rawHits []string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/repos/"):
			w.Write([]byte("[]")) // no GitHub releases
		case r.URL.Path == "/o/r/1.4.0/CHANGELOG.md":
			rawHits = append(rawHits, r.URL.Path)
			w.Write([]byte(sampleChangelog))
		default:
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	defer swap(&APIBase, s.URL)()
	defer swap(&RawGitHub, s.URL)()

	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		change("pkg", "1.2.0", "1.4.0", "https://github.com/o/r/releases/tag/1.4.0"),
	}}}
	Annotate(diffs, "")
	c := diffs[0].Changes[0]
	if len(c.ReleaseNotes) != 2 || !strings.Contains(c.ReleaseNotes[0].Excerpt, "big feature") {
		t.Fatalf("notes = %+v", c.ReleaseNotes)
	}
	if want := "https://github.com/o/r/blob/1.4.0/CHANGELOG.md"; c.ReleaseNotes[0].URL != want {
		t.Errorf("URL = %q, want %q", c.ReleaseNotes[0].URL, want)
	}
	if len(rawHits) != 1 {
		t.Errorf("raw hits = %v", rawHits)
	}
}

// End-to-end: GitLab-hosted repo (no release API call at all).
func TestAnnotateChangelogGitLab(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/grp/proj/-/raw/v1.4.0/CHANGELOG.md":
			http.NotFound(w, r)
		case "/grp/proj/-/raw/v1.4.0/CHANGES.md":
			w.Write([]byte("## v1.4.0\n\ngitlab goodies\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	defer swap(&APIBase, s.URL+"/api-must-not-be-hit")()

	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		change("pkg", "1.2.0", "1.4.0", s.URL+"/grp/proj/-/tags/v1.4.0"),
	}}}
	Annotate(diffs, "")
	c := diffs[0].Changes[0]
	if len(c.ReleaseNotes) != 1 || !strings.Contains(c.ReleaseNotes[0].Excerpt, "gitlab goodies") {
		t.Fatalf("notes = %+v", c.ReleaseNotes)
	}
	if want := s.URL + "/grp/proj/-/blob/v1.4.0/CHANGES.md"; c.ReleaseNotes[0].URL != want {
		t.Errorf("URL = %q, want %q", c.ReleaseNotes[0].URL, want)
	}
}

// Monorepo-style tags must not use a root changelog.
func TestAnnotateChangelogMonorepoSkipped(t *testing.T) {
	hit := false
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/repos/") {
			w.Write([]byte("[]"))
			return
		}
		hit = true
		w.Write([]byte(sampleChangelog))
	}))
	defer s.Close()
	defer swap(&APIBase, s.URL)()
	defer swap(&RawGitHub, s.URL)()

	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		change("pkg", "1.2.0", "1.4.0", "https://github.com/o/r/releases/tag/pkg@1.4.0"),
	}}}
	Annotate(diffs, "")
	if hit {
		t.Error("changelog fetched despite monorepo tag convention")
	}
	if n := diffs[0].Changes[0].ReleaseNotes; n != nil {
		t.Errorf("notes = %+v", n)
	}
}

// GitHub releases still win when present; changelog only fills the gaps.
func TestAnnotateReleasesStillWin(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/repos/") {
			w.Write([]byte(`[{"tag_name":"v1.4.0","body":"from the release","html_url":"u"}]`))
			return
		}
		t.Errorf("unexpected raw fetch %s", r.URL.Path)
	}))
	defer s.Close()
	defer swap(&APIBase, s.URL)()
	defer swap(&RawGitHub, s.URL)()

	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		change("pkg", "1.2.0", "1.4.0", "https://github.com/o/r/releases/tag/v1.4.0"),
	}}}
	Annotate(diffs, "")
	c := diffs[0].Changes[0]
	if len(c.ReleaseNotes) != 1 || c.ReleaseNotes[0].Excerpt != "from the release" {
		t.Fatalf("notes = %+v", c.ReleaseNotes)
	}
}

func swap[T any](p *T, v T) func() {
	old := *p
	*p = v
	return func() { *p = old }
}

func FuzzParseChangelog(f *testing.F) {
	f.Add(sampleChangelog)
	f.Add("v1\n---\n# x\n\n## [2.0] - x\nbody\n")
	f.Fuzz(func(t *testing.T, s string) {
		parseChangelog(s, []string{"pkg"})
	})
}
