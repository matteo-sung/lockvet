package taglink

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

func TestNormalizeRepoURL(t *testing.T) {
	cases := map[string]string{
		"git+https://github.com/lodash/lodash.git":               "https://github.com/lodash/lodash",
		"git://github.com/isaacs/once.git":                       "https://github.com/isaacs/once",
		"git@github.com:sindresorhus/globby.git":                 "https://github.com/sindresorhus/globby",
		"ssh://git@github.com/npm/cli.git":                       "https://github.com/npm/cli",
		"https://github.com/babel/babel/tree/main/packages/core": "https://github.com/babel/babel",
		"https://gitlab.com/group/sub/project/-/tree/main":       "https://gitlab.com/group/sub/project",
		"https://github.com/o/r/extra/deep/path":                 "https://github.com/o/r",
		"https://codeberg.org/forgejo/forgejo":                   "https://codeberg.org/forgejo/forgejo",
		"https://github.com/":                                    "",
		"not a url":                                              "",
		"ftp://github.com/o/r":                                   "",
		"https://localhost/o/r":                                  "",
	}
	for in, want := range cases {
		if got := NormalizeRepoURL(in); got != want {
			t.Errorf("NormalizeRepoURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPseudoVersionSHA(t *testing.T) {
	if got := pseudoVersionSHA("0.0.0-20240101000000-abcdef123456"); got != "abcdef123456" {
		t.Errorf("got %q", got)
	}
	for _, bad := range []string{"1.2.3", "1.2.3-beta.1", "0.0.0-notatime-abcdef123456", "0.0.0-20240101000000-xyz"} {
		if got := pseudoVersionSHA(bad); got != "" {
			t.Errorf("pseudoVersionSHA(%q) = %q, want empty", bad, got)
		}
	}
}

func TestCandidatesGoSubmodule(t *testing.T) {
	c := &diffx.Change{
		Name:       "github.com/aws/aws-sdk-go-v2/service/s3",
		Ecosystem:  "Go",
		SourceRepo: "https://github.com/aws/aws-sdk-go-v2",
	}
	got := candidates(c, "1.2.3")
	if got[0] != "service/s3/v1.2.3" {
		t.Errorf("first candidate = %q, want service/s3/v1.2.3", got[0])
	}
}

// pkt encodes one pkt-line.
func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

func advertisement(refs ...string) []byte {
	var b bytes.Buffer
	b.WriteString(pkt("# service=git-upload-pack\n"))
	b.WriteString("0000")
	for i, r := range refs {
		line := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa " + r
		if i == 0 {
			line += "\x00multi_ack side-band-64k"
		}
		b.WriteString(pkt(line + "\n"))
	}
	b.WriteString("0000")
	return b.Bytes()
}

func TestParseAdvertisement(t *testing.T) {
	body := advertisement(
		"HEAD",
		"refs/heads/main",
		"refs/tags/v1.0.0",
		"refs/tags/v1.0.0^{}",
		"refs/tags/pkg@2.0.0",
	)
	tags, heads, err := parseAdvertisement(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 || tags["v1.0.0"] == "" || tags["pkg@2.0.0"] == "" {
		t.Errorf("tags = %v", tags)
	}
	if len(heads) != 1 || heads["main"] == "" {
		t.Errorf("heads = %v", heads)
	}
}

func TestAnnotate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, ".git/info/refs") || r.URL.Query().Get("service") != "git-upload-pack" {
			http.NotFound(w, r)
			return
		}
		w.Write(advertisement("refs/tags/v1.0.0", "refs/tags/v2.0.0", "refs/tags/left-pad@3.0.0"))
	}))
	defer srv.Close()

	// Point every fetch at the fake server, but keep the real repo URL on
	// the change so forge detection and URL construction still see github.
	old := Transport
	Transport = func(req *http.Request) (*http.Response, error) {
		u := srv.URL + req.URL.Path + "?" + req.URL.RawQuery
		r2, _ := http.NewRequest("GET", u, nil)
		return http.DefaultClient.Do(r2)
	}
	defer func() { Transport = old }()

	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		{Name: "pkg", Ecosystem: "npm", Kind: diffx.Upgraded,
			Old: []string{"1.0.0"}, New: []string{"2.0.0"},
			SourceRepo: "https://github.com/o/r"},
		{Name: "left-pad", Ecosystem: "npm", Kind: diffx.Added,
			New:        []string{"3.0.0"},
			SourceRepo: "https://github.com/o/r"},
		{Name: "gone", Ecosystem: "npm", Kind: diffx.Removed,
			Old:        []string{"1.0.0"},
			SourceRepo: "https://github.com/o/r"},
		{Name: "nowhere", Ecosystem: "npm", Kind: diffx.Upgraded,
			Old: []string{"0.1.0"}, New: []string{"0.2.0"},
			SourceRepo: "https://example.com/o/r"}, // unknown forge
	}}}
	Annotate(diffs)

	c := diffs[0].Changes[0]
	if c.CompareURL != "https://github.com/o/r/compare/v1.0.0...v2.0.0" {
		t.Errorf("CompareURL = %q", c.CompareURL)
	}
	if c.ReleaseURL != "https://github.com/o/r/releases/tag/v2.0.0" {
		t.Errorf("ReleaseURL = %q", c.ReleaseURL)
	}
	add := diffs[0].Changes[1]
	if add.CompareURL != "" || add.ReleaseURL != "https://github.com/o/r/releases/tag/left-pad@3.0.0" {
		t.Errorf("added: compare=%q release=%q", add.CompareURL, add.ReleaseURL)
	}
	if rm := diffs[0].Changes[2]; rm.CompareURL != "" || rm.ReleaseURL != "" {
		t.Errorf("removed got links: %+v", rm)
	}
	if uk := diffs[0].Changes[3]; uk.CompareURL != "" || uk.ReleaseURL != "" {
		t.Errorf("unknown forge got links: %+v", uk)
	}
}

func TestForgeURLStyles(t *testing.T) {
	if got := compareURL(forgeGitLab, "https://gitlab.com/g/p", "v1", "v2"); got != "https://gitlab.com/g/p/-/compare/v1...v2" {
		t.Errorf("gitlab compare = %q", got)
	}
	if got := tagURL(forgeGitea, "https://codeberg.org/o/r", "v2"); got != "https://codeberg.org/o/r/releases/tag/v2" {
		t.Errorf("gitea tag = %q", got)
	}
	if got := compareURL(forgeBitbucket, "https://bitbucket.org/o/r", "v1", "v2"); got != "https://bitbucket.org/o/r/branches/compare/v2..v1" {
		t.Errorf("bitbucket compare = %q", got)
	}
	if got := compareURL(forgeGitiles, "https://go.googlesource.com/exp", "aaa", "bbb"); got != "https://go.googlesource.com/exp/+/aaa..bbb" {
		t.Errorf("gitiles compare = %q", got)
	}
	if got := tagURL(forgeGitiles, "https://go.googlesource.com/text", "v0.17.0"); got != "https://go.googlesource.com/text/+/refs/tags/v0.17.0" {
		t.Errorf("gitiles tag = %q", got)
	}
	if got := NormalizeRepoURL("https://go.googlesource.com/exp"); got != "https://go.googlesource.com/exp" {
		t.Errorf("gitiles normalize = %q", got)
	}
}
