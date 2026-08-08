package actreg

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/taglink"
	"github.com/matteo-sung/lockvet/internal/vers"
)

func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

func advertisement(lines ...string) []byte {
	var b bytes.Buffer
	b.WriteString(pkt("# service=git-upload-pack\n"))
	b.WriteString("0000")
	for i, l := range lines {
		if i == 0 {
			l += "\x00multi_ack"
		}
		b.WriteString(pkt(l + "\n"))
	}
	b.WriteString("0000")
	return b.Bytes()
}

const (
	shaV5   = "08c6903cd8c0fde910a37f88322edcfb5dd907a8"
	shaV421 = "11bd71901bbe5b1630ceea73d27597364c9af683"
	orphan  = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
)

func fakeTransport(t *testing.T) func() {
	old := taglink.Transport
	taglink.Transport = func(req *http.Request) (*http.Response, error) {
		var body []byte
		switch {
		case strings.Contains(req.URL.Path, "actions/checkout"):
			body = advertisement(
				shaV5+" refs/heads/main",
				shaV5+" refs/tags/v5",
				shaV5+" refs/tags/v5.0.0",
				shaV421+" refs/tags/v4",
				shaV421+" refs/tags/v4.2.1",
			)
		case strings.Contains(req.URL.Path, "gone/action"):
			return &http.Response{StatusCode: 404, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		default:
			body = advertisement(shaV421 + " refs/tags/v1.0.0")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
	}
	return func() { taglink.Transport = old }
}

func wf(changes ...diffx.Change) []diffx.FileDiff {
	return []diffx.FileDiff{{Path: ".github/workflows/ci.yml", Kind: "github-workflow", Ecosystem: "GitHub Actions", Changes: changes}}
}

func TestAnnotateResolvesAndClassifies(t *testing.T) {
	defer fakeTransport(t)()

	diffs := wf(
		// SHA -> SHA bump, both are release tags: classify as the tags.
		diffx.Change{Name: "actions/checkout", Ecosystem: "GitHub Actions", Kind: diffx.Changed,
			Old: []string{shaV421}, New: []string{shaV5}},
		// Floating major resolves to the concrete release.
		diffx.Change{Name: "actions/checkout", Ecosystem: "GitHub Actions", Kind: diffx.Upgraded,
			Old: []string{"v4"}, New: []string{"v5"}, Level: vers.Major, LevelString: "major"},
		// Incoming SHA that is no tag: unlisted.
		diffx.Change{Name: "actions/checkout", Ecosystem: "GitHub Actions", Kind: diffx.Upgraded,
			Old: []string{"v4"}, New: []string{orphan}},
		// Branch ref stays quiet.
		diffx.Change{Name: "actions/checkout", Ecosystem: "GitHub Actions", Kind: diffx.Added,
			New: []string{"main"}},
	)
	ok, err := Annotate(diffs)
	if err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	byOld := map[string]*diffx.Change{}
	for i := range diffs[0].Changes {
		c := &diffs[0].Changes[i]
		if len(c.Old) > 0 {
			byOld[c.Old[0]] = c
		} else {
			byOld[""] = c
		}
	}

	c := byOld[shaV421]
	if c.ResolvedRefs[shaV421] != "v4.2.1" || c.ResolvedRefs[shaV5] != "v5.0.0" {
		t.Errorf("resolved = %v", c.ResolvedRefs)
	}
	if c.Kind != diffx.Upgraded || c.Level != vers.Major {
		t.Errorf("sha bump: kind=%s level=%s", c.Kind, c.Level)
	}
	if c.Unlisted {
		t.Errorf("sha bump wrongly unlisted: %v", c.UnlistedVersions)
	}
	if c.SourceRepo != "https://github.com/actions/checkout" {
		t.Errorf("source repo = %q", c.SourceRepo)
	}

	for i := range diffs[0].Changes {
		cc := &diffs[0].Changes[i]
		if len(cc.Old) == 1 && cc.Old[0] == "v4" && cc.New[0] == "v5" {
			if cc.ResolvedRefs["v4"] != "v4.2.1" || cc.ResolvedRefs["v5"] != "v5.0.0" {
				t.Errorf("floating resolve = %v", cc.ResolvedRefs)
			}
		}
		if len(cc.New) == 1 && cc.New[0] == orphan {
			if !cc.Unlisted || cc.UnlistedVersions[0] != orphan {
				t.Errorf("orphan sha not flagged: %+v", cc)
			}
		}
		if len(cc.New) == 1 && cc.New[0] == "main" {
			if cc.Unlisted {
				t.Errorf("branch ref flagged unlisted")
			}
		}
	}
}

func TestAnnotateNoTagDataNoClaims(t *testing.T) {
	defer fakeTransport(t)()
	diffs := wf(diffx.Change{Name: "gone/action", Ecosystem: "GitHub Actions", Kind: diffx.Added,
		New: []string{orphan}})
	if ok, err := Annotate(diffs); err != nil || ok {
		t.Fatalf("Annotate = %v, %v (want no data, no error)", ok, err)
	}
	if diffs[0].Changes[0].Unlisted {
		t.Errorf("404 repo must make no unlisted claims")
	}
}

func TestVersionLike(t *testing.T) {
	yes := []string{"v4", "4.2.2", "v1.2.3-rc1", "45.0.7", "v2.1"}
	no := []string{"main", "master", "release-branch", shaV5, "deadbee", ""}
	for _, s := range yes {
		if !VersionLike(s) {
			t.Errorf("VersionLike(%q) = false", s)
		}
	}
	for _, s := range no {
		if VersionLike(s) {
			t.Errorf("VersionLike(%q) = true", s)
		}
	}
}

func TestAnnotatePreCommitPins(t *testing.T) {
	defer fakeTransport(t)()

	diffs := []diffx.FileDiff{{Path: ".pre-commit-config.yaml", Kind: "pre-commit-config", Ecosystem: "pre-commit", Changes: []diffx.Change{
		// Tag bump on a hook repo: resolved, classified, source repo set.
		{Name: "github.com/actions/checkout", Ecosystem: "pre-commit", Kind: diffx.Upgraded,
			Old: []string{"v4.2.1"}, New: []string{"v5.0.0"}, Level: vers.Major, LevelString: "major"},
		// Incoming rev that matches no tag or branch: unlisted.
		{Name: "github.com/actions/checkout", Ecosystem: "pre-commit", Kind: diffx.Changed,
			Old: []string{"v4.2.1"}, New: []string{orphan}},
		// Non-github host goes through the same machinery.
		{Name: "gitlab.example.com/group/hooks", Ecosystem: "pre-commit", Kind: diffx.Added,
			New: []string{"v1.0.0"}},
	}}}
	ok, err := Annotate(diffs)
	if err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	for i := range diffs[0].Changes {
		c := &diffs[0].Changes[i]
		switch {
		case len(c.New) == 1 && c.New[0] == "v5.0.0":
			if c.SourceRepo != "https://github.com/actions/checkout" {
				t.Errorf("source repo = %q", c.SourceRepo)
			}
			if c.Unlisted {
				t.Errorf("tag bump wrongly unlisted: %v", c.UnlistedVersions)
			}
		case len(c.New) == 1 && c.New[0] == orphan:
			if !c.Unlisted || c.UnlistedVersions[0] != orphan {
				t.Errorf("orphan rev not flagged: %+v", c)
			}
		case len(c.New) == 1 && c.New[0] == "v1.0.0":
			if c.SourceRepo != "https://gitlab.example.com/group/hooks" {
				t.Errorf("source repo = %q", c.SourceRepo)
			}
			if c.Unlisted {
				t.Errorf("v1.0.0 wrongly unlisted (fake serves it): %v", c.UnlistedVersions)
			}
		}
	}
}
