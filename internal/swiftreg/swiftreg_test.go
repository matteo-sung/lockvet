package swiftreg

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/taglink"
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
	sha540 = "f455c2975872ccd2d9c356bd76c1eb30978c19fe"
	sha541 = "513364eaf3f6d7a6f2b2fa76ab6be9678cf4e6c9"
	evil   = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
)

func fakeTransport(t *testing.T) func() {
	t.Helper()
	old := taglink.Transport
	taglink.Transport = func(req *http.Request) (*http.Response, error) {
		var body []byte
		switch {
		case strings.Contains(req.URL.Path, "Alamofire"):
			body = advertisement(
				sha540+" refs/heads/master",
				sha540+" refs/tags/5.4.0",
				sha541+" refs/tags/5.4.1",
			)
		case strings.Contains(req.URL.Path, "vtagged"):
			// annotated tag: tag object plus peeled entry
			body = advertisement(
				evil+" refs/tags/v2.0.0",
				sha541+" refs/tags/v2.0.0^{}",
			)
		case strings.Contains(req.URL.Path, "private"):
			return &http.Response{StatusCode: 404, Body: io.NopCloser(bytes.NewReader(nil))}, nil
		default:
			body = advertisement(sha540 + " refs/tags/1.0.0")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body))}, nil
	}
	return func() { taglink.Transport = old }
}

func change(name string, newVer, pin string) diffx.Change {
	c := diffx.Change{
		Name:      name,
		Ecosystem: "SwiftURL",
		Kind:      diffx.Added,
		New:       []string{newVer},
	}
	if pin != "" {
		c.NewPins = map[string]string{newVer: "commit:" + pin}
	}
	return c
}

func run(t *testing.T, cs ...diffx.Change) []diffx.Change {
	t.Helper()
	defer fakeTransport(t)()
	diffs := []diffx.FileDiff{{Path: "Package.resolved", Kind: "Package.resolved", Ecosystem: "SwiftURL", Changes: cs}}
	ok, err := Annotate(diffs)
	if err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	if !ok {
		t.Fatalf("Annotate reported nothing checked")
	}
	return diffs[0].Changes
}

func TestCleanPinStaysQuiet(t *testing.T) {
	got := run(t, change("github.com/Alamofire/Alamofire", "5.4.1", sha541))[0]
	if got.Unlisted || got.TagMismatch {
		t.Fatalf("clean pin flagged: %+v", got)
	}
	if got.SourceRepo != "https://github.com/Alamofire/Alamofire" {
		t.Fatalf("SourceRepo = %q", got.SourceRepo)
	}
}

func TestTagMismatchFlags(t *testing.T) {
	got := run(t, change("github.com/Alamofire/Alamofire", "5.4.1", evil))[0]
	if !got.TagMismatch {
		t.Fatalf("moved pin not flagged: %+v", got)
	}
	want := "5.4.1 pinned at deadbeefdead, upstream tag 5.4.1 is at 513364eaf3f6"
	if len(got.TagMismatches) != 1 || got.TagMismatches[0] != want {
		t.Fatalf("TagMismatches = %q, want %q", got.TagMismatches, want)
	}
	if got.Unlisted {
		t.Fatalf("mismatch must not double as unlisted")
	}
}

func TestMissingTagIsUnlisted(t *testing.T) {
	got := run(t, change("github.com/Alamofire/Alamofire", "9.9.9", evil))[0]
	if !got.Unlisted || len(got.UnlistedVersions) != 1 || got.UnlistedVersions[0] != "9.9.9" {
		t.Fatalf("deleted tag not flagged: %+v", got)
	}
	if got.TagMismatch {
		t.Fatalf("no tag to mismatch against: %+v", got)
	}
}

func TestAnnotatedTagPeelsToCommit(t *testing.T) {
	// v-prefixed AND annotated: version 2.0.0 matches tag v2.0.0, whose
	// peeled commit is sha541 — a pin at sha541 is clean.
	got := run(t, change("github.com/vtagged/pkg", "2.0.0", sha541))[0]
	if got.Unlisted || got.TagMismatch {
		t.Fatalf("peeled annotated tag flagged: %+v", got)
	}
}

func TestNoPinChecksExistenceOnly(t *testing.T) {
	got := run(t, change("github.com/Alamofire/Alamofire", "5.4.0", ""))[0]
	if got.Unlisted || got.TagMismatch {
		t.Fatalf("pinless change flagged: %+v", got)
	}
}

func TestUnreachableRepoMakesNoClaims(t *testing.T) {
	defer fakeTransport(t)()
	cs := []diffx.Change{change("github.com/private/pkg", "1.0.0", evil)}
	diffs := []diffx.FileDiff{{Path: "Package.resolved", Ecosystem: "SwiftURL", Changes: cs}}
	if ok, err := Annotate(diffs); err != nil || ok {
		t.Fatalf("ok=%v err=%v, want no claims for unreachable repo", ok, err)
	}
	got := diffs[0].Changes[0]
	if got.Unlisted || got.TagMismatch {
		t.Fatalf("unreachable repo flagged: %+v", got)
	}
}

func TestNonRegistryAndForeignEcosystemSkipped(t *testing.T) {
	defer fakeTransport(t)()
	skip := change("github.com/Alamofire/Alamofire", "5.4.1", evil)
	skip.NonRegistry = true
	npm := change("github.com/Alamofire/Alamofire", "5.4.1", evil)
	npm.Ecosystem = "npm"
	diffs := []diffx.FileDiff{{Path: "Package.resolved", Ecosystem: "SwiftURL", Changes: []diffx.Change{skip, npm}}}
	if ok, _ := Annotate(diffs); ok {
		t.Fatalf("nothing checkable, but ok=true")
	}
	for _, got := range diffs[0].Changes {
		if got.Unlisted || got.TagMismatch {
			t.Fatalf("skipped change flagged: %+v", got)
		}
	}
}
