package osv

import (
	"encoding/json"
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

func detailFromJSON(t *testing.T, affected string) vulnDetail {
	t.Helper()
	var d vulnDetail
	if err := json.Unmarshal([]byte(affected), &d.affected); err != nil {
		t.Fatalf("bad fixture: %v", err)
	}
	return d
}

func tgt(name, eco string, versions ...string) fixTarget {
	return fixTarget{name: name, eco: eco, versions: versions}
}

func TestFixedInBasicRange(t *testing.T) {
	d := detailFromJSON(t, `[{"package":{"name":"lodash","ecosystem":"npm"},
		"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]`)
	if got := fixedIn(d, tgt("lodash", "npm", "4.17.11")); got != "4.17.21" {
		t.Fatalf("got %q, want 4.17.21", got)
	}
	// pinned version already past the fix: no claim
	if got := fixedIn(d, tgt("lodash", "npm", "4.17.21")); got != "" {
		t.Fatalf("got %q, want empty (already fixed)", got)
	}
}

func TestFixedInPicksTheRightLine(t *testing.T) {
	d := detailFromJSON(t, `[{"package":{"name":"p","ecosystem":"npm"},
		"ranges":[{"type":"ECOSYSTEM","events":[
			{"introduced":"1.0.0"},{"fixed":"1.2.5"},
			{"introduced":"2.0.0"},{"fixed":"2.3.1"}]}]}]`)
	if got := fixedIn(d, tgt("p", "npm", "2.0.0")); got != "2.3.1" {
		t.Fatalf("got %q, want 2.3.1", got)
	}
	if got := fixedIn(d, tgt("p", "npm", "1.1.0")); got != "1.2.5" {
		t.Fatalf("got %q, want 1.2.5", got)
	}
}

func TestFixedInNoFixReleased(t *testing.T) {
	last := detailFromJSON(t, `[{"package":{"name":"p","ecosystem":"npm"},
		"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"last_affected":"2.0.0"}]}]}]`)
	if got := fixedIn(last, tgt("p", "npm", "1.0.0")); got != "" {
		t.Fatalf("last_affected: got %q, want empty", got)
	}
	open := detailFromJSON(t, `[{"package":{"name":"p","ecosystem":"npm"},
		"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"}]}]}]`)
	if got := fixedIn(open, tgt("p", "npm", "1.5.0")); got != "" {
		t.Fatalf("open range: got %q, want empty", got)
	}
}

func TestFixedInVersionsListFallback(t *testing.T) {
	d := detailFromJSON(t, `[{"package":{"name":"p","ecosystem":"PyPI"},
		"versions":["1.0.0","1.1.0"],
		"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0.0"},{"fixed":"1.2.0"}]}]}]`)
	// 1.1.0 sits inside the range anyway; check the explicit-list path with
	// a version the range walk already covers, then one it doesn't.
	if got := fixedIn(d, tgt("p", "PyPI", "1.1.0")); got != "1.2.0" {
		t.Fatalf("got %q, want 1.2.0", got)
	}
}

func TestFixedInMultiplePins(t *testing.T) {
	d := detailFromJSON(t, `[{"package":{"name":"p","ecosystem":"npm"},
		"ranges":[{"type":"SEMVER","events":[
			{"introduced":"1.0.0"},{"fixed":"1.2.5"},
			{"introduced":"2.0.0"},{"fixed":"2.3.1"}]}]}]`)
	// both lines pinned: the version clearing everything is the larger fix
	if got := fixedIn(d, tgt("p", "npm", "1.1.0", "2.1.0")); got != "2.3.1" {
		t.Fatalf("got %q, want 2.3.1", got)
	}
	// one pin unfixable: no claim at all
	d2 := detailFromJSON(t, `[{"package":{"name":"p","ecosystem":"npm"},
		"ranges":[{"type":"SEMVER","events":[
			{"introduced":"1.0.0"},{"fixed":"1.2.5"},
			{"introduced":"2.0.0"}]}]}]`)
	if got := fixedIn(d2, tgt("p", "npm", "1.1.0", "2.1.0")); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestFixedInNameEcoMatching(t *testing.T) {
	d := detailFromJSON(t, `[{"package":{"name":"pillow","ecosystem":"PyPI"},
		"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"10.0.1"}]}]}]`)
	if got := fixedIn(d, tgt("Pillow", "PyPI", "9.0.0")); got != "10.0.1" {
		t.Fatalf("case fold: got %q, want 10.0.1", got)
	}
	u := detailFromJSON(t, `[{"package":{"name":"python-dateutil","ecosystem":"PyPI"},
		"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.8.0"}]}]}]`)
	if got := fixedIn(u, tgt("python_dateutil", "PyPI", "2.7.0")); got != "2.8.0" {
		t.Fatalf("pypi norm: got %q, want 2.8.0", got)
	}
	// distro suffix on our side matches the record's bare ecosystem
	a := detailFromJSON(t, `[{"package":{"name":"openssl","ecosystem":"Alpine:v3.19"},
		"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.1.4-r5"}]}]}]`)
	if got := fixedIn(a, tgt("openssl", "Alpine:v3.19", "3.1.4-r2")); got != "3.1.4-r5" {
		t.Fatalf("alpine: got %q, want 3.1.4-r5", got)
	}
	// wrong package in a multi-package advisory: never matched
	if got := fixedIn(d, tgt("other", "PyPI", "9.0.0")); got != "" {
		t.Fatalf("wrong name: got %q, want empty", got)
	}
}

func TestFixedInVPrefix(t *testing.T) {
	d := detailFromJSON(t, `[{"package":{"name":"golang.org/x/crypto","ecosystem":"Go"},
		"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"0.17.0"}]}]}]`)
	got := fixedIn(d, fixTarget{name: "golang.org/x/crypto", eco: "Go", versions: []string{"v0.14.0"}, vPrefix: true})
	if got != "v0.17.0" {
		t.Fatalf("got %q, want v0.17.0", got)
	}
}

func TestFixTargetForActions(t *testing.T) {
	c := &diffx.Change{
		Name: "actions/checkout", Ecosystem: "GitHub Actions",
		New:          []string{"abc1234abc1234abc1234abc1234abc1234abc12"},
		ResolvedRefs: map[string]string{"abc1234abc1234abc1234abc1234abc1234abc12": "v4.1.2"},
	}
	tg := fixTargetFor(c)
	if len(tg.versions) != 1 || tg.versions[0] != "4.1.2" || !tg.vPrefix {
		t.Fatalf("resolved sha: got %+v", tg)
	}
	// unresolved SHA: no claims
	c2 := &diffx.Change{Name: "a/b", Ecosystem: "GitHub Actions",
		New: []string{"abc1234abc1234abc1234abc1234abc1234abc12"}}
	if tg := fixTargetFor(c2); len(tg.versions) != 0 {
		t.Fatalf("unresolved sha: got %+v", tg)
	}
	// floating major that didn't resolve: no claims
	c3 := &diffx.Change{Name: "a/b", Ecosystem: "GitHub Actions", New: []string{"v4"}}
	if tg := fixTargetFor(c3); len(tg.versions) != 0 {
		t.Fatalf("floating major: got %+v", tg)
	}
}
