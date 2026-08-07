package hkgreg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// fakeHackage serves version maps under /package/{name}.json, upload
// times under /package/{name}-{ver}/upload-time, .cabal files under
// /package/{name}-{ver}/{name}.cabal and the registry-wide deprecation
// list under /packages/deprecated.json. Missing entries 404.
func fakeHackage(t *testing.T, versions map[string]string, uploads map[string]string, cabals map[string]string, deprecated string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		switch {
		case p == "packages/deprecated.json":
			if deprecated == "" {
				http.NotFound(w, r)
				return
			}
			fmt.Fprint(w, deprecated)
		case strings.HasPrefix(p, "package/") && strings.HasSuffix(p, ".json"):
			name := strings.TrimSuffix(strings.TrimPrefix(p, "package/"), ".json")
			if doc, ok := versions[name]; ok {
				fmt.Fprint(w, doc)
				return
			}
			http.NotFound(w, r)
		case strings.HasSuffix(p, "/upload-time"):
			key := strings.TrimSuffix(strings.TrimPrefix(p, "package/"), "/upload-time")
			if ts, ok := uploads[key]; ok {
				fmt.Fprint(w, ts)
				return
			}
			http.NotFound(w, r)
		case strings.HasSuffix(p, ".cabal"):
			key := strings.TrimPrefix(p, "package/")
			key = key[:strings.IndexByte(key, '/')]
			if c, ok := cabals[key]; ok {
				fmt.Fprint(w, c)
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	old := BaseURL
	BaseURL = srv.URL
	liveMemo.Clear()
	return func() { BaseURL = old; srv.Close() }
}

func bump(name, from, to string) diffx.FileDiff {
	return diffx.FileDiff{Path: "stack.yaml.lock", Changes: []diffx.Change{{
		Name: name, Ecosystem: "Hackage", Kind: diffx.Changed,
		Old: []string{from}, New: []string{to},
	}}}
}

func ts(age time.Duration) string {
	return time.Now().UTC().Add(-age).Format(time.RFC3339)
}

func TestAgesFreshAndSource(t *testing.T) {
	defer fakeHackage(t,
		map[string]string{"aeson": `{"2.2.2.0":"normal","2.2.3.0":"normal"}`},
		map[string]string{"aeson-2.2.3.0": ts(3 * 24 * time.Hour)},
		map[string]string{"aeson-2.2.3.0": "name: aeson\nhomepage: https://github.com/haskell/aeson\nsource-repository head\n  type: git\n  location: git://github.com/haskell/aeson.git\n"},
		`[]`)()
	diffs := []diffx.FileDiff{bump("aeson", "2.2.2.0", "2.2.3.0")}
	checked, err := Annotate(diffs, 7)
	if err != nil || !checked {
		t.Fatalf("Annotate: checked=%v err=%v", checked, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 3 || !c.Fresh {
		t.Errorf("age=%d fresh=%v, want 3/true", c.AgeDays, c.Fresh)
	}
	if c.SourceRepo != "https://github.com/haskell/aeson" {
		t.Errorf("SourceRepo=%q", c.SourceRepo)
	}
	if c.Deprecated || c.Unlisted {
		t.Errorf("unexpected flags: deprecated=%v unlisted=%v", c.Deprecated, c.Unlisted)
	}
}

func TestPackageDeprecationWithReplacements(t *testing.T) {
	defer fakeHackage(t,
		map[string]string{"cryptonite": `{"0.30":"normal"}`},
		nil, nil,
		`[{"deprecated-package":"cryptonite","in-favour-of":["crypton","cryptohash-md5","cryptohash-sha1","cryptohash-sha256"]}]`)()
	diffs := []diffx.FileDiff{bump("cryptonite", "0.29", "0.30")}
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated {
		t.Fatal("want deprecated")
	}
	want := "deprecated on Hackage; use crypton, cryptohash-md5 or cryptohash-sha1 instead"
	if c.DeprecatedReason != want {
		t.Errorf("reason=%q\nwant   %q", c.DeprecatedReason, want)
	}
}

func TestVersionDeprecated(t *testing.T) {
	defer fakeHackage(t,
		map[string]string{"aeson": `{"0.10.0.0":"deprecated","0.11.0.0":"normal"}`},
		nil, nil, `[]`)()
	diffs := []diffx.FileDiff{bump("aeson", "0.9.0.1", "0.10.0.0")}
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated || !strings.Contains(c.DeprecatedReason, "0.10.0.0 is marked deprecated") {
		t.Errorf("deprecated=%v reason=%q", c.Deprecated, c.DeprecatedReason)
	}
	if c.Unlisted {
		t.Error("deprecated versions stay listed; must not be unlisted")
	}
}

func TestUnlistedRegistryVerified(t *testing.T) {
	defer fakeHackage(t,
		map[string]string{"text": `{"2.1":"normal","2.1.1":"normal"}`},
		nil, nil, `[]`)()
	diffs := []diffx.FileDiff{bump("text", "2.1", "9.9.9")}
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "9.9.9" {
		t.Errorf("unlisted=%v versions=%v", c.Unlisted, c.UnlistedVersions)
	}
}

func TestUnknownPackageMakesNoClaims(t *testing.T) {
	defer fakeHackage(t, map[string]string{}, nil, nil, `[]`)()
	diffs := []diffx.FileDiff{bump("acme-internal-pkg", "1.0", "1.1")}
	checked, err := Annotate(diffs, 0)
	if err != nil {
		t.Fatal(err)
	}
	if checked {
		t.Error("nothing was on Hackage; checked must be false")
	}
	c := diffs[0].Changes[0]
	if c.Unlisted || c.Deprecated {
		t.Errorf("unexpected flags on unknown package: %+v", c)
	}
}

func TestNonRegistrySkipped(t *testing.T) {
	defer fakeHackage(t, map[string]string{"aeson": `{"2.2.3.0":"normal"}`}, nil, nil, `[]`)()
	d := bump("aeson", "2.2.2.0", "9.9.9")
	d.Changes[0].NonRegistry = true
	diffs := []diffx.FileDiff{d}
	checked, err := Annotate(diffs, 0)
	if err != nil {
		t.Fatal(err)
	}
	if checked || diffs[0].Changes[0].Unlisted {
		t.Errorf("NonRegistry change must be skipped (checked=%v)", checked)
	}
}

func TestLatest(t *testing.T) {
	defer fakeHackage(t,
		map[string]string{"aeson": `{"2.2.2.0":"normal","2.2.3.0":"normal","2.2.4.0":"deprecated"}`},
		nil, nil, `[]`)()
	v, err := Latest("aeson")
	if err != nil {
		t.Fatal(err)
	}
	if v != "2.2.3.0" {
		t.Errorf("Latest=%q, want 2.2.3.0 (deprecated 2.2.4.0 skipped)", v)
	}
	if _, err := Latest("nope"); err == nil {
		t.Error("want error for unknown package")
	}
}

func TestHumanList(t *testing.T) {
	for _, tc := range []struct {
		in   []string
		want string
	}{
		{[]string{"a"}, "a"},
		{[]string{"a", "b"}, "a or b"},
		{[]string{"a", "b", "c"}, "a, b or c"},
		{[]string{"a", "b", "c", "d"}, "a, b or c"},
	} {
		if got := humanList(tc.in); got != tc.want {
			t.Errorf("humanList(%v)=%q want %q", tc.in, got, tc.want)
		}
	}
}
