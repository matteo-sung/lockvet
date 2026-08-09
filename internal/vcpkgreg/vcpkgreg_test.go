package vcpkgreg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

const (
	oldSha = "aaaaaaaaaaaa"
	newSha = "bbbbbbbbbbbb"
	badSha = "cccccccccccc"
)

func withFake(t *testing.T) {
	t.Helper()
	mux := http.NewServeMux()
	dates := map[string]string{
		oldSha: "2024-03-01T10:00:00Z",
		newSha: "2026-06-15T10:00:00Z",
	}
	mux.HandleFunc("/repos/microsoft/vcpkg/commits/", func(w http.ResponseWriter, r *http.Request) {
		sha := r.URL.Path[len("/repos/microsoft/vcpkg/commits/"):]
		d, ok := dates[sha]
		if !ok {
			w.WriteHeader(422)
			fmt.Fprint(w, `{"message":"No commit found"}`)
			return
		}
		fmt.Fprintf(w, `{"sha":"%s","commit":{"committer":{"date":"%s"}}}`, sha, d)
	})
	mux.HandleFunc("/microsoft/vcpkg/master/versions/f-/fmt.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"versions":[
		  {"version":"12.2.0","port-version":1,"git-tree":"x"},
		  {"version":"12.2.0","port-version":0,"git-tree":"x"},
		  {"version":"12.1.0","port-version":0,"git-tree":"x"}]}`)
	})
	mux.HandleFunc("/microsoft/vcpkg/master/versions/o-/openssl.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"versions":[
		  {"version":"3.1.4","port-version":0,"git-tree":"x"},
		  {"version":"3.1.3","port-version":0,"git-tree":"x"}]}`)
	})
	server := httptest.NewServer(mux) // anything else 404s
	t.Cleanup(server.Close)
	oldAPI, oldRaw, oldNow := APIBase, RawBase, Now
	APIBase, RawBase = server.URL, server.URL
	Now = func() time.Time { return time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { APIBase, RawBase, Now = oldAPI, oldRaw, oldNow })
}

func baselineDiff(old, new string) []diffx.FileDiff {
	return []diffx.FileDiff{{Path: "vcpkg.json", Changes: []diffx.Change{{
		Name: "builtin-baseline", Ecosystem: "vcpkg", Kind: diffx.Changed,
		Old: []string{old}, New: []string{new},
		SourceRepo: "https://github.com/microsoft/vcpkg",
	}}}}
}

func TestBaselineAgeAndCompare(t *testing.T) {
	withFake(t)
	diffs := baselineDiff(oldSha, newSha)
	ok, err := Annotate(diffs, 14, "")
	if err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	c := &diffs[0].Changes[0]
	if c.PublishedAt != "2026-06-15T10:00:00Z" {
		t.Errorf("PublishedAt = %q", c.PublishedAt)
	}
	if c.AgeDays != 46 {
		t.Errorf("AgeDays = %d", c.AgeDays)
	}
	if c.Fresh {
		t.Error("46 days should not be fresh at 14")
	}
	want := "https://github.com/microsoft/vcpkg/compare/" + oldSha + "..." + newSha
	if c.CompareURL != want {
		t.Errorf("CompareURL = %q", c.CompareURL)
	}
	if c.Unlisted {
		t.Error("known commit flagged unlisted")
	}
}

func TestBaselineNotACommit(t *testing.T) {
	withFake(t)
	diffs := baselineDiff(oldSha, badSha)
	if _, err := Annotate(diffs, 14, ""); err != nil {
		t.Fatal(err)
	}
	c := &diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != badSha {
		t.Errorf("want unlisted [%s], got %v (unlisted=%v)", badSha, c.UnlistedVersions, c.Unlisted)
	}
}

func TestBaselineGateOldUnknown(t *testing.T) {
	withFake(t)
	// Old baseline unknown too: repository may be a fork we can't see —
	// no claim.
	diffs := baselineDiff(badSha, "dddddddddddd")
	if _, err := Annotate(diffs, 14, ""); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Unlisted {
		t.Error("claimed unlisted although the old baseline is unknown too")
	}
}

func overrideDiff(name string, old, new string) []diffx.FileDiff {
	return []diffx.FileDiff{{Path: "vcpkg.json", Changes: []diffx.Change{{
		Name: name, Ecosystem: "vcpkg", Kind: diffx.Changed,
		Old: []string{old}, New: []string{new},
	}}}}
}

func TestOverrideKnownVersion(t *testing.T) {
	withFake(t)
	diffs := overrideDiff("fmt", "12.1.0", "12.2.0#1")
	ok, err := Annotate(diffs, 14, "")
	if err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	if diffs[0].Changes[0].Unlisted {
		t.Error("known version flagged")
	}
}

func TestOverrideUnknownVersion(t *testing.T) {
	withFake(t)
	diffs := overrideDiff("openssl", "3.1.3", "9.9.9")
	if _, err := Annotate(diffs, 14, ""); err != nil {
		t.Fatal(err)
	}
	c := &diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "9.9.9" {
		t.Errorf("want unlisted [9.9.9], got %v", c.UnlistedVersions)
	}
}

func TestOverridePortVersionOnlyBumpQuiet(t *testing.T) {
	withFake(t)
	// Overlay ports re-cut official versions with a bumped #N — never a
	// claim as long as the base version is known.
	diffs := overrideDiff("openssl", "3.1.4", "3.1.4#7")
	if _, err := Annotate(diffs, 14, ""); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Unlisted {
		t.Error("port-version-only bump flagged")
	}
}

func TestOverrideUnknownPortQuiet(t *testing.T) {
	withFake(t)
	diffs := overrideDiff("corp-internal", "1.0.0", "2.0.0")
	if _, err := Annotate(diffs, 14, ""); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Unlisted {
		t.Error("unknown port flagged")
	}
}

func TestOverrideGateOldUnknownVersion(t *testing.T) {
	withFake(t)
	// The outgoing version was never in the database either → the
	// project overrides from somewhere else; no claim.
	diffs := overrideDiff("fmt", "0.0.1-corp", "0.0.2-corp")
	if _, err := Annotate(diffs, 14, ""); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Unlisted {
		t.Error("claimed although outgoing version was unknown too")
	}
}

func TestOverrideAddedQuiet(t *testing.T) {
	withFake(t)
	diffs := []diffx.FileDiff{{Path: "vcpkg.json", Changes: []diffx.Change{{
		Name: "fmt", Ecosystem: "vcpkg", Kind: diffx.Added, New: []string{"9.9.9"},
	}}}}
	if _, err := Annotate(diffs, 14, ""); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Unlisted {
		t.Error("added override claimed without an outgoing gate")
	}
}

func TestLatest(t *testing.T) {
	withFake(t)
	v, err := Latest("fmt")
	if err != nil {
		t.Fatal(err)
	}
	if v != "12.2.0#1" {
		t.Errorf("Latest = %q", v)
	}
	if _, err := Latest("corp-internal"); err == nil {
		t.Error("unknown port should error")
	}
}

func TestOverridePkgModeAddedClaims(t *testing.T) {
	withFake(t)
	diffs := []diffx.FileDiff{{Path: "vcpkg:fmt@9.9.9", Kind: "pkg", Changes: []diffx.Change{{
		Name: "fmt", Ecosystem: "vcpkg", Kind: diffx.Added,
		New: []string{"9.9.9"},
	}}}}
	ok, err := Annotate(diffs, 14, "")
	if err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	c := &diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "9.9.9" {
		t.Errorf("pkg-mode added override should claim unlisted: %+v", c)
	}
}

func TestOverridePkgModeAddedKnownQuiet(t *testing.T) {
	withFake(t)
	diffs := []diffx.FileDiff{{Path: "vcpkg:fmt@12.2.0", Kind: "pkg", Changes: []diffx.Change{{
		Name: "fmt", Ecosystem: "vcpkg", Kind: diffx.Added,
		New: []string{"12.2.0#1"},
	}}}}
	ok, err := Annotate(diffs, 14, "")
	if err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	if c := &diffs[0].Changes[0]; c.Unlisted {
		t.Errorf("known version should stay quiet: %+v", c)
	}
}
