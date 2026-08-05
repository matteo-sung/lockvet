package phpreg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// fakePackagist serves p2 documents under /p2/ and API documents under
// /packages/. Missing names 404.
func fakePackagist(t *testing.T, p2, api map[string]string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if name, ok := strings.CutPrefix(r.URL.Path, "/p2/"); ok {
			if doc, ok := p2[strings.TrimSuffix(name, ".json")]; ok {
				fmt.Fprint(w, doc)
				return
			}
		}
		if name, ok := strings.CutPrefix(r.URL.Path, "/packages/"); ok {
			if doc, ok := api[strings.TrimSuffix(name, ".json")]; ok {
				fmt.Fprint(w, doc)
				return
			}
		}
		http.NotFound(w, r)
	}))
	oldRepo, oldAPI, oldUse := RepoURL, APIURL, UseAPI
	RepoURL, APIURL = srv.URL, srv.URL
	return func() { RepoURL, APIURL, UseAPI = oldRepo, oldAPI, oldUse; srv.Close() }
}

func bump(name, from, to string) diffx.FileDiff {
	return diffx.FileDiff{Path: "composer.lock", Changes: []diffx.Change{{
		Name: name, Ecosystem: "Packagist", Kind: diffx.Changed,
		Old: []string{from}, New: []string{to},
	}}}
}

func ts(age time.Duration) string {
	return time.Now().UTC().Add(-age).Format("2006-01-02T15:04:05+00:00")
}

// p2Doc builds a minified p2 document: entries newest first, each entry
// only carrying the fields given (like Composer's MetadataMinifier).
func p2Doc(name string, entries ...string) string {
	return fmt.Sprintf(`{"minified":"composer/2.0","packages":{%q:[%s]}}`,
		name, strings.Join(entries, ","))
}

func TestP2MinifiedExpansionAndSignals(t *testing.T) {
	// Newest entry carries license + abandoned + source; older entries
	// inherit license via minification unless overridden.
	doc := p2Doc("acme/lib",
		fmt.Sprintf(`{"version":"v2.0.0","version_normalized":"2.0.0.0","time":%q,"license":["GPL-3.0-only"],"abandoned":"acme/new-lib","source":{"type":"git","url":"https://github.com/acme/lib.git"}}`, ts(2*24*time.Hour)),
		fmt.Sprintf(`{"version":"v1.9.0","time":%q,"license":["MIT"]}`, ts(400*24*time.Hour)),
		fmt.Sprintf(`{"version":"v1.8.0","time":%q}`, ts(500*24*time.Hour)), // inherits MIT
	)
	defer fakePackagist(t, map[string]string{"acme/lib": doc}, nil)()

	diffs := []diffx.FileDiff{bump("acme/lib", "1.8.0", "2.0.0")}
	ok, err := Annotate(diffs, 7)
	if err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 2 || !c.Fresh {
		t.Errorf("age = %d fresh = %v, want 2/true", c.AgeDays, c.Fresh)
	}
	if !c.Deprecated || !strings.Contains(c.DeprecatedReason, "acme/new-lib") {
		t.Errorf("deprecated = %v %q, want abandoned with replacement", c.Deprecated, c.DeprecatedReason)
	}
	if !c.LicenseChanged || c.OldLicense != "MIT" || c.NewLicense != "GPL-3.0-only" {
		t.Errorf("license: %v %q → %q", c.LicenseChanged, c.OldLicense, c.NewLicense)
	}
	if c.Unlisted {
		t.Errorf("unlisted flagged for listed versions")
	}
	if c.SourceRepo != "https://github.com/acme/lib" {
		t.Errorf("SourceRepo = %q", c.SourceRepo)
	}
}

func TestUnlistedAndDevVersions(t *testing.T) {
	doc := p2Doc("acme/lib",
		fmt.Sprintf(`{"version":"v1.1.0","time":%q}`, ts(40*24*time.Hour)),
		fmt.Sprintf(`{"version":"v1.0.0","time":%q}`, ts(80*24*time.Hour)),
	)
	defer fakePackagist(t, map[string]string{"acme/lib": doc}, nil)()

	diffs := []diffx.FileDiff{
		bump("acme/lib", "1.0.0", "1.2.0"),    // 1.2.0 missing → unlisted
		bump("acme/lib", "1.0.0", "dev-main"), // branch pin: never flagged
		bump("acme/gone", "1.0.0", "1.1.0"),   // 404: package unknown, no flags
		bump("vendorless", "1.0.0", "1.1.0"),  // no “/”: not a Packagist package
	}
	diffs = append(diffs, diffx.FileDiff{Path: "composer.lock", Changes: []diffx.Change{{
		Name: "acme/pinned", Ecosystem: "Packagist", Kind: diffx.Changed,
		Old: []string{"1.0.0"}, New: []string{"9.9.9"}, NonRegistry: true, // VCS pin
	}}})
	ok, err := Annotate(diffs, 7)
	if err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	if c := diffs[0].Changes[0]; !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "1.2.0" {
		t.Errorf("want 1.2.0 unlisted, got %v %v", c.Unlisted, c.UnlistedVersions)
	}
	for i := 1; i < len(diffs); i++ {
		if c := diffs[i].Changes[0]; c.Unlisted {
			t.Errorf("diff %d (%s): unexpected unlisted flag", i, c.Name)
		}
	}
	if c := diffs[1].Changes[0]; c.Fresh || c.AgeDays != 0 {
		t.Errorf("dev-main pin picked up an age: %+v", c)
	}
}

func TestAbandonedTrueWithoutReplacement(t *testing.T) {
	doc := p2Doc("acme/old",
		fmt.Sprintf(`{"version":"1.0.1","time":%q,"abandoned":true}`, ts(900*24*time.Hour)))
	defer fakePackagist(t, map[string]string{"acme/old": doc}, nil)()

	diffs := []diffx.FileDiff{bump("acme/old", "1.0.0", "1.0.1")}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated || c.DeprecatedReason != "abandoned by its maintainer" {
		t.Errorf("got %v %q", c.Deprecated, c.DeprecatedReason)
	}
	if c.Fresh {
		t.Errorf("900-day-old release flagged fresh")
	}
	// Removals of an abandoned package are good news, not warnings.
	rm := []diffx.FileDiff{{Path: "composer.lock", Changes: []diffx.Change{{
		Name: "acme/old", Ecosystem: "Packagist", Kind: diffx.Removed, Old: []string{"1.0.0"},
	}}}}
	if _, err := Annotate(rm, 7); err != nil {
		t.Fatal(err)
	}
	if rm[0].Changes[0].Deprecated {
		t.Errorf("removal flagged deprecated")
	}
}

func TestAPIMode(t *testing.T) {
	api := fmt.Sprintf(`{"package":{"name":"acme/lib","abandoned":"acme/new-lib","versions":{
		"v2.0.0":{"version":"v2.0.0","time":%q,"license":["Apache-2.0"],"source":{"type":"git","url":"https://github.com/acme/lib.git"}},
		"v1.0.0":{"version":"v1.0.0","time":%q,"license":["MIT"],"source":{"type":"git","url":"https://github.com/acme/lib.git"}},
		"dev-main":{"version":"dev-main","time":%q}
	}}}`, ts(3*24*time.Hour), ts(300*24*time.Hour), ts(time.Hour))
	defer fakePackagist(t, nil, map[string]string{"acme/lib": api})()
	UseAPI = true

	diffs := []diffx.FileDiff{bump("acme/lib", "1.0.0", "2.0.0")}
	ok, err := Annotate(diffs, 7)
	if err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 3 || !c.Fresh || !c.Deprecated || !c.LicenseChanged {
		t.Errorf("api mode: %+v", c)
	}
	if c.OldLicense != "MIT" || c.NewLicense != "Apache-2.0" {
		t.Errorf("api licenses: %q → %q", c.OldLicense, c.NewLicense)
	}
	if c.SourceRepo != "https://github.com/acme/lib" {
		t.Errorf("api SourceRepo = %q", c.SourceRepo)
	}
}

func TestTotalFailureReturnsError(t *testing.T) {
	oldRepo := RepoURL
	RepoURL = "http://127.0.0.1:1" // nothing listens here
	defer func() { RepoURL = oldRepo }()
	diffs := []diffx.FileDiff{bump("acme/lib", "1.0.0", "2.0.0")}
	if _, err := Annotate(diffs, 7); err == nil {
		t.Fatal("want error on total failure")
	}
}

func TestNoPackagistChanges(t *testing.T) {
	diffs := []diffx.FileDiff{{Path: "package-lock.json", Changes: []diffx.Change{{
		Name: "left-pad", Ecosystem: "npm", Kind: diffx.Changed,
		Old: []string{"1.0.0"}, New: []string{"1.3.0"},
	}}}}
	ok, err := Annotate(diffs, 7)
	if err != nil || ok {
		t.Fatalf("want false/nil for non-PHP diff, got %v, %v", ok, err)
	}
}
