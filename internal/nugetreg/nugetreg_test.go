package nugetreg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// fakeNuGet serves registration documents by path (relative to the
// server root). Missing paths 404.
func fakeNuGet(t *testing.T, docs map[string]string) (*httptest.Server, func()) {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if doc, ok := docs[r.URL.Path]; ok {
			fmt.Fprint(w, strings.ReplaceAll(doc, "SRV", srv.URL))
			return
		}
		http.NotFound(w, r)
	}))
	old := RegURL
	RegURL = srv.URL
	return srv, func() { RegURL = old; srv.Close() }
}

func bump(name, from, to string) []diffx.FileDiff {
	return []diffx.FileDiff{{Path: "packages.lock.json", Changes: []diffx.Change{{
		Name: name, Ecosystem: "NuGet", Kind: diffx.Changed,
		Old: []string{from}, New: []string{to},
	}}}}
}

func ts(age time.Duration) string {
	return time.Now().UTC().Add(-age).Format("2006-01-02T15:04:05.000+00:00")
}

func leaf(version, published string, listed bool, license, extra string) string {
	l := "true"
	if !listed {
		l = "false"
	}
	return fmt.Sprintf(`{"catalogEntry":{"version":%q,"listed":%s,"published":%q,"licenseExpression":%q%s}}`,
		version, l, published, license, extra)
}

func inlinedIndex(leaves ...string) string {
	return fmt.Sprintf(`{"count":1,"items":[{"lower":"0.0.0","upper":"999.0.0","items":[%s]}]}`,
		strings.Join(leaves, ","))
}

func TestListedBumpNoFlagsAndAgeBackfill(t *testing.T) {
	_, done := fakeNuGet(t, map[string]string{
		"/acme.lib/index.json": inlinedIndex(
			leaf("1.0.0", ts(400*24*time.Hour), true, "MIT", ""),
			leaf("1.1.0", ts(2*24*time.Hour), true, "MIT", ""),
		),
	})
	defer done()
	diffs := bump("Acme.Lib", "1.0.0", "1.1.0")
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if c.Unlisted || c.Deprecated || c.LicenseChanged {
		t.Fatalf("unexpected flags: %+v", c)
	}
	if c.AgeDays != 2 || !c.Fresh {
		t.Fatalf("age backfill failed: age=%d fresh=%v", c.AgeDays, c.Fresh)
	}
	if c.OldLicense != "MIT" || c.NewLicense != "MIT" {
		t.Fatalf("license fallback failed: %q → %q", c.OldLicense, c.NewLicense)
	}
}

func TestAuthorUnlistedVersionLandsInDeprecationLane(t *testing.T) {
	_, done := fakeNuGet(t, map[string]string{
		"/acme.lib/index.json": inlinedIndex(
			leaf("1.0.0", ts(400*24*time.Hour), true, "MIT", ""),
			leaf("1.1.0", "1900-01-01T00:00:00+00:00", false, "MIT", ""),
		),
	})
	defer done()
	diffs := bump("Acme.Lib", "1.0.0", "1.1.0")
	// deps.dev lag-claimed it missing; the registry knows better.
	diffs[0].Changes[0].Unlisted = true
	diffs[0].Changes[0].UnlistedVersions = []string{"1.1.0"}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if c.Unlisted {
		t.Fatalf("listed:false is restorable, must not keep ▲: %+v", c)
	}
	if !c.Deprecated || c.DeprecatedReason != "unlisted on the registry (hidden by its author)" {
		t.Fatalf("listed:false should land in the deprecation lane: %+v", c)
	}
	if c.Fresh || c.AgeDays != 0 {
		t.Fatalf("1900 sentinel must not drive ages: %+v", c)
	}
}

func TestAbsentPrereleaseCleared(t *testing.T) {
	_, done := fakeNuGet(t, map[string]string{
		"/acme.lib/index.json": inlinedIndex(
			leaf("4.11.0-3.24281.8", ts(100*24*time.Hour), true, "MIT", ""),
		),
	})
	defer done()
	// A CI-feed daily build: absent from nuget.org, claimed by deps.dev.
	diffs := bump("Acme.Lib", "4.11.0-3.24281.8", "4.12.0-1.24355.3")
	diffs[0].Changes[0].Unlisted = true
	diffs[0].Changes[0].UnlistedVersions = []string{"4.12.0-1.24355.3"}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if c.Unlisted || c.Deprecated {
		t.Fatalf("absent prerelease must be cleared, not flagged: %+v", c)
	}
}

func TestMissingVersionFlagsAndRegistryClearsDepsDevClaim(t *testing.T) {
	_, done := fakeNuGet(t, map[string]string{
		"/acme.lib/index.json": inlinedIndex(
			leaf("1.0.0", ts(400*24*time.Hour), true, "MIT", ""),
			leaf("1.1.0", ts(30*24*time.Hour), true, "MIT", ""),
		),
	})
	defer done()

	// deps.dev lagged and claimed 1.1.0 unlisted; the registry lists it.
	diffs := bump("Acme.Lib", "1.0.0", "1.1.0")
	diffs[0].Changes[0].Unlisted = true
	diffs[0].Changes[0].UnlistedVersions = []string{"1.1.0"}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Unlisted {
		t.Fatalf("registry-listed version must clear the deps.dev claim")
	}

	// A version the index simply lacks flags even without a prior claim.
	diffs = bump("Acme.Lib", "1.0.0", "1.2.0")
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || c.UnlistedVersions[0] != "1.2.0" {
		t.Fatalf("missing version should flag: %+v", c)
	}
}

func TestDeprecationWithReplacement(t *testing.T) {
	dep := `,"deprecation":{"message":"long story","reasons":["Legacy"],"alternatePackage":{"id":"Acme.NewLib","range":"*"}}`
	_, done := fakeNuGet(t, map[string]string{
		"/acme.lib/index.json": inlinedIndex(
			leaf("1.0.0", ts(400*24*time.Hour), true, "MIT", ""),
			leaf("1.1.0", ts(300*24*time.Hour), true, "MIT", dep),
		),
	})
	defer done()
	diffs := bump("Acme.Lib", "1.0.0", "1.1.0")
	if err := Annotate(diffs, 30); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated || c.DeprecatedReason != "legacy; use Acme.NewLib instead" {
		t.Fatalf("deprecation: %+v", c)
	}
	if c.Fresh {
		t.Fatalf("300d-old release must not be fresh")
	}
}

func TestLicenseChangeFallbackOnly(t *testing.T) {
	_, done := fakeNuGet(t, map[string]string{
		"/acme.lib/index.json": inlinedIndex(
			leaf("1.0.0", ts(400*24*time.Hour), true, "MIT", ""),
			leaf("2.0.0", ts(200*24*time.Hour), true, "BUSL-1.1", ""),
		),
	})
	defer done()
	diffs := bump("Acme.Lib", "1.0.0", "2.0.0")
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.LicenseChanged || c.OldLicense != "MIT" || c.NewLicense != "BUSL-1.1" {
		t.Fatalf("license change: %+v", c)
	}

	// deps.dev already filled the licenses in: never overwrite.
	diffs = bump("Acme.Lib", "1.0.0", "2.0.0")
	diffs[0].Changes[0].OldLicense, diffs[0].Changes[0].NewLicense = "Apache-2.0", "Apache-2.0"
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c = diffs[0].Changes[0]
	if c.LicenseChanged || c.OldLicense != "Apache-2.0" {
		t.Fatalf("deps.dev licenses overwritten: %+v", c)
	}
}

func TestPagedIndexFetchesOnlyRelevantPages(t *testing.T) {
	var pageGets int32
	docs := map[string]string{
		"/acme.big/index.json": `{"count":3,"items":[
			{"@id":"SRV/acme.big/page0.json","lower":"1.0.0","upper":"1.9.0"},
			{"@id":"SRV/acme.big/page1.json","lower":"2.0.0","upper":"2.9.0"},
			{"@id":"SRV/acme.big/page2.json","lower":"3.0.0","upper":"3.9.0"}]}`,
		"/acme.big/page1.json": fmt.Sprintf(`{"items":[%s,%s]}`,
			leaf("2.0.0", ts(500*24*time.Hour), true, "MIT", ""),
			leaf("2.1.0", ts(100*24*time.Hour), true, "MIT", "")),
	}
	srv, done := fakeNuGet(t, docs)
	defer done()
	base := http.HandlerFunc(srv.Config.Handler.ServeHTTP)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "page") {
			atomic.AddInt32(&pageGets, 1)
		}
		base.ServeHTTP(w, r)
	})

	diffs := bump("Acme.Big", "2.0.0", "2.1.0")
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if c.Unlisted {
		t.Fatalf("listed paged version flagged: %+v", c)
	}
	if got := atomic.LoadInt32(&pageGets); got != 1 {
		t.Fatalf("expected exactly 1 page fetch, got %d", got)
	}

	// A version above every page range is genuinely missing: flag it
	// without fetching anything extra.
	diffs = bump("Acme.Big", "2.1.0", "99.9.9")
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; !c.Unlisted || c.UnlistedVersions[0] != "99.9.9" {
		t.Fatalf("out-of-range version should flag: %+v", c)
	}
}

func TestFailedPageStaysQuiet(t *testing.T) {
	_, done := fakeNuGet(t, map[string]string{
		"/acme.big/index.json": `{"count":1,"items":[
			{"@id":"SRV/acme.big/page0.json","lower":"1.0.0","upper":"1.9.0"}]}`,
		// page0.json intentionally missing → fetch 404s → partial
	})
	defer done()
	diffs := bump("Acme.Big", "1.0.0", "1.1.0")
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; c.Unlisted {
		t.Fatalf("partial coverage must not flag: %+v", c)
	}

	// …but a deps.dev claim it cannot disprove survives.
	diffs = bump("Acme.Big", "1.0.0", "1.1.0")
	diffs[0].Changes[0].Unlisted = true
	diffs[0].Changes[0].UnlistedVersions = []string{"1.1.0"}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; !c.Unlisted {
		t.Fatalf("deps.dev claim dropped despite partial coverage: %+v", c)
	}
}

func TestUnknownPackageAndNonRegistrySkipped(t *testing.T) {
	_, done := fakeNuGet(t, map[string]string{})
	defer done()
	diffs := bump("Acme.Ghost", "1.0.0", "9.9.9")
	diffs = append(diffs, bump("Local.Proj", "1.0.0", "2.0.0")...)
	diffs[1].Changes[0].NonRegistry = true
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	for _, d := range diffs {
		if d.Changes[0].Unlisted {
			t.Fatalf("unknown/non-registry package flagged: %+v", d.Changes[0])
		}
	}
}

func TestNormalization(t *testing.T) {
	_, done := fakeNuGet(t, map[string]string{
		"/acme.lib/index.json": inlinedIndex(
			leaf("1.0.0-BETA.1+sha.abc", ts(10*24*time.Hour), true, "MIT", ""),
		),
	})
	defer done()
	diffs := bump("Acme.Lib", "", "1.0.0-beta.1")
	diffs[0].Changes[0].Old = nil
	diffs[0].Changes[0].Kind = diffx.Added
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; c.Unlisted {
		t.Fatalf("case/build-metadata differences must match: %+v", c)
	}
}
