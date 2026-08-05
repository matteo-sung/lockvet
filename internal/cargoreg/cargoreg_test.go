package cargoreg

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

// fakeCrates serves canned sparse-index documents (by crate name) and
// crates.io API answers (by full path, e.g. "/crates/demo/versions").
// It returns a counter of API hits and a teardown func.
func fakeCrates(t *testing.T, index map[string]string, api map[string]string) (*int64, func()) {
	t.Helper()
	var apiHits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/crates/") {
			atomic.AddInt64(&apiHits, 1)
			if doc, ok := api[r.URL.Path]; ok {
				fmt.Fprint(w, doc)
				return
			}
			http.NotFound(w, r)
			return
		}
		for name, doc := range index {
			if r.URL.Path == indexPath(name) {
				fmt.Fprint(w, doc)
				return
			}
		}
		http.NotFound(w, r)
	}))
	oldIdx, oldAPI, oldUse := IndexURL, APIURL, UseAPI
	IndexURL, APIURL = srv.URL, srv.URL
	return &apiHits, func() { IndexURL, APIURL, UseAPI = oldIdx, oldAPI, oldUse; srv.Close() }
}

func idxLine(v string, yanked bool) string {
	return fmt.Sprintf(`{"name":"demo","vers":%q,"yanked":%v}`, v, yanked)
}

func apiVer(v string, yanked, trustpub bool, age time.Duration) string {
	tp := "null"
	if trustpub {
		tp = `{"provider":"github","repository":"o/r"}`
	}
	return fmt.Sprintf(`{"num":%q,"yanked":%v,"yank_message":null,"trustpub_data":%s,"created_at":%q}`,
		v, yanked, tp, time.Now().UTC().Add(-age).Format(time.RFC3339))
}

func bump(from, to string) []diffx.FileDiff {
	return []diffx.FileDiff{{Path: "Cargo.lock", Changes: []diffx.Change{{
		Name: "demo", Ecosystem: "crates.io", Kind: diffx.Changed,
		Old: []string{from}, New: []string{to},
	}}}}
}

const day = 24 * time.Hour

func demoIndex() map[string]string {
	return map[string]string{"demo": idxLine("1.0.0", false) + "\n" + idxLine("1.1.0", false) + "\n" +
		idxLine("1.2.0", false) + "\n" + idxLine("2.0.0-rc1", false) + "\n" + idxLine("2.0.0", false)}
}

func demoVersionsAPI(incomingTrustpub bool, incomingAge time.Duration) map[string]string {
	return map[string]string{"/crates/demo/versions": `{"versions":[` +
		apiVer("2.0.0", false, incomingTrustpub, incomingAge) + `,` +
		apiVer("2.0.0-rc1", false, false, 40*day) + `,` +
		apiVer("1.2.0", false, true, 60*day) + `,` +
		apiVer("1.1.0", false, true, 90*day) + `,` +
		apiVer("1.0.0", false, true, 120*day) +
		`],"meta":{"total":5}}`}
}

func TestProvenanceDropIndexPath(t *testing.T) {
	_, done := fakeCrates(t, demoIndex(), demoVersionsAPI(false, day))
	defer done()
	diffs := bump("1.2.0", "2.0.0")
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.ProvenanceDropped || len(c.UnattestedVersions) != 1 || c.UnattestedVersions[0] != "2.0.0" {
		t.Fatalf("want provenance drop on 2.0.0, got %+v", c)
	}
}

func TestProvenanceKeptQuiet(t *testing.T) {
	_, done := fakeCrates(t, demoIndex(), demoVersionsAPI(true, day))
	defer done()
	diffs := bump("1.2.0", "2.0.0") // incoming attests too: nothing dropped
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].ProvenanceDropped {
		t.Fatalf("attested incoming version must not flag")
	}
}

func TestProvenanceAgeGate(t *testing.T) {
	_, done := fakeCrates(t, demoIndex(), demoVersionsAPI(false, 60*day))
	defer done()
	diffs := bump("1.2.0", "2.0.0") // unattested but two months old: practice, not attack
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].ProvenanceDropped {
		t.Fatalf("old incoming version must not flag")
	}
}

func TestProvenanceNoEstablishedPractice(t *testing.T) {
	api := map[string]string{"/crates/demo/versions": `{"versions":[` +
		apiVer("2.0.0", false, false, day) + `,` +
		apiVer("1.2.0", false, true, 60*day) + `,` + // only the pin attested: one-off
		apiVer("1.1.0", false, false, 90*day) + `,` +
		apiVer("1.0.0", false, true, 120*day) +
		`],"meta":{"total":4}}`}
	_, done := fakeCrates(t, demoIndex(), api)
	defer done()
	diffs := bump("1.2.0", "2.0.0")
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].ProvenanceDropped {
		t.Fatalf("mixed practice below the incoming version must not flag")
	}
}

func TestProvenanceOldSideUnattested(t *testing.T) {
	api := map[string]string{"/crates/demo/versions": `{"versions":[` +
		apiVer("2.0.0", false, false, day) + `,` +
		apiVer("1.2.0", false, false, 60*day) + `,` +
		apiVer("1.1.0", false, true, 90*day) + `,` +
		apiVer("1.0.0", false, true, 120*day) +
		`],"meta":{"total":4}}`}
	_, done := fakeCrates(t, demoIndex(), api)
	defer done()
	diffs := bump("1.2.0", "2.0.0")
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].ProvenanceDropped {
		t.Fatalf("unattested outgoing pin must not flag")
	}
}

func TestDepsdevOldAgeSkipsAPIEntirely(t *testing.T) {
	hits, done := fakeCrates(t, demoIndex(), demoVersionsAPI(false, day))
	defer done()
	diffs := bump("1.2.0", "2.0.0")
	diffs[0].Changes[0].PublishedAt = "2020-01-01T00:00:00Z"
	diffs[0].Changes[0].AgeDays = 2000
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].ProvenanceDropped {
		t.Fatalf("deps.dev-old incoming version must not flag")
	}
	if *hits != 0 {
		t.Fatalf("old bumps must not touch the crates.io API, saw %d hits", *hits)
	}
}

func TestSingleVersionFallbackForOldPin(t *testing.T) {
	api := demoVersionsAPI(false, day)
	// The versions page misses the old pin (deep history): a
	// single-version lookup must resolve it.
	api["/crates/demo/versions"] = `{"versions":[` +
		apiVer("2.0.0", false, false, day) + `,` +
		apiVer("1.2.0", false, true, 60*day) + `,` +
		apiVer("1.1.0", false, true, 90*day) + `,` +
		apiVer("1.0.0", false, true, 120*day) +
		`],"meta":{"total":6}}`
	api["/crates/demo/0.9.0"] = `{"version":` + apiVer("0.9.0", false, true, 300*day) + `}`
	idx := map[string]string{"demo": demoIndex()["demo"] + "\n" + idxLine("0.9.0", false)}
	_, done := fakeCrates(t, idx, api)
	defer done()
	diffs := bump("0.9.0", "2.0.0")
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.ProvenanceDropped {
		t.Fatalf("single-version fallback should have resolved the old pin, got %+v", c)
	}
}

func TestYankFallback(t *testing.T) {
	idx := map[string]string{"demo": idxLine("1.0.0", false) + "\n" + idxLine("1.1.0", true)}
	_, done := fakeCrates(t, idx, nil)
	defer done()
	diffs := bump("1.0.0", "1.1.0")
	diffs[0].Changes[0].PublishedAt = "2020-01-01T00:00:00Z"
	diffs[0].Changes[0].AgeDays = 2000
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated || !strings.Contains(c.DeprecatedReason, "yanked on crates.io") {
		t.Fatalf("want yank fallback, got %+v", c)
	}
}

func TestYankNeverOverwritesDepsdev(t *testing.T) {
	idx := map[string]string{"demo": idxLine("1.0.0", false) + "\n" + idxLine("1.1.0", true)}
	_, done := fakeCrates(t, idx, nil)
	defer done()
	diffs := bump("1.0.0", "1.1.0")
	diffs[0].Changes[0].PublishedAt = "2020-01-01T00:00:00Z"
	diffs[0].Changes[0].AgeDays = 2000
	diffs[0].Changes[0].Deprecated = true
	diffs[0].Changes[0].DeprecatedReason = "upstream says so"
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].DeprecatedReason != "upstream says so" {
		t.Fatalf("deps.dev reason overwritten: %+v", diffs[0].Changes[0])
	}
}

func TestUnlistedVerification(t *testing.T) {
	idx := map[string]string{"demo": idxLine("1.0.0", false)}
	_, done := fakeCrates(t, idx, nil)
	defer done()
	diffs := bump("0.9.0", "1.0.0")
	c := &diffs[0].Changes[0]
	c.PublishedAt, c.AgeDays = "2020-01-01T00:00:00Z", 2000
	c.Unlisted = true
	c.UnlistedVersions = []string{"1.0.0", "9.9.9"} // deps.dev lag vs truly gone
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "9.9.9" {
		t.Fatalf("want only 9.9.9 to stay flagged, got %+v", c)
	}
}

func TestUnlistedWholeCrateGoneKeepsFlags(t *testing.T) {
	_, done := fakeCrates(t, nil, nil) // 404 everywhere
	defer done()
	diffs := bump("0.9.0", "1.0.0")
	c := &diffs[0].Changes[0]
	c.PublishedAt, c.AgeDays = "2020-01-01T00:00:00Z", 2000
	c.Unlisted = true
	c.UnlistedVersions = []string{"1.0.0"}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if !c.Unlisted {
		t.Fatalf("crate gone from the registry must keep the flag, got %+v", c)
	}
}

func TestAPIListingPath(t *testing.T) {
	_, done := fakeCrates(t, nil, demoVersionsAPI(false, day))
	defer done()
	UseAPI = true
	diffs := bump("1.2.0", "2.0.0")
	c := &diffs[0].Changes[0]
	c.Unlisted = true
	c.UnlistedVersions = []string{"2.0.0"}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if c.Unlisted {
		t.Fatalf("API listing serves 2.0.0: flag must clear, got %+v", c)
	}
	if !c.ProvenanceDropped {
		t.Fatalf("provenance drop must work on the API path, got %+v", c)
	}
}

func TestNonRegistrySkipped(t *testing.T) {
	hits, done := fakeCrates(t, demoIndex(), demoVersionsAPI(false, day))
	defer done()
	diffs := bump("1.2.0", "2.0.0")
	diffs[0].Changes[0].NonRegistry = true
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].ProvenanceDropped || *hits != 0 {
		t.Fatalf("non-registry crates must not be vetted (hits=%d)", *hits)
	}
}

func TestIndexPathShapes(t *testing.T) {
	for name, want := range map[string]string{
		"a": "/1/a", "ab": "/2/ab", "abc": "/3/a/abc", "serde": "/se/rd/serde", "Inflector": "/in/fl/inflector",
	} {
		if got := indexPath(name); got != want {
			t.Fatalf("indexPath(%q) = %q, want %q", name, got, want)
		}
	}
}
