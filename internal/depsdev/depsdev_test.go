package depsdev

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// fakeServer answers versionbatch queries from a canned table keyed by
// "name@version".
func fakeServer(t *testing.T, table map[string]versionInfo) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Requests []request `json:"requests"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			t.Fatalf("bad request body: %v", err)
		}
		var out struct {
			Responses []map[string]any `json:"responses"`
		}
		for _, q := range in.Requests {
			key := q.VersionKey.Name + "@" + q.VersionKey.Version
			if info, ok := table[key]; ok {
				out.Responses = append(out.Responses, map[string]any{"version": info})
			} else {
				out.Responses = append(out.Responses, map[string]any{})
			}
		}
		json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func pinClock(t *testing.T, iso string) {
	t.Helper()
	fixed, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		t.Fatal(err)
	}
	old := Now
	Now = func() time.Time { return fixed }
	t.Cleanup(func() { Now = old })
}

func TestAnnotate(t *testing.T) {
	pinClock(t, "2026-07-22T12:00:00Z")
	srv := fakeServer(t, map[string]versionInfo{
		"left-pad@2.0.0": {PublishedAt: "2026-07-20T09:00:00Z"}, // 2 days old → fresh
		"lodash@4.17.21": {PublishedAt: "2021-02-20T00:00:00Z"}, // ancient
		"request@2.88.2": {
			PublishedAt:      "2020-02-11T00:00:00Z",
			IsDeprecated:     true,
			DeprecatedReason: "request has been deprecated\nsee issue #3142",
		},
	})
	old := BatchURL
	BatchURL = srv.URL
	defer func() { BatchURL = old }()

	diffs := []diffx.FileDiff{{
		Path: "package-lock.json", Ecosystem: "npm",
		Changes: []diffx.Change{
			{Name: "left-pad", Ecosystem: "npm", Kind: diffx.Upgraded, Old: []string{"1.3.0"}, New: []string{"2.0.0"}},
			{Name: "lodash", Ecosystem: "npm", Kind: diffx.Upgraded, Old: []string{"4.17.20"}, New: []string{"4.17.21"}},
			{Name: "request", Ecosystem: "npm", Kind: diffx.Added, New: []string{"2.88.2"}},
			{Name: "gone", Ecosystem: "npm", Kind: diffx.Removed, Old: []string{"1.0.0"}},
			{Name: "unknown-pkg", Ecosystem: "npm", Kind: diffx.Added, New: []string{"0.0.1"}},
			{Name: "jsr:@std/path", Ecosystem: "npm", Kind: diffx.Added, New: []string{"1.0.0"}},
		},
	}, {
		Path: "Podfile.lock", Ecosystem: "CocoaPods", // not covered → skipped
		Changes: []diffx.Change{
			{Name: "Alamofire", Ecosystem: "CocoaPods", Kind: diffx.Upgraded, Old: []string{"5.0.0"}, New: []string{"5.9.0"}},
		},
	}}

	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}

	cs := diffs[0].Changes
	if !cs[0].Fresh || cs[0].AgeDays != 2 || cs[0].PublishedAt != "2026-07-20T09:00:00Z" {
		t.Errorf("left-pad: want fresh 2d, got %+v", cs[0])
	}
	if cs[1].Fresh || cs[1].AgeDays < 1900 {
		t.Errorf("lodash: want old & not fresh, got %+v", cs[1])
	}
	if !cs[2].Deprecated || cs[2].DeprecatedReason != "request has been deprecated" {
		t.Errorf("request: want deprecated with first-line reason, got %+v", cs[2])
	}
	if cs[3].PublishedAt != "" {
		t.Errorf("removed pkg should not be queried, got %+v", cs[3])
	}
	if cs[4].PublishedAt != "" || cs[4].Fresh {
		t.Errorf("unknown pkg should stay unannotated, got %+v", cs[4])
	}
	if cs[5].PublishedAt != "" {
		t.Errorf("jsr entry should be skipped, got %+v", cs[5])
	}
	if diffs[1].Changes[0].PublishedAt != "" {
		t.Errorf("CocoaPods should be skipped, got %+v", diffs[1].Changes[0])
	}
}

func TestAnnotateFreshWindow(t *testing.T) {
	pinClock(t, "2026-07-22T12:00:00Z")
	srv := fakeServer(t, map[string]versionInfo{
		"a@1.0.0": {PublishedAt: "2026-07-16T00:00:00Z"}, // 6.5 days → inside 7d window
		"b@1.0.0": {PublishedAt: "2026-07-15T00:00:00Z"}, // 7.5 days → outside
	})
	old := BatchURL
	BatchURL = srv.URL
	defer func() { BatchURL = old }()

	diffs := []diffx.FileDiff{{Ecosystem: "npm", Changes: []diffx.Change{
		{Name: "a", Ecosystem: "npm", Kind: diffx.Added, New: []string{"1.0.0"}},
		{Name: "b", Ecosystem: "npm", Kind: diffx.Added, New: []string{"1.0.0"}},
	}}}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if !diffs[0].Changes[0].Fresh {
		t.Errorf("a: 6.5d old should be fresh at 7d window")
	}
	if diffs[0].Changes[1].Fresh {
		t.Errorf("b: 7.5d old should not be fresh at 7d window")
	}

	// freshDays=0 disables the flag but keeps ages.
	diffs[0].Changes[0].Fresh = false
	if err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Fresh {
		t.Errorf("freshDays=0 must never mark fresh")
	}
	if diffs[0].Changes[0].AgeDays != 6 {
		t.Errorf("age should still be filled, got %d", diffs[0].Changes[0].AgeDays)
	}
}

func TestAnnotateGoPrefix(t *testing.T) {
	pinClock(t, "2026-07-22T12:00:00Z")
	// lockvet stores Go versions without "v"; deps.dev needs it back.
	srv := fakeServer(t, map[string]versionInfo{
		"golang.org/x/tools@v0.47.0": {PublishedAt: "2026-06-26T00:00:00Z"},
	})
	old := BatchURL
	BatchURL = srv.URL
	defer func() { BatchURL = old }()

	diffs := []diffx.FileDiff{{Ecosystem: "Go", Changes: []diffx.Change{
		{Name: "golang.org/x/tools", Ecosystem: "Go", Kind: diffx.Upgraded, Old: []string{"0.45.0"}, New: []string{"0.47.0"}},
	}}}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].AgeDays != 26 {
		t.Errorf("go version should be queried with v-prefix, got %+v", diffs[0].Changes[0])
	}
}

func TestAnnotateServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", 500)
	}))
	defer srv.Close()
	old := BatchURL
	BatchURL = srv.URL
	defer func() { BatchURL = old }()

	diffs := []diffx.FileDiff{{Ecosystem: "npm", Changes: []diffx.Change{
		{Name: "a", Ecosystem: "npm", Kind: diffx.Added, New: []string{"1.0.0"}},
	}}}
	if err := Annotate(diffs, 7); err == nil {
		t.Fatal("want error on HTTP 500")
	}
	if diffs[0].Changes[0].Fresh || diffs[0].Changes[0].PublishedAt != "" {
		t.Errorf("failed annotate must leave diffs untouched")
	}
}

func TestCovers(t *testing.T) {
	for _, eco := range []string{"npm", "crates.io", "PyPI", "Go", "Maven", "NuGet", "RubyGems"} {
		if !Covers(eco) {
			t.Errorf("Covers(%q) = false, want true", eco)
		}
	}
	for _, eco := range []string{"Packagist", "Hex", "Pub", "SwiftURL", "CocoaPods", "Nix", ""} {
		if Covers(eco) {
			t.Errorf("Covers(%q) = true, want false", eco)
		}
	}
}

func TestAnnotateLicenseChange(t *testing.T) {
	pinClock(t, "2026-07-22T12:00:00Z")
	srv := fakeServer(t, map[string]versionInfo{
		// real-world shape: husky 4.x was MIT, 5.x was Parity ("non-standard")
		"husky@4.3.8": {PublishedAt: "2021-01-10T00:00:00Z", Licenses: []string{"MIT"}},
		"husky@5.0.9": {PublishedAt: "2021-02-01T00:00:00Z", Licenses: []string{"non-standard"}},
		// unchanged license → fields set, no flag
		"lodash@4.17.20": {PublishedAt: "2020-08-13T00:00:00Z", Licenses: []string{"MIT"}},
		"lodash@4.17.21": {PublishedAt: "2021-02-20T00:00:00Z", Licenses: []string{"MIT"}},
		// case-only difference → not a change
		"c@1.0.0": {PublishedAt: "2020-01-01T00:00:00Z", Licenses: []string{"Apache-2.0"}},
		"c@2.0.0": {PublishedAt: "2021-01-01T00:00:00Z", Licenses: []string{"APACHE-2.0"}},
		// old side unknown → no claim
		"d@2.0.0": {PublishedAt: "2021-01-01T00:00:00Z", Licenses: []string{"MIT"}},
		// multi-version change: license from most recently published per side
		"e@1.0.0": {PublishedAt: "2020-01-01T00:00:00Z", Licenses: []string{"MIT"}},
		"e@1.5.0": {PublishedAt: "2020-06-01T00:00:00Z", Licenses: []string{"MIT"}},
		"e@2.0.0": {PublishedAt: "2021-01-01T00:00:00Z", Licenses: []string{"BUSL-1.1"}},
	})
	old := BatchURL
	BatchURL = srv.URL
	defer func() { BatchURL = old }()

	diffs := []diffx.FileDiff{{Path: "package-lock.json", Ecosystem: "npm", Changes: []diffx.Change{
		{Name: "husky", Ecosystem: "npm", Kind: diffx.Upgraded, Old: []string{"4.3.8"}, New: []string{"5.0.9"}},
		{Name: "lodash", Ecosystem: "npm", Kind: diffx.Upgraded, Old: []string{"4.17.20"}, New: []string{"4.17.21"}},
		{Name: "c", Ecosystem: "npm", Kind: diffx.Upgraded, Old: []string{"1.0.0"}, New: []string{"2.0.0"}},
		{Name: "d", Ecosystem: "npm", Kind: diffx.Upgraded, Old: []string{"1.0.0"}, New: []string{"2.0.0"}},
		{Name: "e", Ecosystem: "npm", Kind: diffx.Changed, Old: []string{"1.0.0", "1.5.0"}, New: []string{"1.5.0", "2.0.0"}},
		{Name: "husky", Ecosystem: "npm", Kind: diffx.Removed, Old: []string{"4.3.8"}},
	}}}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	cs := diffs[0].Changes
	if !cs[0].LicenseChanged || cs[0].OldLicense != "MIT" || cs[0].NewLicense != "non-standard" {
		t.Errorf("husky: want MIT → non-standard flagged, got %+v", cs[0])
	}
	if cs[1].LicenseChanged || cs[1].OldLicense != "MIT" || cs[1].NewLicense != "MIT" {
		t.Errorf("lodash: want unchanged MIT with fields set, got %+v", cs[1])
	}
	if cs[2].LicenseChanged {
		t.Errorf("c: case-only difference must not flag, got %+v", cs[2])
	}
	if cs[3].LicenseChanged || cs[3].OldLicense != "" {
		t.Errorf("d: unknown old side must not claim a change, got %+v", cs[3])
	}
	if !cs[4].LicenseChanged || cs[4].OldLicense != "MIT" || cs[4].NewLicense != "BUSL-1.1" {
		t.Errorf("e: want MIT → BUSL-1.1 from most recent per side, got %+v", cs[4])
	}
	if cs[5].OldLicense != "" || cs[5].LicenseChanged {
		t.Errorf("removed pkg must not be license-checked, got %+v", cs[5])
	}
}
