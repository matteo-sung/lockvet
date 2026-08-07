package condareg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// fakeAnaconda serves /release/{channel}/{name}/{version} documents and
// answers HEAD /package/{channel}/{name} 200 for names in pkgs. Missing
// paths 404.
func fakeAnaconda(t *testing.T, releases map[string]string, pkgs map[string]bool) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rest, ok := strings.CutPrefix(r.URL.Path, "/release/"); ok {
			if doc, ok := releases[rest]; ok {
				fmt.Fprint(w, doc)
				return
			}
		}
		if rest, ok := strings.CutPrefix(r.URL.Path, "/package/"); ok && pkgs[rest] {
			fmt.Fprint(w, `{"latest_version":"9.9.9"}`)
			return
		}
		http.NotFound(w, r)
	}))
	old := BaseURL
	BaseURL = srv.URL
	return func() { BaseURL = old; srv.Close() }
}

func bump(name, channel, from, to string) diffx.FileDiff {
	return diffx.FileDiff{Path: "pixi.lock", Changes: []diffx.Change{{
		Name: name, Ecosystem: "conda", Kind: diffx.Changed, Channel: channel,
		Old: []string{from}, New: []string{to},
	}}}
}

func uploadTS(age time.Duration) string {
	return time.Now().UTC().Add(-age).Format("2006-01-02 15:04:05.000000+00:00")
}

func relDoc(age time.Duration, license string, labels ...string) string {
	var dists []string
	for _, l := range labels {
		dists = append(dists, fmt.Sprintf(
			`{"upload_time":%q,"labels":[%s],"attrs":{"license":%q}}`,
			uploadTS(age), l, license))
	}
	return `{"distributions":[` + strings.Join(dists, ",") + `]}`
}

func TestAgesFreshAndLicenseChange(t *testing.T) {
	defer fakeAnaconda(t, map[string]string{
		"conda-forge/numpy/2.5.0": relDoc(400*24*time.Hour, "BSD-3-Clause", `"main"`, `"main"`),
		"conda-forge/numpy/2.5.1": relDoc(3*24*time.Hour, "GPL-3.0-only", `"main"`, `"main"`),
	}, nil)()
	diffs := []diffx.FileDiff{bump("numpy", "conda-forge", "2.5.0", "2.5.1")}
	checked, err := Annotate(diffs, 7)
	if err != nil || !checked {
		t.Fatalf("Annotate: checked=%v err=%v", checked, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 3 || !c.Fresh {
		t.Errorf("age=%d fresh=%v, want 3/true", c.AgeDays, c.Fresh)
	}
	if !c.LicenseChanged || c.OldLicense != "BSD-3-Clause" || c.NewLicense != "GPL-3.0-only" {
		t.Errorf("license change not detected: %+v", c)
	}
	if c.Deprecated || c.Unlisted {
		t.Errorf("unexpected flags: %+v", c)
	}
}

func TestBrokenLabels(t *testing.T) {
	defer fakeAnaconda(t, map[string]string{
		"conda-forge/smmap/5.0.2": relDoc(300*24*time.Hour, "BSD-3-Clause", `"main"`),
		"conda-forge/smmap/6.0.0": relDoc(30*24*time.Hour, "BSD-3-Clause", `"main","broken"`, `"main","broken"`),
		"conda-forge/part/1.0.0":  relDoc(300*24*time.Hour, "MIT", `"main"`),
		"conda-forge/part/2.0.0":  relDoc(30*24*time.Hour, "MIT", `"main","broken"`, `"main"`),
	}, nil)()
	diffs := []diffx.FileDiff{
		bump("smmap", "conda-forge", "5.0.2", "6.0.0"),
		bump("part", "conda-forge", "1.0.0", "2.0.0"),
	}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	all := diffs[0].Changes[0]
	if !all.Deprecated || !strings.Contains(all.DeprecatedReason, "marked broken on conda-forge") {
		t.Errorf("all-broken not flagged: %+v", all)
	}
	some := diffs[1].Changes[0]
	if !some.Deprecated || !strings.Contains(some.DeprecatedReason, "some builds marked broken") {
		t.Errorf("some-broken not flagged: %+v", some)
	}
}

func TestUnlistedNeedsExistenceProof(t *testing.T) {
	defer fakeAnaconda(t, map[string]string{
		"conda-forge/known/1.0.0": relDoc(300*24*time.Hour, "MIT", `"main"`),
	}, map[string]bool{"conda-forge/headonly": true})()
	diffs := []diffx.FileDiff{
		bump("known", "conda-forge", "1.0.0", "9.9.9"),    // sibling proves existence
		bump("headonly", "conda-forge", "0.1.0", "9.9.9"), // HEAD proves existence
		bump("ghost", "conda-forge", "0.1.0", "9.9.9"),    // package unknown entirely
	}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "9.9.9" {
		t.Errorf("sibling-proved unlisted not flagged: %+v", c)
	}
	if c := diffs[1].Changes[0]; !c.Unlisted {
		t.Errorf("HEAD-proved unlisted not flagged: %+v", c)
	}
	if c := diffs[2].Changes[0]; c.Unlisted {
		t.Errorf("unknown package must not be flagged: %+v", c)
	}
}

func TestSkipsNonRegistryAndChannelless(t *testing.T) {
	defer fakeAnaconda(t, nil, nil)()
	diffs := []diffx.FileDiff{{Path: "pixi.lock", Changes: []diffx.Change{
		{Name: "local", Ecosystem: "conda", Kind: diffx.Changed, Channel: "conda-forge",
			Old: []string{"1.0"}, New: []string{"2.0"}, NonRegistry: true},
		{Name: "defaults-pkg", Ecosystem: "conda", Kind: diffx.Changed,
			Old: []string{"1.0"}, New: []string{"2.0"}},
		{Name: "wheel", Ecosystem: "PyPI", Kind: diffx.Changed, Channel: "conda-forge",
			Old: []string{"1.0"}, New: []string{"2.0"}},
	}}}
	checked, err := Annotate(diffs, 7)
	if err != nil {
		t.Fatal(err)
	}
	if checked {
		t.Error("nothing eligible, checked must be false")
	}
	for _, c := range diffs[0].Changes {
		if c.Unlisted || c.Deprecated || c.AgeDays != 0 {
			t.Errorf("skipped change got annotated: %+v", c)
		}
	}
}

func TestLatest(t *testing.T) {
	defer fakeAnaconda(t, nil, map[string]bool{"bioconda/samtools": true})()
	v, err := Latest("bioconda", "samtools")
	if err != nil || v != "9.9.9" {
		t.Fatalf("Latest = %q, %v", v, err)
	}
	if _, err := Latest("conda-forge", "nope"); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing package error = %v", err)
	}
}
