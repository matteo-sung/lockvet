package helmreg

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// testIndex mimics `helm repo index` output: entries keyed by chart,
// releases as list items, nested annotations/maintainers blocks,
// sigs.k8s.io/yaml-style lists at field indent.
const testIndex = `apiVersion: v1
entries:
  postgresql:
  - annotations:
      category: Database
    apiVersion: v2
    appVersion: 16.2.0
    created: "2026-08-01T10:00:00Z"
    description: PostgreSQL chart
    home: https://bitnami.com
    maintainers:
    - name: Bitnami
      url: https://github.com/bitnami
    name: postgresql
    sources:
    - https://github.com/example/charts/tree/main/example/postgresql
    urls:
    - https://charts.example.com/postgresql-15.2.0.tgz
    version: 15.2.0
  - apiVersion: v2
    created: "2024-01-05T10:00:00Z"
    name: postgresql
    sources:
    - https://github.com/example/charts/tree/main/example/postgresql
    version: 12.0.0
  oldchart:
  - apiVersion: v2
    created: "2020-02-02T00:00:00Z"
    deprecated: true
    description: DEPRECATED old chart
    name: oldchart
    version: 2.0.0
  - apiVersion: v2
    created: "2019-02-02T00:00:00Z"
    name: oldchart
    version: 1.0.0
generated: "2026-08-08T00:00:00Z"
`

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/index.yaml" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(testIndex))
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

func oneChange(repo string, c diffx.Change) []diffx.FileDiff {
	c.Ecosystem = "Helm"
	c.Channel = repo
	return []diffx.FileDiff{{Path: "Chart.lock", Changes: []diffx.Change{c}}}
}

func TestAgesDeprecationSourceRepo(t *testing.T) {
	srv := testServer(t)
	pinClock(t, "2026-08-08T00:00:00Z")

	diffs := oneChange(srv.URL, diffx.Change{
		Name: "postgresql", Old: []string{"12.0.0"}, New: []string{"15.2.0"},
	})
	ok, err := Annotate(diffs, 14)
	if err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	c := diffs[0].Changes[0]
	if c.PublishedAt != "2026-08-01T10:00:00Z" {
		t.Errorf("PublishedAt = %q", c.PublishedAt)
	}
	if c.AgeDays != 6 || !c.Fresh {
		t.Errorf("AgeDays/Fresh = %d/%v, want 6/true", c.AgeDays, c.Fresh)
	}
	if c.SourceRepo != "https://github.com/example/charts" {
		t.Errorf("SourceRepo = %q (want monorepo /tree suffix stripped)", c.SourceRepo)
	}
	if c.Deprecated || c.Unlisted {
		t.Errorf("unexpected flags: deprecated=%v unlisted=%v", c.Deprecated, c.Unlisted)
	}
}

func TestDeprecatedChart(t *testing.T) {
	srv := testServer(t)
	pinClock(t, "2026-08-08T00:00:00Z")

	// Bump ONTO the deprecated release: direct wording.
	diffs := oneChange(srv.URL, diffx.Change{
		Name: "oldchart", Old: []string{"1.0.0"}, New: []string{"2.0.0"},
	})
	if ok, err := Annotate(diffs, 0); err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated || c.DeprecatedReason == "" {
		t.Fatalf("want deprecated, got %+v", c)
	}

	// Bump onto an old, non-deprecated release of a chart whose latest
	// IS deprecated: worded apart.
	diffs = oneChange(srv.URL, diffx.Change{
		Name: "oldchart", New: []string{"1.0.0"},
	})
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	c = diffs[0].Changes[0]
	if !c.Deprecated || c.DeprecatedReason == "" {
		t.Fatalf("want latest-deprecated wording, got %+v", c)
	}
}

func TestUnlistedWithPruneGuard(t *testing.T) {
	srv := testServer(t)
	pinClock(t, "2026-08-08T00:00:00Z")

	// Missing version ABOVE the oldest listed release: flags.
	diffs := oneChange(srv.URL, diffx.Change{
		Name: "postgresql", New: []string{"14.9.9"},
	})
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; !c.Unlisted || len(c.UnlistedVersions) != 1 {
		t.Fatalf("want unlisted 14.9.9, got %+v", c)
	}

	// Missing version BELOW the oldest listed release: pruning is
	// routine, no claims.
	diffs = oneChange(srv.URL, diffx.Change{
		Name: "postgresql", New: []string{"5.0.0"},
	})
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; c.Unlisted {
		t.Fatalf("pruned-range version must not flag, got %+v", c)
	}

	// Chart unknown to the index entirely: no claims.
	diffs = oneChange(srv.URL, diffx.Change{
		Name: "ghost", New: []string{"1.0.0"},
	})
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; c.Unlisted {
		t.Fatalf("unknown chart must not flag, got %+v", c)
	}
}

func TestSkipsNonHTTPAndNonHelm(t *testing.T) {
	diffs := []diffx.FileDiff{{Path: "Chart.lock", Changes: []diffx.Change{
		{Name: "a", Ecosystem: "Helm", Channel: "", New: []string{"1.0.0"}},
		{Name: "b", Ecosystem: "npm", Channel: "https://x", New: []string{"1.0.0"}},
	}}}
	ok, err := Annotate(diffs, 0)
	if err != nil || ok {
		t.Fatalf("expected no-op, got %v, %v", ok, err)
	}
}

func TestTotalFailureReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	diffs := oneChange(srv.URL, diffx.Change{Name: "x", New: []string{"1.0.0"}})
	if ok, err := Annotate(diffs, 0); err == nil || ok {
		t.Fatalf("want total-failure error, got %v, %v", ok, err)
	}
}

func TestParseIndexShapes(t *testing.T) {
	charts := parseIndex([]byte(testIndex), map[string]bool{"postgresql": true, "oldchart": true})
	if len(charts["postgresql"]) != 2 || len(charts["oldchart"]) != 2 {
		t.Fatalf("parse counts: %d/%d", len(charts["postgresql"]), len(charts["oldchart"]))
	}
	e := charts["postgresql"][0]
	if e.version != "15.2.0" || e.created != "2026-08-01T10:00:00Z" || e.deprecated {
		t.Errorf("entry = %+v", e)
	}
	if len(e.sources) != 1 || e.sources[0] != "https://github.com/example/charts/tree/main/example/postgresql" {
		t.Errorf("sources = %v", e.sources)
	}
	// maintainers' url: line must not leak into sources.
	for _, s := range e.sources {
		if s == "https://github.com/bitnami" {
			t.Error("maintainer URL leaked into sources")
		}
	}
	if !charts["oldchart"][0].deprecated {
		t.Error("deprecated not parsed")
	}
}

func TestForgeRepo(t *testing.T) {
	cases := map[string]string{
		"https://github.com/foo/bar":                   "https://github.com/foo/bar",
		"https://github.com/foo/bar.git":               "https://github.com/foo/bar",
		"https://github.com/foo/bar/tree/main/sub/pkg": "https://github.com/foo/bar",
		"https://gitlab.com/g/sub":                     "https://gitlab.com/g/sub",
		"https://prometheus.io":                        "",
		"https://example.com/foo/bar":                  "",
		"http://github.com/foo/bar":                    "",
		"https://github.com/onlyowner":                 "",
	}
	for in, want := range cases {
		if got := forgeRepo(in); got != want {
			t.Errorf("forgeRepo(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRegeneratedIndexClaimsNoAges(t *testing.T) {
	// Some repositories rebuild index.yaml from scratch and stamp every
	// entry with the generation time (app.getambassador.io): two
	// different versions sharing one exact created timestamp proves the
	// timestamps are generation artifacts — no age claims.
	idx := `apiVersion: v1
entries:
  gateway:
  - apiVersion: v2
    created: "2026-08-08T20:04:31.46711177Z"
    name: gateway
    version: 8.4.0
  - apiVersion: v2
    created: "2026-08-08T20:04:31.487201332Z"
    name: gateway
    version: 8.3.0
  - apiVersion: v2
    created: "2026-08-08T20:04:31.502994810Z"
    name: gateway
    version: 8.2.0
generated: "2026-08-08T20:04:32Z"
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(idx))
	}))
	defer srv.Close()
	pinClock(t, "2026-08-08T22:00:00Z")

	diffs := oneChange(srv.URL, diffx.Change{
		Name: "gateway", Old: []string{"8.3.0"}, New: []string{"8.4.0"},
	})
	ok, err := Annotate(diffs, 14)
	if err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	c := diffs[0].Changes[0]
	if c.PublishedAt != "" || c.AgeDays != 0 || c.Fresh {
		t.Errorf("age claimed from regenerated index: published=%q age=%d fresh=%v",
			c.PublishedAt, c.AgeDays, c.Fresh)
	}
	if c.Unlisted {
		t.Errorf("unlisted flagged unexpectedly")
	}
}

func TestOneTimeRegeneratedIndexKeepsRealAges(t *testing.T) {
	// kyverno shape: a one-time index rebuild stamped years of history
	// with one instant, but releases cut after it carry real publish
	// times. Cluster versions claim no age; later versions keep theirs.
	idx := `apiVersion: v1
entries:
  policy:
  - apiVersion: v2
    created: "2026-08-03T12:00:00.100Z"
    name: policy
    version: 3.5.0
  - apiVersion: v2
    created: "2026-06-21T16:33:27.415077384Z"
    name: policy
    version: 3.0.5
  - apiVersion: v2
    created: "2026-06-21T16:33:27.284295016Z"
    name: policy
    version: 2.6.5
  - apiVersion: v2
    created: "2026-06-21T16:33:27.183387012Z"
    name: policy
    version: 2.0.0
generated: "2026-08-08T00:00:00Z"
`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(idx))
	}))
	defer srv.Close()
	pinClock(t, "2026-08-08T12:00:00Z")

	// Bump onto a cluster version: no age claim.
	diffs := oneChange(srv.URL, diffx.Change{
		Name: "policy", Old: []string{"2.6.5"}, New: []string{"3.0.5"},
	})
	if ok, err := Annotate(diffs, 14); err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	if c := diffs[0].Changes[0]; c.PublishedAt != "" || c.Fresh {
		t.Errorf("cluster version claimed age: published=%q fresh=%v", c.PublishedAt, c.Fresh)
	}

	// Bump onto a post-rebuild version: the real timestamp stands.
	diffs = oneChange(srv.URL, diffx.Change{
		Name: "policy", Old: []string{"3.0.5"}, New: []string{"3.5.0"},
	})
	if ok, err := Annotate(diffs, 14); err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	if c := diffs[0].Changes[0]; c.AgeDays != 4 || !c.Fresh {
		t.Errorf("real timestamp lost: age=%d fresh=%v published=%q", c.AgeDays, c.Fresh, c.PublishedAt)
	}
}
