package osv

import (
	"archive/zip"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }

func writeZip(t *testing.T, path string, records map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range records {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

const ghsaA = `{"id":"GHSA-aaaa","summary":"prototype pollution","aliases":["CVE-2020-1"],
 "database_specific":{"severity":"HIGH"},
 "affected":[{"package":{"name":"left-pad","ecosystem":"npm"},
   "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.2.0"}]}]}]}`

const malB = `{"id":"MAL-0001","summary":"malicious code",
 "affected":[{"package":{"name":"left-pad","ecosystem":"npm"},"versions":["9.9.9"]}]}`

const withdrawnC = `{"id":"GHSA-gone","withdrawn":"2024-01-01T00:00:00Z",
 "affected":[{"package":{"name":"left-pad","ecosystem":"npm"},
   "ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`

func TestLocalBatchAndDetails(t *testing.T) {
	dir := t.TempDir()
	writeZip(t, filepath.Join(dir, "npm", "all.zip"), map[string]string{
		"GHSA-aaaa.json": ghsaA, "MAL-0001.json": malB, "GHSA-gone.json": withdrawnC,
	})
	b := &localBackend{dir: dir, download: false}

	res, err := b.batch([]query{
		mkQuery("left-pad", "npm", "1.1.0"), // in GHSA range
		mkQuery("left-pad", "npm", "1.2.0"), // fixed
		mkQuery("left-pad", "npm", "9.9.9"), // versions-list hit
		mkQuery("other", "npm", "1.0.0"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 4 {
		t.Fatalf("got %d results", len(res))
	}
	if len(res[0].Vulns) != 1 || res[0].Vulns[0].ID != "GHSA-aaaa" {
		t.Errorf("q0: %+v", res[0])
	}
	if len(res[1].Vulns) != 0 {
		t.Errorf("fixed version still flagged: %+v", res[1])
	}
	if len(res[2].Vulns) != 1 || res[2].Vulns[0].ID != "MAL-0001" {
		t.Errorf("q2: %+v", res[2])
	}
	if len(res[3].Vulns) != 0 {
		t.Errorf("unknown package flagged: %+v", res[3])
	}

	det := b.details([]string{"GHSA-aaaa"})
	if d, ok := det["GHSA-aaaa"]; !ok || d.severity != "high" || d.summary != "prototype pollution" {
		t.Errorf("details: %+v", det)
	}

	// Index was persisted for next time.
	if _, err := os.Stat(filepath.Join(dir, "npm", "index.json.gz")); err != nil {
		t.Errorf("index not saved: %v", err)
	}
}

func TestLocalActionsStyleQuery(t *testing.T) {
	dir := t.TempDir()
	writeZip(t, filepath.Join(dir, "GitHub_Actions", "all.zip"), map[string]string{
		"GHSA-act.json": `{"id":"GHSA-act","summary":"cache poisoning",
		 "affected":[{"package":{"name":"acme/setup","ecosystem":"GitHub Actions"},
		   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.1"}]}]}]}`,
	})
	b := &localBackend{dir: dir}
	res, err := b.batch([]query{mkQuery("acme/setup", "GitHub Actions", "")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res[0].Vulns) != 1 || res[0].Vulns[0].ID != "GHSA-act" {
		t.Fatalf("package-level query: %+v", res[0])
	}
}

func TestLocalPyPINormalizationAndDistro(t *testing.T) {
	dir := t.TempDir()
	writeZip(t, filepath.Join(dir, "PyPI", "all.zip"), map[string]string{
		"PYSEC-1.json": `{"id":"PYSEC-1","summary":"x",
		 "affected":[{"package":{"name":"Foo_Bar","ecosystem":"PyPI"},
		   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0"}]}]}]}`,
	})
	writeZip(t, filepath.Join(dir, "Alpine_v3.19", "all.zip"), map[string]string{
		"CVE-1.json": `{"id":"CVE-1","summary":"y",
		 "affected":[{"package":{"name":"openssl","ecosystem":"Alpine:v3.18"},
		   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}]},
		  {"package":{"name":"openssl","ecosystem":"Alpine:v3.19"},
		   "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.1.4-r5"}]}]}]}`,
	})
	b := &localBackend{dir: dir}
	res, err := b.batch([]query{
		mkQuery("foo.bar", "PyPI", "1.0"),
		mkQuery("openssl", "Alpine:v3.19", "3.1.4-r5"), // fixed in v3.19's own entry
		mkQuery("openssl", "Alpine:v3.19", "3.1.4-r4"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res[0].Vulns) != 1 {
		t.Errorf("PyPI normalization miss: %+v", res[0])
	}
	if len(res[1].Vulns) != 0 {
		t.Errorf("fixed distro version flagged (wrong release's range?): %+v", res[1])
	}
	if len(res[2].Vulns) != 1 {
		t.Errorf("affected distro version missed: %+v", res[2])
	}
}

func TestLocalOfflineMissingEcosystem(t *testing.T) {
	b := &localBackend{dir: t.TempDir(), download: false}
	_, err := b.batch([]query{mkQuery("left-pad", "npm", "1.0.0")})
	if err == nil || !contains(err.Error(), "no local OSV database for npm") {
		t.Fatalf("want instructive error, got %v", err)
	}
}

func TestLocalDownloadAndConditionalGet(t *testing.T) {
	// One-record zip served with an ETag; second fetch must be a 304.
	zipPath := filepath.Join(t.TempDir(), "src.zip")
	writeZip(t, zipPath, map[string]string{"GHSA-aaaa.json": ghsaA})
	data, _ := os.ReadFile(zipPath)
	var hits, notMod int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/npm/all.zip" {
			http.NotFound(w, r)
			return
		}
		hits++
		if r.Header.Get("If-None-Match") == `"v1"` {
			notMod++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Write(data)
	}))
	defer srv.Close()
	old := gcsBase
	gcsBase = srv.URL + "/"
	defer func() { gcsBase = old }()

	dir := t.TempDir()
	b := &localBackend{dir: dir, download: true}
	res, err := b.batch([]query{mkQuery("left-pad", "npm", "1.0.0")})
	if err != nil || len(res[0].Vulns) != 1 {
		t.Fatalf("download run: %v %+v", err, res)
	}

	b2 := &localBackend{dir: dir, download: true}
	res, err = b2.batch([]query{mkQuery("left-pad", "npm", "1.0.0")})
	if err != nil || len(res[0].Vulns) != 1 {
		t.Fatalf("cached run: %v %+v", err, res)
	}
	if notMod != 1 {
		t.Errorf("second run should revalidate with If-None-Match (hits=%d notMod=%d)", hits, notMod)
	}

	// Unknown ecosystem: 404 upstream = empty database, not an error.
	res, err = b2.batch([]query{mkQuery("x", "Hex", "1.0.0")})
	if err != nil || len(res[0].Vulns) != 0 {
		t.Fatalf("404 ecosystem: %v %+v", err, res)
	}
}

func TestAffectsVersionEdges(t *testing.T) {
	aff := []affectedEntry{}
	mustDecode := func(s string) {
		t.Helper()
		v, err := decodeVulnDoc(stringsReader(s))
		if err != nil {
			t.Fatal(err)
		}
		aff = v.affected
	}
	mustDecode(`{"affected":[{"package":{"name":"p","ecosystem":"crates.io"},
	  "ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"last_affected":"1.5.0"}]}]}]}`)
	for v, want := range map[string]bool{"0.9.0": false, "1.0.0": true, "1.5.0": true, "1.5.1": false} {
		if got := affectsVersion(aff, "p", "crates.io", v); got != want {
			t.Errorf("last_affected %s: got %v", v, got)
		}
	}
	mustDecode(`{"affected":[{"package":{"name":"p","ecosystem":"crates.io"},
	  "ranges":[{"type":"SEMVER","events":[{"introduced":"2.0.0"}]}]}]}`)
	for v, want := range map[string]bool{"1.9.9": false, "2.0.0": true, "99.0.0": true} {
		if got := affectsVersion(aff, "p", "crates.io", v); got != want {
			t.Errorf("open-ended %s: got %v", v, got)
		}
	}
	// GIT ranges alone never match a version pin.
	mustDecode(`{"affected":[{"package":{"name":"p","ecosystem":"crates.io"},
	  "ranges":[{"type":"GIT","events":[{"introduced":"abc"},{"fixed":"def"}]}]}]}`)
	if affectsVersion(aff, "p", "crates.io", "1.0.0") {
		t.Error("GIT range matched a version pin")
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
