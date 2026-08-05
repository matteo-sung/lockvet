package pypireg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// fakePyPI serves canned simple-API JSON documents by normalized name.
func fakePyPI(t *testing.T, docs map[string]string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for name, doc := range docs {
			if r.URL.Path == "/"+name+"/" {
				w.Header().Set("Content-Type", "application/vnd.pypi.simple.v1+json")
				fmt.Fprint(w, doc)
				return
			}
		}
		http.NotFound(w, r)
	}))
	old := SimpleURL
	SimpleURL = srv.URL
	return func() { SimpleURL = old; srv.Close() }
}

func file(version, kind string, attested bool, extra string) string {
	prov := "null"
	if attested {
		prov = fmt.Sprintf(`"https://pypi.org/integrity/x/%s/f/provenance"`, version)
	}
	name := "pkg-" + version + ".tar.gz"
	if kind == "whl" {
		name = "pkg-" + version + "-py3-none-any.whl"
	}
	if extra != "" {
		extra = "," + extra
	}
	return fmt.Sprintf(`{"filename":%q,"provenance":%s,"upload-time":%q%s}`,
		name, prov, time.Now().UTC().Add(-24*time.Hour).Format(time.RFC3339), extra)
}

func bump(name, from, to string) diffx.FileDiff {
	return diffx.FileDiff{Path: "uv.lock", Changes: []diffx.Change{{
		Name: name, Ecosystem: "PyPI", Kind: diffx.Changed,
		Old: []string{from}, New: []string{to},
	}}}
}

func TestProvenanceDropFlagged(t *testing.T) {
	defer fakePyPI(t, map[string]string{"pkg": `{
		"versions":["1.0.0","1.1.0","1.2.0","2.0.0"],
		"files":[` + file("1.0.0", "whl", true, "") + `,` + file("1.1.0", "whl", true, "") + `,` +
		file("1.2.0", "whl", true, "") + `,` + file("2.0.0", "whl", false, "") + `],
		"project-status":{"status":"active"}}`})()
	diffs := []diffx.FileDiff{bump("pkg", "1.2.0", "2.0.0")}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.ProvenanceDropped || len(c.UnattestedVersions) != 1 || c.UnattestedVersions[0] != "2.0.0" {
		t.Fatalf("want provenance drop on 2.0.0, got %+v", c)
	}
}

func TestNoPracticeNoFlag(t *testing.T) {
	// Only the outgoing version attested — one-off adopter, stay quiet.
	defer fakePyPI(t, map[string]string{"pkg": `{
		"versions":["1.0.0","1.1.0","1.2.0","2.0.0"],
		"files":[` + file("1.0.0", "whl", false, "") + `,` + file("1.1.0", "whl", false, "") + `,` +
		file("1.2.0", "whl", true, "") + `,` + file("2.0.0", "whl", false, "") + `],
		"project-status":{"status":"active"}}`})()
	diffs := []diffx.FileDiff{bump("pkg", "1.2.0", "2.0.0")}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].ProvenanceDropped {
		t.Fatalf("one-off adopter must not flag: %+v", diffs[0].Changes[0])
	}
}

func TestMixedAttestationIncomingNotFlagged(t *testing.T) {
	// Incoming version has one attested and one unattested file: mixed
	// publishing setup, not a stolen-token signature.
	docs := map[string]string{"pkg": `{
		"versions":["1.0.0","1.1.0","1.2.0","2.0.0"],
		"files":[` + file("1.0.0", "whl", true, "") + `,` + file("1.1.0", "whl", true, "") + `,` +
		file("1.2.0", "whl", true, "") + `,` + file("2.0.0", "whl", true, "") + `,` +
		file("2.0.0", "sdist", false, "") + `],
		"project-status":{"status":"active"}}`}
	defer fakePyPI(t, docs)()
	diffs := []diffx.FileDiff{bump("pkg", "1.2.0", "2.0.0")}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].ProvenanceDropped {
		t.Fatalf("mixed attestation must not flag: %+v", diffs[0].Changes[0])
	}
}

func TestOldAgeGateSilences(t *testing.T) {
	docs := map[string]string{"pkg": fmt.Sprintf(`{
		"versions":["1.0.0","1.1.0","1.2.0","2.0.0"],
		"files":[%s,%s,%s,
			{"filename":"pkg-2.0.0-py3-none-any.whl","provenance":null,"upload-time":%q}],
		"project-status":{"status":"active"}}`,
		file("1.0.0", "whl", true, ""), file("1.1.0", "whl", true, ""), file("1.2.0", "whl", true, ""),
		time.Now().UTC().Add(-90*24*time.Hour).Format(time.RFC3339))}
	defer fakePyPI(t, docs)()
	diffs := []diffx.FileDiff{bump("pkg", "1.2.0", "2.0.0")}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].ProvenanceDropped {
		t.Fatalf("90-day-old release must not flag: %+v", diffs[0].Changes[0])
	}
}

func TestPrereleasesExcludedFromPractice(t *testing.T) {
	// The three versions below 2.0.0 include prereleases that never
	// attested; the stable line did. Practice = stable line only.
	docs := map[string]string{"pkg": `{
		"versions":["1.1.0","1.2.0","2.0.0a1","2.0.0rc1","2.0.0.dev1","2.0.0"],
		"files":[` + file("1.1.0", "whl", true, "") + `,` + file("1.2.0", "whl", true, "") + `,` +
		file("2.0.0a1", "whl", false, "") + `,` + file("2.0.0rc1", "whl", false, "") + `,` +
		file("2.0.0.dev1", "whl", false, "") + `,` + file("2.0.0", "whl", false, "") + `],
		"project-status":{"status":"active"}}`}
	defer fakePyPI(t, docs)()
	diffs := []diffx.FileDiff{bump("pkg", "1.2.0", "2.0.0")}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if !diffs[0].Changes[0].ProvenanceDropped {
		t.Fatalf("prerelease gaps must not break stable practice: %+v", diffs[0].Changes[0])
	}
}

func TestUnlistedVerification(t *testing.T) {
	defer fakePyPI(t, map[string]string{"pkg": `{
		"versions":["1.0.0","1.1.0"],
		"files":[` + file("1.0.0", "whl", false, "") + `,` + file("1.1.0", "whl", false, "") + `],
		"project-status":{"status":"active"}}`})()
	diffs := []diffx.FileDiff{{Path: "uv.lock", Changes: []diffx.Change{
		{Name: "pkg", Ecosystem: "PyPI", Kind: diffx.Changed, Old: []string{"1.0.0"}, New: []string{"1.1.0"},
			Unlisted: true, UnlistedVersions: []string{"1.1.0"}}, // deps.dev lag: PyPI has it
		{Name: "pkg", Ecosystem: "PyPI", Kind: diffx.Changed, Old: []string{"1.0.0"}, New: []string{"6.6.6"},
			Unlisted: true, UnlistedVersions: []string{"6.6.6"}}, // truly gone
	}}}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Unlisted {
		t.Fatalf("version PyPI serves must lose the unlisted flag: %+v", diffs[0].Changes[0])
	}
	if !diffs[0].Changes[1].Unlisted {
		t.Fatalf("version PyPI lacks must keep the unlisted flag: %+v", diffs[0].Changes[1])
	}
}

func TestYankedIncoming(t *testing.T) {
	docs := map[string]string{"pkg": `{
		"versions":["1.0.0","1.1.0"],
		"files":[` + file("1.0.0", "whl", false, "") + `,` +
		file("1.1.0", "whl", false, `"yanked":"broke everything"`) + `],
		"project-status":{"status":"active"}}`}
	defer fakePyPI(t, docs)()
	diffs := []diffx.FileDiff{bump("pkg", "1.0.0", "1.1.0")}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated || c.DeprecatedReason != "version 1.1.0 was yanked on PyPI: broke everything" {
		t.Fatalf("yanked incoming must surface as deprecation, got %+v", c)
	}
}

func TestQuarantinedAndArchivedStatus(t *testing.T) {
	docs := map[string]string{
		"quarantined-pkg": `{"versions":["1.0.0"],"files":[` +
			file("1.0.0", "whl", false, "") + `],"project-status":{"status":"quarantined"}}`,
		"archived-pkg": `{"versions":["1.0.0"],"files":[` +
			file("1.0.0", "whl", false, "") + `],"project-status":{"status":"archived"}}`,
	}
	defer fakePyPI(t, docs)()
	diffs := []diffx.FileDiff{{Path: "uv.lock", Changes: []diffx.Change{
		{Name: "quarantined_pkg", Ecosystem: "PyPI", Kind: diffx.Added, New: []string{"1.0.0"}},
		{Name: "Archived.pkg", Ecosystem: "PyPI", Kind: diffx.Added, New: []string{"1.0.0"}},
	}}}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if r := diffs[0].Changes[0].DeprecatedReason; r != "quarantined by PyPI (under malware review; not installable)" {
		t.Fatalf("quarantined reason wrong: %q", r)
	}
	if r := diffs[0].Changes[1].DeprecatedReason; r != "project archived on PyPI (no further releases expected)" {
		t.Fatalf("archived reason wrong (name normalization?): %q", r)
	}
}

func TestDepsDevReasonNotOverwritten(t *testing.T) {
	docs := map[string]string{"pkg": `{"versions":["1.0.0"],"files":[` +
		file("1.0.0", "whl", false, "") + `],"project-status":{"status":"archived"}}`}
	defer fakePyPI(t, docs)()
	diffs := []diffx.FileDiff{{Path: "uv.lock", Changes: []diffx.Change{
		{Name: "pkg", Ecosystem: "PyPI", Kind: diffx.Added, New: []string{"1.0.0"},
			Deprecated: true, DeprecatedReason: "upstream says so"},
	}}}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	if r := diffs[0].Changes[0].DeprecatedReason; r != "upstream says so" {
		t.Fatalf("deps.dev reason must win: %q", r)
	}
}

func TestNonRegistryAndOtherEcosystemsSkipped(t *testing.T) {
	defer fakePyPI(t, map[string]string{})() // any fetch would 404 loudly
	diffs := []diffx.FileDiff{{Path: "uv.lock", Changes: []diffx.Change{
		{Name: "local", Ecosystem: "PyPI", Kind: diffx.Changed, Old: []string{"1"}, New: []string{"2"}, NonRegistry: true},
		{Name: "left-pad", Ecosystem: "npm", Kind: diffx.Changed, Old: []string{"1"}, New: []string{"2"}},
	}}}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
}

func TestVersionOfFilenames(t *testing.T) {
	vs := map[string]bool{"2.8.2": true, "1.0": true, "1.0.1": true}
	cases := map[string]string{
		"python_dateutil-2.8.2-py2.py3-none-any.whl": "2.8.2",
		"python-dateutil-2.8.2.tar.gz":               "2.8.2", // old unnormalized sdist
		"pkg-1.0.tar.gz":                             "1.0",
		"pkg-1.0.1-py3-none-any.whl":                 "1.0.1",
		"unrelated-9.9.9.tar.gz":                     "",
	}
	for fn, want := range cases {
		if got := versionOf(fn, vs); got != want {
			t.Errorf("versionOf(%q) = %q, want %q", fn, got, want)
		}
	}
}

func TestIsPrerelease(t *testing.T) {
	pre := []string{"1.0a1", "1.0.0b2", "1.0rc1", "1.0.dev3", "2.0.0.dev0", "1.0.0-alpha.1", "1.2.0c1"}
	stable := []string{"1.0.0", "1.0.post1", "2.8.2", "1!2.0.0", "1.0.0+local.1", "0.21-8"}
	for _, v := range pre {
		if !isPrerelease(v) {
			t.Errorf("isPrerelease(%q) = false, want true", v)
		}
	}
	for _, v := range stable {
		if isPrerelease(v) {
			t.Errorf("isPrerelease(%q) = true, want false", v)
		}
	}
}
