package cranreg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// fakeCRAN serves crandb documents under /{name}/all and a CRAN mirror
// whose tarball paths answer 200 for the given set. Missing names 404.
func fakeCRAN(t *testing.T, docs map[string]string, mirrorHas map[string]bool) func() {
	t.Helper()
	db := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if name, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/all"); ok {
			if doc, ok := docs[name]; ok {
				fmt.Fprint(w, doc)
				return
			}
		}
		http.NotFound(w, r)
	}))
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mirrorHas[r.URL.Path] {
			return // 200
		}
		http.NotFound(w, r)
	}))
	oldB, oldM := BaseURL, MirrorURL
	BaseURL, MirrorURL = db.URL, mirror.URL
	return func() { BaseURL, MirrorURL = oldB, oldM; db.Close(); mirror.Close() }
}

func bump(name, from, to string) diffx.FileDiff {
	return diffx.FileDiff{Path: "renv.lock", Changes: []diffx.Change{{
		Name: name, Ecosystem: "CRAN", Kind: diffx.Changed,
		Old: []string{from}, New: []string{to},
	}}}
}

func ts(age time.Duration) string {
	return time.Now().UTC().Add(-age).Format(time.RFC3339)
}

func TestAgesFreshLicenseAndSource(t *testing.T) {
	doc := fmt.Sprintf(`{"name":"dplyr","latest":"1.2.1","archived":false,
		"timeline":{"1.2.0":%q,"1.2.1":%q},
		"versions":{
		  "1.2.0":{"License":"MIT + file LICENSE","URL":"https://dplyr.tidyverse.org, https://github.com/tidyverse/dplyr"},
		  "1.2.1":{"License":"GPL (>= 2)","URL":"https://dplyr.tidyverse.org, https://github.com/tidyverse/dplyr"}}}`,
		ts(400*24*time.Hour), ts(3*24*time.Hour))
	defer fakeCRAN(t, map[string]string{"dplyr": doc}, nil)()
	diffs := []diffx.FileDiff{bump("dplyr", "1.2.0", "1.2.1")}
	checked, err := Annotate(diffs, 7)
	if err != nil || !checked {
		t.Fatalf("Annotate: checked=%v err=%v", checked, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 3 || !c.Fresh {
		t.Errorf("age/fresh = %d/%v, want 3/true", c.AgeDays, c.Fresh)
	}
	if c.SourceRepo != "https://github.com/tidyverse/dplyr" {
		t.Errorf("SourceRepo = %q", c.SourceRepo)
	}
	if !c.LicenseChanged || c.OldLicense != "MIT + file LICENSE" || c.NewLicense != "GPL (>= 2)" {
		t.Errorf("license change not caught: %+v", c)
	}
	if c.Unlisted || c.Deprecated {
		t.Errorf("healthy bump flagged: unlisted=%v deprecated=%v", c.Unlisted, c.Deprecated)
	}
}

func TestArchivedPackage(t *testing.T) {
	doc := `{"name":"rgdal","latest":"1.6-7","archived":true,
		"timeline":{"1.6-6":"2023-01-01T00:00:00+00:00","1.6-7":"2023-05-31T00:00:00+00:00"},
		"versions":{"1.6-7":{"License":"GPL (>= 2)"}}}`
	defer fakeCRAN(t, map[string]string{"rgdal": doc}, nil)()
	diffs := []diffx.FileDiff{bump("rgdal", "1.6-6", "1.6-7")}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated || !strings.Contains(c.DeprecatedReason, "archived on CRAN") {
		t.Errorf("archived package not in deprecation lane: %+v", c)
	}
	// Removal of an archived package stays quiet.
	diffs = []diffx.FileDiff{{Path: "renv.lock", Changes: []diffx.Change{{
		Name: "rgdal", Ecosystem: "CRAN", Kind: diffx.Removed, Old: []string{"1.6-7"},
	}}}}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Deprecated {
		t.Errorf("removal flagged deprecated")
	}
}

func TestUnlistedDoubleCheckedAgainstMirror(t *testing.T) {
	doc := `{"name":"pkgA","latest":"1.0","archived":false,
		"timeline":{"1.0":"2020-01-01T00:00:00+00:00"},
		"versions":{"1.0":{"License":"MIT"}}}`
	// Version 9.9 absent from crandb AND the mirror: flags.
	defer fakeCRAN(t, map[string]string{"pkgA": doc}, nil)()
	diffs := []diffx.FileDiff{bump("pkgA", "1.0", "9.9")}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "9.9" {
		t.Errorf("missing version not flagged: %+v", c)
	}
}

func TestMirrorLagClearsUnlisted(t *testing.T) {
	doc := `{"name":"pkgB","latest":"1.0","archived":false,
		"timeline":{"1.0":"2020-01-01T00:00:00+00:00"},
		"versions":{"1.0":{"License":"MIT"}}}`
	// crandb lacks 1.1 but CRAN itself serves the tarball: no claim.
	defer fakeCRAN(t, map[string]string{"pkgB": doc},
		map[string]bool{"/src/contrib/pkgB_1.1.tar.gz": true})()
	diffs := []diffx.FileDiff{bump("pkgB", "1.0", "1.1")}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Unlisted {
		t.Errorf("mirror-lag version flagged unlisted")
	}
	// Same for a version only in the Archive.
	defer fakeCRAN(t, map[string]string{"pkgB": doc},
		map[string]bool{"/src/contrib/Archive/pkgB/pkgB_0.9.tar.gz": true})()
	diffs = []diffx.FileDiff{bump("pkgB", "1.0", "0.9")}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Unlisted {
		t.Errorf("archived version flagged unlisted")
	}
}

func TestUnknownPackageAndNonRegistrySkipped(t *testing.T) {
	defer fakeCRAN(t, map[string]string{}, nil)()
	diffs := []diffx.FileDiff{bump("nosuchpkg", "1.0", "2.0")}
	checked, err := Annotate(diffs, 7)
	if err != nil {
		t.Fatal(err)
	}
	if checked {
		t.Errorf("unknown package counted as checked")
	}
	c := diffs[0].Changes[0]
	if c.Unlisted || c.Deprecated || c.AgeDays != 0 {
		t.Errorf("unknown package got claims: %+v", c)
	}
	// NonRegistry changes never reach the API at all.
	diffs = []diffx.FileDiff{{Path: "renv.lock", Changes: []diffx.Change{{
		Name: "devpkg", Ecosystem: "CRAN", Kind: diffx.Changed,
		Old: []string{"1.0.0"}, New: []string{"1.0.0.9000"}, NonRegistry: true,
	}}}}
	checked, err = Annotate(diffs, 7)
	if err != nil || checked {
		t.Fatalf("NonRegistry: checked=%v err=%v", checked, err)
	}
}

func TestBioconductorLeftAlone(t *testing.T) {
	defer fakeCRAN(t, map[string]string{}, nil)()
	diffs := []diffx.FileDiff{{Path: "renv.lock", Changes: []diffx.Change{{
		Name: "limma", Ecosystem: "Bioconductor", Kind: diffx.Changed,
		Old: []string{"3.56.0"}, New: []string{"3.58.1"},
	}}}}
	checked, err := Annotate(diffs, 7)
	if err != nil || checked {
		t.Fatalf("Bioconductor: checked=%v err=%v", checked, err)
	}
}

func TestLatest(t *testing.T) {
	doc := `{"name":"cli","latest":"3.6.3","archived":false,
		"timeline":{"3.6.3":"2024-06-21T00:00:00+00:00"},
		"versions":{"3.6.3":{"License":"MIT"}}}`
	defer fakeCRAN(t, map[string]string{"cli": doc}, nil)()
	v, err := Latest("cli")
	if err != nil || v != "3.6.3" {
		t.Fatalf("Latest = %q, %v", v, err)
	}
	if _, err := Latest("nope"); err == nil {
		t.Fatalf("Latest(nope) succeeded")
	}
}
