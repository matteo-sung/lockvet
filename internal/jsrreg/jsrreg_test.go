package jsrreg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// fakeJSR serves /@scope/name/meta.json from metas and
// /api/scopes/scope/packages/name from pkgs. Missing names 404.
func fakeJSR(t *testing.T, metas, pkgs map[string]string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rest, ok := strings.CutPrefix(r.URL.Path, "/api/scopes/"); ok {
			scope, name, _ := strings.Cut(rest, "/packages/")
			if doc, ok := pkgs["@"+scope+"/"+name]; ok {
				fmt.Fprint(w, doc)
				return
			}
			http.NotFound(w, r)
			return
		}
		if name, ok := strings.CutSuffix(r.URL.Path, "/meta.json"); ok {
			if doc, ok := metas[strings.TrimPrefix(name, "/")]; ok {
				fmt.Fprint(w, doc)
				return
			}
		}
		http.NotFound(w, r)
	}))
	oldB, oldA := BaseURL, APIBaseURL
	BaseURL, APIBaseURL = srv.URL, srv.URL
	return func() { BaseURL, APIBaseURL = oldB, oldA; srv.Close() }
}

func bump(name, from, to string) diffx.FileDiff {
	return diffx.FileDiff{Path: "deno.lock", Changes: []diffx.Change{{
		Name: name, Ecosystem: "npm", Kind: diffx.Changed,
		Old: []string{from}, New: []string{to},
	}}}
}

func ts(age time.Duration) string {
	return time.Now().UTC().Add(-age).Format("2006-01-02T15:04:05.000000Z")
}

func TestAgesFreshYankedAndSource(t *testing.T) {
	defer fakeJSR(t,
		map[string]string{
			"@std/path": fmt.Sprintf(
				`{"scope":"std","name":"path","latest":"1.1.6","versions":{"1.1.6":{"createdAt":%q},"1.1.0":{"createdAt":%q},"1.0.9":{"yanked":true,"createdAt":%q}}}`,
				ts(2*24*time.Hour), ts(300*24*time.Hour), ts(200*24*time.Hour)),
		},
		map[string]string{
			"@std/path": `{"scope":"std","name":"path","isArchived":false,"githubRepository":{"owner":"denoland","name":"std"}}`,
		},
	)()

	diffs := []diffx.FileDiff{bump("jsr:@std/path", "1.1.0", "1.1.6")}
	checked, err := Annotate(diffs, 7)
	if err != nil || !checked {
		t.Fatalf("Annotate: checked=%v err=%v", checked, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 2 || !c.Fresh {
		t.Errorf("age/fresh = %d/%v, want 2/true", c.AgeDays, c.Fresh)
	}
	if c.SourceRepo != "https://github.com/denoland/std" {
		t.Errorf("SourceRepo = %q", c.SourceRepo)
	}
	if c.Deprecated || c.Unlisted {
		t.Errorf("unexpected flags: deprecated=%v unlisted=%v", c.Deprecated, c.Unlisted)
	}

	// Bump onto the yanked version → deprecation lane.
	diffs = []diffx.FileDiff{bump("jsr:@std/path", "1.1.0", "1.0.9")}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c = diffs[0].Changes[0]
	if !c.Deprecated || !strings.Contains(c.DeprecatedReason, "yanked") {
		t.Errorf("yanked bump: deprecated=%v reason=%q", c.Deprecated, c.DeprecatedReason)
	}
	if c.Unlisted {
		t.Error("yanked version must not be unlisted (it stays in meta.json)")
	}
}

func TestUnlistedArchivedAndUnknown(t *testing.T) {
	defer fakeJSR(t,
		map[string]string{
			"@old/thing": fmt.Sprintf(`{"versions":{"1.0.0":{"createdAt":%q}}}`, ts(400*24*time.Hour)),
		},
		map[string]string{
			"@old/thing": `{"isArchived":true}`,
		},
	)()

	// Incoming version absent from meta.json → unlisted; archived → deprecated.
	diffs := []diffx.FileDiff{bump("jsr:@old/thing", "1.0.0", "1.0.1")}
	checked, err := Annotate(diffs, 7)
	if err != nil || !checked {
		t.Fatalf("Annotate: checked=%v err=%v", checked, err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "1.0.1" {
		t.Errorf("unlisted = %v %v", c.Unlisted, c.UnlistedVersions)
	}
	if !c.Deprecated || !strings.Contains(c.DeprecatedReason, "archived") {
		t.Errorf("archived: deprecated=%v reason=%q", c.Deprecated, c.DeprecatedReason)
	}

	// Package jsr.io does not know at all → nothing flagged, not checked.
	diffs = []diffx.FileDiff{bump("jsr:@no/such", "1.0.0", "1.0.1")}
	checked, err = Annotate(diffs, 7)
	if err != nil {
		t.Fatal(err)
	}
	if checked {
		t.Error("unknown package must not count as checked")
	}
	if c := diffs[0].Changes[0]; c.Unlisted || c.Deprecated {
		t.Errorf("unknown package flagged: %+v", c)
	}

	// Plain npm changes and NonRegistry entries are ignored entirely.
	diffs = []diffx.FileDiff{bump("chalk", "5.3.0", "5.4.0")}
	if checked, _ := Annotate(diffs, 7); checked {
		t.Error("plain npm change must be ignored")
	}
	nr := bump("jsr:@old/thing", "1.0.0", "1.0.1")
	nr.Changes[0].NonRegistry = true
	if checked, _ := Annotate([]diffx.FileDiff{nr}, 7); checked {
		t.Error("NonRegistry change must be ignored")
	}
}

func TestSplitName(t *testing.T) {
	cases := []struct {
		in, scope, name string
		ok              bool
	}{
		{"jsr:@std/path", "std", "path", true},
		{"jsr:@a/b", "a", "b", true},
		{"jsr:std/path", "", "", false},
		{"jsr:@std", "", "", false},
		{"jsr:@std/a/b", "", "", false},
		{"@std/path", "", "", false},
	}
	for _, tc := range cases {
		scope, name, ok := splitName(tc.in)
		if scope != tc.scope || name != tc.name || ok != tc.ok {
			t.Errorf("splitName(%q) = %q %q %v, want %q %q %v", tc.in, scope, name, ok, tc.scope, tc.name, tc.ok)
		}
	}
}
