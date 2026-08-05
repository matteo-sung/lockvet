package npmreg

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// fakeRegistry serves abbreviated metadata docs keyed by package name.
// Each entry maps version -> hasInstallScript.
func fakeRegistry(t *testing.T, pkgs map[string]map[string]bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.npm.install-v1+json" {
			t.Errorf("missing abbreviated-metadata Accept header, got %q", r.Header.Get("Accept"))
		}
		name := r.URL.Path[1:]
		vs, ok := pkgs[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		type ver struct {
			HasInstallScript bool `json:"hasInstallScript,omitempty"`
		}
		doc := struct {
			Versions map[string]ver `json:"versions"`
		}{Versions: map[string]ver{}}
		for v, has := range vs {
			doc.Versions[v] = ver{HasInstallScript: has}
		}
		json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func change(name string, old, nu []string) diffx.Change {
	return diffx.Change{Name: name, Ecosystem: "npm", Kind: diffx.Upgraded, Old: old, New: nu}
}

func TestAnnotateScriptTransitions(t *testing.T) {
	srv := fakeRegistry(t, map[string]map[string]bool{
		"gains-scripts":  {"1.0.0": false, "2.0.0": true},
		"always-scripts": {"1.0.0": true, "2.0.0": true},
		"never-scripts":  {"1.0.0": false, "2.0.0": false},
		"drops-scripts":  {"1.0.0": true, "2.0.0": false},
		"old-unknown":    {"2.0.0": true},
		"pnpm-decorated": {"1.0.0": false, "2.0.0": true},
	})
	oldURL := RegistryURL
	RegistryURL = srv.URL
	defer func() { RegistryURL = oldURL }()

	diffs := []diffx.FileDiff{{Path: "package-lock.json", Changes: []diffx.Change{
		change("gains-scripts", []string{"1.0.0"}, []string{"2.0.0"}),
		change("always-scripts", []string{"1.0.0"}, []string{"2.0.0"}),
		change("never-scripts", []string{"1.0.0"}, []string{"2.0.0"}),
		change("drops-scripts", []string{"1.0.0"}, []string{"2.0.0"}),
		change("old-unknown", []string{"1.0.0"}, []string{"2.0.0"}),
		change("gone-from-registry", []string{"1.0.0"}, []string{"2.0.0"}),
		change("pnpm-decorated", []string{"1.0.0(react@18.2.0)"}, []string{"2.0.0(react@18.2.0)"}),
	}}}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	cs := diffs[0].Changes
	if !cs[0].ScriptsAdded || len(cs[0].ScriptedVersions) != 1 || cs[0].ScriptedVersions[0] != "2.0.0" {
		t.Errorf("gains-scripts: want flag [2.0.0], got %v %v", cs[0].ScriptsAdded, cs[0].ScriptedVersions)
	}
	for i, name := range []string{"", "always-scripts", "never-scripts", "drops-scripts", "old-unknown", "gone-from-registry"} {
		if i == 0 {
			continue
		}
		if cs[i].ScriptsAdded {
			t.Errorf("%s: unexpectedly flagged", name)
		}
	}
	if !cs[6].ScriptsAdded || cs[6].ScriptedVersions[0] != "2.0.0" {
		t.Errorf("pnpm-decorated: want flag on stripped version, got %v %v", cs[6].ScriptsAdded, cs[6].ScriptedVersions)
	}
}

func TestAnnotateSkips(t *testing.T) {
	// The server must never be hit: non-npm ecosystems, additions,
	// removals, non-registry and jsr: packages are all out of scope.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s", r.URL.Path)
	}))
	defer srv.Close()
	oldURL := RegistryURL
	RegistryURL = srv.URL
	defer func() { RegistryURL = oldURL }()

	nonReg := change("workspace-pkg", []string{"1.0.0"}, []string{"2.0.0"})
	nonReg.NonRegistry = true
	diffs := []diffx.FileDiff{{Path: "package-lock.json", Changes: []diffx.Change{
		{Name: "serde", Ecosystem: "crates.io", Kind: diffx.Upgraded, Old: []string{"1.0.0"}, New: []string{"1.1.0"}},
		{Name: "brand-new", Ecosystem: "npm", Kind: diffx.Added, New: []string{"1.0.0"}},
		{Name: "going-away", Ecosystem: "npm", Kind: diffx.Removed, Old: []string{"1.0.0"}},
		{Name: "jsr:@std/path", Ecosystem: "npm", Kind: diffx.Upgraded, Old: []string{"1.0.0"}, New: []string{"1.1.0"}},
		nonReg,
	}}}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	for _, c := range diffs[0].Changes {
		if c.ScriptsAdded {
			t.Errorf("%s: unexpectedly flagged", c.Name)
		}
	}
}

func TestAnnotateServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusTooManyRequests)
	}))
	defer srv.Close()
	oldURL := RegistryURL
	RegistryURL = srv.URL
	defer func() { RegistryURL = oldURL }()

	diffs := []diffx.FileDiff{{Path: "package-lock.json", Changes: []diffx.Change{
		change("anything", []string{"1.0.0"}, []string{"2.0.0"}),
	}}}
	if err := Annotate(diffs); err == nil {
		t.Fatal("want an error on HTTP 429")
	}
	if diffs[0].Changes[0].ScriptsAdded {
		t.Error("flagged despite server error")
	}
}

func TestAnnotateVerifiesUnlisted(t *testing.T) {
	srv := fakeRegistry(t, map[string]map[string]bool{
		"depsdev-lag":  {"1.0.0": false, "2.0.0": false}, // npm has it: clear
		"really-gone":  {"1.0.0": false},                 // npm lacks 2.0.0: keep
		"half-cleared": {"1.0.0": false, "2.0.0": false}, // one of two clears
	})
	oldURL := RegistryURL
	RegistryURL = srv.URL
	defer func() { RegistryURL = oldURL }()

	mk := func(name string, unlisted ...string) diffx.Change {
		c := change(name, []string{"1.0.0"}, []string{"2.0.0"})
		c.Unlisted = true
		c.UnlistedVersions = unlisted
		return c
	}
	wholePkgGone := mk("whole-pkg-gone", "2.0.0") // registry 404s: keep
	added := diffx.Change{Name: "depsdev-lag", Ecosystem: "npm", Kind: diffx.Added,
		New: []string{"2.0.0"}, Unlisted: true, UnlistedVersions: []string{"2.0.0"}}

	diffs := []diffx.FileDiff{{Path: "package-lock.json", Changes: []diffx.Change{
		mk("depsdev-lag", "2.0.0"),
		mk("really-gone", "2.0.0"),
		mk("half-cleared", "2.0.0", "3.0.0"),
		wholePkgGone,
		added,
	}}}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}
	cs := diffs[0].Changes
	if cs[0].Unlisted || len(cs[0].UnlistedVersions) != 0 {
		t.Errorf("depsdev-lag: flag should clear, got %v %v", cs[0].Unlisted, cs[0].UnlistedVersions)
	}
	if !cs[1].Unlisted || len(cs[1].UnlistedVersions) != 1 {
		t.Errorf("really-gone: flag should stay, got %v %v", cs[1].Unlisted, cs[1].UnlistedVersions)
	}
	if !cs[2].Unlisted || len(cs[2].UnlistedVersions) != 1 || cs[2].UnlistedVersions[0] != "3.0.0" {
		t.Errorf("half-cleared: want only 3.0.0 kept, got %v %v", cs[2].Unlisted, cs[2].UnlistedVersions)
	}
	if !cs[3].Unlisted {
		t.Error("whole-pkg-gone: flag should stay on registry 404")
	}
	if cs[4].Unlisted {
		t.Errorf("added change: flag should clear when npm lists the version, got %v", cs[4].UnlistedVersions)
	}
}
