package bzlreg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

func fakeRegistry(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/modules/protobuf/metadata.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
		  "homepage": "https://github.com/protocolbuffers/protobuf",
		  "repository": ["github:protocolbuffers/protobuf"],
		  "versions": ["3.19.0", "21.7", "35.0", "35.1"],
		  "yanked_versions": {"3.19.0": "CVE-2022-3171 (https://github.com/advisories/GHSA-h4h5-3hr4-j3g2)"}
		}`)
	})
	mux.HandleFunc("/modules/rules_java/metadata.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{
		  "repository": ["github:bazelbuild/rules_java"],
		  "versions": ["7.6.1", "8.0.0", "9.0.0-rc1"],
		  "yanked_versions": {}
		}`)
	})
	// lagging: metadata misses 2.0.0 but the MODULE.bazel file exists.
	mux.HandleFunc("/modules/lagging/metadata.json", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"repository": [], "versions": ["1.0.0"], "yanked_versions": {}}`)
	})
	mux.HandleFunc("/modules/lagging/2.0.0/MODULE.bazel", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `module(name = "lagging", version = "2.0.0")`)
	})
	server := httptest.NewServer(mux) // anything else 404s
	t.Cleanup(server.Close)
	return server
}

func change(name string, newVers ...string) diffx.FileDiff {
	return diffx.FileDiff{Path: "MODULE.bazel.lock", Changes: []diffx.Change{
		{Name: name, Ecosystem: "Bazel", Kind: diffx.Added, New: newVers},
	}}
}

func withFake(t *testing.T) {
	t.Helper()
	old := BaseURL
	BaseURL = fakeRegistry(t).URL
	t.Cleanup(func() { BaseURL = old })
}

func TestYankedVersion(t *testing.T) {
	withFake(t)
	diffs := []diffx.FileDiff{change("protobuf", "3.19.0")}
	ok, err := Annotate(diffs, 0)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated {
		t.Fatal("yanked version should be deprecated")
	}
	if c.DeprecatedReason == "" || c.Unlisted {
		t.Errorf("reason=%q unlisted=%v", c.DeprecatedReason, c.Unlisted)
	}
	if c.SourceRepo != "https://github.com/protocolbuffers/protobuf" {
		t.Errorf("SourceRepo = %q", c.SourceRepo)
	}
}

func TestUnlistedVersion(t *testing.T) {
	withFake(t)
	diffs := []diffx.FileDiff{change("rules_java", "99.0.0")}
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "99.0.0" {
		t.Errorf("unlisted=%v versions=%v", c.Unlisted, c.UnlistedVersions)
	}
}

func TestListedVersionQuiet(t *testing.T) {
	withFake(t)
	diffs := []diffx.FileDiff{change("rules_java", "8.0.0")}
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if c.Unlisted || c.Deprecated {
		t.Errorf("clean version flagged: unlisted=%v deprecated=%v", c.Unlisted, c.Deprecated)
	}
}

func TestMetadataLagCleared(t *testing.T) {
	withFake(t)
	diffs := []diffx.FileDiff{change("lagging", "2.0.0")}
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; c.Unlisted {
		t.Error("MODULE.bazel exists → the registry knows the version, no unlisted claim")
	}
}

func TestUnknownModuleNoClaims(t *testing.T) {
	withFake(t)
	diffs := []diffx.FileDiff{change("nonexistent_module", "1.0.0")}
	ok, err := Annotate(diffs, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("nothing was vetted, ok should be false")
	}
	if c := diffs[0].Changes[0]; c.Unlisted || c.Deprecated {
		t.Error("unknown module must produce no claims")
	}
}

func TestNonRegistrySkipped(t *testing.T) {
	withFake(t)
	diffs := []diffx.FileDiff{{Path: "MODULE.bazel.lock", Changes: []diffx.Change{
		{Name: "protobuf", Ecosystem: "Bazel", Kind: diffx.Added, New: []string{"3.19.0"}, NonRegistry: true},
	}}}
	ok, err := Annotate(diffs, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ok || diffs[0].Changes[0].Deprecated {
		t.Error("NonRegistry modules must be skipped")
	}
}

func TestLatest(t *testing.T) {
	withFake(t)
	v, err := Latest("rules_java")
	if err != nil {
		t.Fatal(err)
	}
	if v != "8.0.0" {
		t.Errorf("Latest = %q, want 8.0.0 (9.0.0-rc1 is a pre-release)", v)
	}
	if _, err := Latest("nonexistent_module"); err == nil {
		t.Error("want error for unknown module")
	}
}
