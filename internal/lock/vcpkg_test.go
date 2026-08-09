package lock

import "testing"

func TestParseVcpkgManifest(t *testing.T) {
	data := []byte(`{
  // vcpkg allows comments
  "name": "app",
  "dependencies": [ "zlib", { "name": "boost-asio", "version>=": "1.83.0" } ],
  "overrides": [
    { "name": "fmt", "version": "12.1.0" },
    { "name": "openssl", "version": "3.1.4", "port-version": 2 },
    { "name": "beicode", "version": "1.0.0" },
    { "name": "sqlite3", "version-semver": "3.45.0" }
  ],
  "builtin-baseline": "927F62e4b8838bd7e441e9c45103a16ffd75007e",
  "vcpkg-configuration": {
    "registries": [
      { "kind": "git", "repository": "https://github.com/northwindtraders/vcpkg-registry.git",
        "baseline": "dacf4de488094a384ca2c202b923ccc097956e0c", "packages": ["beicode", "beison"] }
    ]
  }
}`)
	p := ByBasename("some/dir/vcpkg.json")
	if p == nil {
		t.Fatal("no parser for vcpkg.json")
	}
	f, err := p.Parse("vcpkg.json", data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"builtin-baseline": "927f62e4b883",
		"fmt":              "12.1.0",
		"openssl":          "3.1.4#2",
		"beicode":          "1.0.0",
		"sqlite3":          "3.45.0",
		"registry github.com/northwindtraders/vcpkg-registry": "dacf4de48809",
	}
	for name, ver := range want {
		got := f.Packages[name]
		if len(got) != 1 || got[0] != ver {
			t.Errorf("%s = %v, want [%s]", name, got, ver)
		}
	}
	if _, ok := f.Packages["zlib"]; ok {
		t.Error("bare dependency zlib should pin nothing")
	}
	if _, ok := f.Packages["boost-asio"]; ok {
		t.Error("version>= constraint should pin nothing")
	}
	if f.PkgRepo["builtin-baseline"] != vcpkgOfficialRepo {
		t.Errorf("baseline PkgRepo = %q", f.PkgRepo["builtin-baseline"])
	}
	if !f.NonRegistry["beicode"] {
		t.Error("beicode is claimed by a custom registry: want NonRegistry")
	}
	if f.NonRegistry["fmt"] || f.NonRegistry["openssl"] {
		t.Error("official overrides must not be NonRegistry")
	}
}

func TestParseVcpkgConfiguration(t *testing.T) {
	data := []byte(`{
  "default-registry": { "kind": "git", "repository": "git@github.com:corp/private-vcpkg",
    "baseline": "aaaabbbbccccddddeeeeffff0000111122223333" },
  "registries": [
    { "kind": "filesystem", "path": "./registry", "packages": ["local-pkg"] },
    { "kind": "git", "repository": "https://gitlab.com/corp/registry",
      "baseline": "0123456789abcdef0123456789abcdef01234567", "packages": ["tool*"] }
  ]
}`)
	f, err := parseVcpkgConfiguration("vcpkg-configuration.json", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["default-registry"]; len(got) != 1 || got[0] != "aaaabbbbcccc" {
		t.Errorf("default-registry = %v", got)
	}
	if f.Pins["default-registry"]["aaaabbbbcccc"].Host != "github.com/corp/private-vcpkg" {
		t.Errorf("default-registry pin host = %q", f.Pins["default-registry"]["aaaabbbbcccc"].Host)
	}
	if got := f.Packages["registry gitlab.com/corp/registry"]; len(got) != 1 || got[0] != "0123456789ab" {
		t.Errorf("gitlab registry = %v", got)
	}
	if f.PkgRepo["registry gitlab.com/corp/registry"] != "https://gitlab.com/corp/registry" {
		t.Errorf("gitlab registry PkgRepo = %q", f.PkgRepo["registry gitlab.com/corp/registry"])
	}
}

func TestParseVcpkgBuiltinDefaultRegistry(t *testing.T) {
	// The builtin form and the explicit-git form of the official registry
	// must canonicalize to the same pin host (no ⇄ on equivalent edits).
	a, err := parseVcpkgConfiguration("vcpkg-configuration.json",
		[]byte(`{"default-registry":{"kind":"builtin","baseline":"927f62e4b8838bd7e441e9c45103a16ffd75007e"}}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := parseVcpkgConfiguration("vcpkg-configuration.json",
		[]byte(`{"default-registry":{"kind":"git","repository":"https://github.com/microsoft/vcpkg.git","baseline":"927f62e4b8838bd7e441e9c45103a16ffd75007e"}}`))
	if err != nil {
		t.Fatal(err)
	}
	ha := a.Pins["default-registry"]["927f62e4b883"].Host
	hb := b.Pins["default-registry"]["927f62e4b883"].Host
	if ha == "" || ha != hb {
		t.Errorf("builtin host %q != git host %q", ha, hb)
	}
}

func TestParseVcpkgCustomDefaultMarksOverrides(t *testing.T) {
	data := []byte(`{
  "overrides": [ { "name": "fmt", "version": "12.1.0" } ],
  "vcpkg-configuration": {
    "default-registry": { "kind": "git", "repository": "https://example.com/corp/registry",
      "baseline": "0123456789abcdef0123456789abcdef01234567" }
  }
}`)
	f, err := parseVcpkgManifest("vcpkg.json", data)
	if err != nil {
		t.Fatal(err)
	}
	if !f.NonRegistry["fmt"] {
		t.Error("default registry replaced: overrides must be NonRegistry")
	}
}

func TestParseVcpkgOverlayPortsMarkOverrides(t *testing.T) {
	data := []byte(`{
	  "dependencies": ["fmt"],
	  "overrides": [{"name": "fmt", "version": "11.1.4"}],
	  "builtin-baseline": "fe1cde61e971d53c9687cf9a46308f8f55da19fa",
	  "vcpkg-configuration": {"overlay-ports": ["./dep/vcpkg-overlay-ports"]}
	}`)
	f, err := parseVcpkgManifest("vcpkg.json", data)
	if err != nil {
		t.Fatal(err)
	}
	if !f.NonRegistry["fmt"] {
		t.Error("override under overlay-ports must be NonRegistry")
	}
	if f.NonRegistry["builtin-baseline"] {
		t.Error("baseline claims are independent of overlays")
	}
}
