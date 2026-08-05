package lock

import "testing"

func TestConanLockV2(t *testing.T) {
	data := []byte(`{
  "version": "0.5",
  "requires": [
    "zlib/1.3.1#f52e03ae3d251dec704634230cd806a2%1708593606.497",
    "fmt/10.2.1#9199a2a0a1a1b0aab616a2ba34d93d94%1708593606.497",
    "mytool/1.0.0@corp/stable#deadbeef%1700000000.0",
    "plain/2.0"
  ],
  "build_requires": [
    "cmake/3.25.3#586c962fa58ccc886a7b2667f7c19ab9%1678699428.979"
  ],
  "python_requires": [],
  "config_requires": []
}`)
	p := ByBasename("some/dir/conan.lock")
	if p == nil {
		t.Fatal("no parser for conan.lock")
	}
	f, err := p.Parse("conan.lock", data)
	if err != nil {
		t.Fatal(err)
	}
	if f.Ecosystem != Conan {
		t.Fatalf("eco = %q", f.Ecosystem)
	}
	for name, want := range map[string]string{
		"zlib": "1.3.1", "fmt": "10.2.1", "mytool": "1.0.0", "plain": "2.0", "cmake": "3.25.3",
	} {
		got := f.Packages[name]
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s = %v, want [%s]", name, got, want)
		}
	}
	if !f.NonRegistry["mytool"] {
		t.Error("mytool (user/channel ref) should be NonRegistry")
	}
	if f.NonRegistry["zlib"] || f.NonRegistry["plain"] {
		t.Error("center refs must not be NonRegistry")
	}
	if f.RootsKnown {
		t.Error("v2 flat lockfile records no graph")
	}
}

func TestConanLockV1GraphLock(t *testing.T) {
	data := []byte(`{
  "graph_lock": {
    "nodes": {
      "0": {"path": "conanfile.py", "requires": ["1", "2"]},
      "1": {"ref": "openssl/1.1.1k#deadbeef", "requires": ["3"]},
      "2": {"ref": "fmt/8.0.0", "requires": []},
      "3": {"ref": "zlib/1.2.11@user/channel", "requires": []}
    },
    "revisions_enabled": true
  },
  "version": "0.4"
}`)
	f, err := parseConanLock("conan.lock", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["openssl"]; len(got) != 1 || got[0] != "1.1.1k" {
		t.Fatalf("openssl = %v", got)
	}
	if !f.RootsKnown || len(f.Roots) != 2 {
		t.Fatalf("roots = %v known=%v", f.Roots, f.RootsKnown)
	}
	found := false
	for _, d := range f.Deps["openssl"] {
		if d == "zlib" {
			found = true
		}
	}
	if !found {
		t.Errorf("missing openssl -> zlib edge: %v", f.Deps)
	}
	if !f.NonRegistry["zlib"] {
		t.Error("zlib@user/channel should be NonRegistry")
	}
}

func TestSplitConanRef(t *testing.T) {
	cases := []struct {
		in, name, ver string
		nonReg        bool
	}{
		{"zlib/1.3.1#abc%123.4", "zlib", "1.3.1", false},
		{"pkg/1.0@user/ch#abc", "pkg", "1.0", true},
		{"pkg/1.0@_/_", "pkg", "1.0", false},
		{"noslash", "", "", false},
		{"cci/cci.20210814", "cci", "cci.20210814", false},
	}
	for _, c := range cases {
		n, v, nr := splitConanRef(c.in)
		if n != c.name || v != c.ver || nr != c.nonReg {
			t.Errorf("splitConanRef(%q) = %q %q %v", c.in, n, v, nr)
		}
	}
}
