package lock

import "testing"

const zlsModernZon = `.{
    .name = .zls,
    // Remove ` + "`-dev`" + ` when tagging a new ZLS release.
    .version = "0.17.0-dev",
    .minimum_zig_version = "0.17.0-dev.292+fc1c83a36",
    .dependencies = .{
        .known_folders = .{
            .url = "https://github.com/ziglibs/known-folders/archive/207c34a16e4365edc20d92c7892f962b3bed46e8.tar.gz",
            .hash = "known_folders-0.0.0-Fy-PJsbKAACbDh9bBxR0MMThxZSS6A9RH4apWphNHY70",
        },
        .diffz = .{
            .url = "https://github.com/ziglibs/diffz/archive/d080c1eb782fff15068cabb3b82da85ce6054b74.tar.gz",
            .hash = "diffz-0.0.1-G2tlIfLNAQCc06RFk0tFGj2M-X-id4WHFkMVw2JoMILR",
        },
        .tracy = .{
            .url = "https://github.com/wolfpld/tracy/archive/refs/tags/v0.13.1.tar.gz",
            .hash = "N-V-__8AAOncKwEm1F9c5LrT7HMNmRMYX8-fAoqpc6YyTu9X",
            .lazy = true,
        },
        .@"weird-name" = .{
            .url = "https://deps.example.org/weird-1.2.3.tar.gz",
            .hash = "weird_name-1.2.3-Q_BUWmU6BwB_9JKG2l2W7i_mhmYWeRseTGBEHi_YlV5f",
        },
        .local_thing = .{ .path = "../local" },
    },
    .paths = .{""},
    .fingerprint = 0xa66330b97eb969ae, // trailing comment
}
`

func TestParseZigZonModern(t *testing.T) {
	f, err := parseZigZon("build.zig.zon", []byte(zlsModernZon))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		// URL revision beats the hash's semver: it is the content identity.
		"known_folders": "207c34a16e43",
		"diffz":         "d080c1eb782f",
		// Tag tarball, N-V hash: the tag is the version.
		"tracy": "v0.13.1",
		// Plain tarball, no rev: the hash's semver.
		"weird-name": "1.2.3",
	}
	if len(f.Packages) != len(want) {
		t.Fatalf("got %d packages (%v), want %d", len(f.Packages), f.Packages, len(want))
	}
	for name, ver := range want {
		got := f.Packages[name]
		if len(got) != 1 || got[0] != ver {
			t.Errorf("%s: got %v, want [%s]", name, got, ver)
		}
	}
	if _, ok := f.Packages["local_thing"]; ok {
		t.Error("path dependency should be skipped")
	}
	// Pins: hash as integrity, forge repo path as host.
	pin := f.Pin("diffz", "d080c1eb782f")
	if pin.Integrity == "" || pin.Host != "github.com/ziglibs/diffz" {
		t.Errorf("diffz pin = %+v", pin)
	}
	if h := f.Pin("weird-name", "1.2.3").Host; h != "deps.example.org" {
		t.Errorf("mirror host = %q", h)
	}
	if r := f.PkgRepo["tracy"]; r != "https://github.com/wolfpld/tracy" {
		t.Errorf("tracy repo = %q", r)
	}
	if _, ok := f.PkgRepo["weird-name"]; ok {
		t.Error("mirror URL must not become a repo link")
	}
}

const zlsLegacyZon = `.{
    .name = "zls",
    .version = "0.13.0",
    .dependencies = .{
        .known_folders = .{
            .url = "https://github.com/ziglibs/known-folders/archive/0ad514dcfb7525e32ae349b9acc0a53976f3a9fa.tar.gz",
            .hash = "12209cde192558f8b3dc098ac2330fc2a14fdd211c5433afd33085af75caa9183147",
        },
    },
    .paths = .{""},
}
`

func TestParseZigZonLegacy(t *testing.T) {
	f, err := parseZigZon("build.zig.zon", []byte(zlsLegacyZon))
	if err != nil {
		t.Fatal(err)
	}
	got := f.Packages["known_folders"]
	if len(got) != 1 || got[0] != "0ad514dcfb75" {
		t.Fatalf("known_folders = %v", got)
	}
	// The pre-0.14 multihash is labeled sha256 (0x12 0x20 prefix) so the
	// pin-comparison layer can compare it at all: bare 68-char hex matches
	// no algorithm shape and a swapped hash would silently compare as
	// nothing (the bug this assertion pins down).
	if pin := f.Pin("known_folders", "0ad514dcfb75"); pin.Integrity !=
		"sha256:9cde192558f8b3dc098ac2330fc2a14fdd211c5433afd33085af75caa9183147" {
		t.Fatalf("legacy integrity = %q", pin.Integrity)
	}
}

func TestZigIntegrityLabels(t *testing.T) {
	cases := map[string]string{
		"": "",
		// pre-0.14 multihash → sha256 with the 2-byte prefix stripped
		"12209cde192558f8b3dc098ac2330fc2a14fdd211c5433afd33085af75caa9183147": "sha256:9cde192558f8b3dc098ac2330fc2a14fdd211c5433afd33085af75caa9183147",
		// 0.14+ package hash: leading NAME must not be mistaken for an
		// algorithm label ("zap") nor dropped ("known_folders")
		"zap-0.8.0-Fy-PJsbKAACbDh9bBxR0MMThxZSS6A9RH4apWphNHY70":           "zigpkg:zap-0.8.0-Fy-PJsbKAACbDh9bBxR0MMThxZSS6A9RH4apWphNHY70",
		"known_folders-0.0.0-Fy-PJsbKAACbDh9bBxR0MMThxZSS6A9RH4apWphNHY70": "zigpkg:known_folders-0.0.0-Fy-PJsbKAACbDh9bBxR0MMThxZSS6A9RH4apWphNHY70",
		// wrong-length hex is not a multihash: keep it comparable anyway
		"deadbeef": "zigpkg:deadbeef",
	}
	for in, want := range cases {
		if got := zigIntegrity(in); got != want {
			t.Errorf("zigIntegrity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseZigZonGitURL(t *testing.T) {
	src := `.{
    .name = .raylib_zig,
    .version = "5.6.0-dev",
    .dependencies = .{
        .raylib = .{
            .url = "git+https://github.com/raysan5/raylib?ref=master#bdda18656b301303b711785db48ac311655bb3d9",
            .hash = "raylib-5.5.0-whq8uExcNgQBBys4-PIIEqPuWO-MpfOJkwiM4Q1nLXVN",
        },
        .tagged = .{
            .url = "git+https://github.com/foo/bar?ref=v1.4.0",
            .hash = "N-V-__8AAEp9UgBJ2n1eks3_3YZk3GCO1XOENazWaCO7ggM2",
        },
        .hashonly = .{
            .url = "https://mirror.example.com/blob.tar.gz",
            .hash = "N-V-__8AAEp9UgBJ2n1eks3_3YZk3GCO1XOENazWaCO7ggM2",
        },
    },
}
`
	f, err := parseZigZon("build.zig.zon", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["raylib"]; len(got) != 1 || got[0] != "bdda18656b30" {
		t.Errorf("raylib = %v (want the #rev, not the branch ref)", got)
	}
	if got := f.Packages["tagged"]; len(got) != 1 || got[0] != "v1.4.0" {
		t.Errorf("tagged = %v", got)
	}
	// No rev, no tag, N-V hash: an (opaque but change-tracking) digest prefix.
	if got := f.Packages["hashonly"]; len(got) != 1 || got[0] != "__8AAEp9UgBJ" {
		t.Errorf("hashonly = %v", got)
	}
	if r := f.PkgRepo["raylib"]; r != "https://github.com/raysan5/raylib" {
		t.Errorf("raylib repo = %q", r)
	}
}

func TestParseZigZonNoDeps(t *testing.T) {
	src := ".{\n    .name = .libxev,\n    .version = \"0.0.0\",\n    .paths = .{\"\"},\n}\n"
	f, err := parseZigZon("build.zig.zon", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Packages) != 0 {
		t.Fatalf("leaf package should parse empty, got %v", f.Packages)
	}
}

func TestParseZigZonRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "not zon", "{\"json\":true}", ".{", `.{ .a = `} {
		if _, err := parseZigZon("build.zig.zon", []byte(bad)); err == nil {
			t.Errorf("parse(%q) should fail", bad)
		}
	}
}

func TestZigHashVersion(t *testing.T) {
	cases := map[string]string{
		"diffz-0.0.1-G2tlIfLNAQCc06RFk0tFGj2M-X-id4WHFkMVw2JoMILR":             "0.0.1",
		"known_folders-0.0.0-Fy-PJsbKAACbDh9bBxR0MMThxZSS6A9RH4apWphNHY70":     "0.0.0",
		"vaxis-0.6.0-BWNV_CrbCQCscGpzsAlR402rYQ_tV3aAl081c2iRRkka":             "0.6.0",
		"N-V-__8AAOncKwEm1F9c5LrT7HMNmRMYX8-fAoqpc6YyTu9X":                     "",
		"12209cde192558f8b3dc098ac2330fc2a14fdd211c5433afd33085af75caa9183147": "",
		"": "",
	}
	for h, want := range cases {
		if got := zigHashVersion(h); got != want {
			t.Errorf("zigHashVersion(%q) = %q, want %q", h, got, want)
		}
	}
}

func TestZigURLShapes(t *testing.T) {
	if tag := zigURLTag("https://github.com/wolfpld/tracy/archive/refs/tags/v0.13.1.tar.gz"); tag != "v0.13.1" {
		t.Errorf("tag = %q", tag)
	}
	if tag := zigURLTag("git+https://github.com/foo/bar?ref=master#bdda18656b301303b711785db48ac311655bb3d9"); tag != "" {
		t.Errorf("branch ref must not be a tag, got %q", tag)
	}
	if rev := zigURLRev("https://github.com/z/k/archive/207c34a16e4365edc20d92c7892f962b3bed46e8.tar.gz"); rev != "207c34a16e4365edc20d92c7892f962b3bed46e8" {
		t.Errorf("rev = %q", rev)
	}
	if rev := zigURLRev("git+https://github.com/a/b#deadbeefcafe"); rev != "deadbeefcafe" {
		t.Errorf("fragment rev = %q", rev)
	}
	if host := zigHost("https://gitlab.com/Owner/Repo/-/archive/x.tar.gz"); host != "gitlab.com/owner/repo" {
		t.Errorf("gitlab host = %q", host)
	}
	if host := zigHost("https://deps.files.ghostty.org/libxev-9ce8.tar.gz"); host != "deps.files.ghostty.org" {
		t.Errorf("mirror host = %q", host)
	}
}
