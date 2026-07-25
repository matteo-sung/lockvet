package lock

import "testing"

func TestPodfileLock(t *testing.T) {
	f := mustParse(t, "Podfile.lock", `PODS:
  - AFNetworking (2.6.3):
    - AFNetworking/NSURLConnection (= 2.6.3)
    - AFNetworking/NSURLSession (= 2.6.3)
  - AFNetworking/NSURLConnection (2.6.3):
    - AFNetworking/Reachability
  - Alamofire (5.4.4)
  - "GoogleUtilities/NSData+zlib (7.7.0)"
  - Firebase/Core (8.9.0):
    - FirebaseCore (= 8.9.0)

DEPENDENCIES:
  - Alamofire (~> 5.4)

SPEC CHECKSUMS:
  Alamofire: f3b09a368f1582ab751b3fff5460276e0d2cf5c9

COCOAPODS: 1.11.2
`)
	if f.Ecosystem != CocoaPods {
		t.Errorf("ecosystem = %s", f.Ecosystem)
	}
	wantPkgs(t, f, map[string][]string{
		"AFNetworking":    {"2.6.3"},
		"Alamofire":       {"5.4.4"},
		"GoogleUtilities": {"7.7.0"},
		"Firebase":        {"8.9.0"},
	})
}

func TestDenoLockV4(t *testing.T) {
	f := mustParse(t, "deno.lock", `{
  "version": "4",
  "specifiers": {
    "jsr:@std/assert@^1.0.0": "1.0.5",
    "npm:chalk@^5": "5.3.0"
  },
  "jsr": {
    "@std/assert@1.0.5": {"integrity": "abc", "dependencies": ["jsr:@std/internal"]},
    "@std/internal@1.0.4": {"integrity": "def"}
  },
  "npm": {
    "chalk@5.3.0": {"integrity": "sha512-x"},
    "string_decoder@1.3.0": {"integrity": "sha512-y"},
    "@tanstack/react-query@5.0.0_react@18.2.0": {"integrity": "sha512-z"}
  },
  "remote": {"https://deno.land/x/foo@1.0.0/mod.ts": "sha256"}
}`)
	if f.Ecosystem != NPM {
		t.Errorf("ecosystem = %s", f.Ecosystem)
	}
	wantPkgs(t, f, map[string][]string{
		"chalk":                 {"5.3.0"},
		"string_decoder":        {"1.3.0"},
		"@tanstack/react-query": {"5.0.0"},
		"jsr:@std/assert":       {"1.0.5"},
		"jsr:@std/internal":     {"1.0.4"},
	})
}

func TestDenoLockV3(t *testing.T) {
	f := mustParse(t, "deno.lock", `{
  "version": "3",
  "packages": {
    "specifiers": {"npm:express@4": "npm:express@4.18.2"},
    "npm": {
      "express@4.18.2": {"integrity": "sha512-a", "dependencies": {}}
    },
    "jsr": {
      "@luca/flag@1.0.1": {"integrity": "b"}
    }
  }
}`)
	wantPkgs(t, f, map[string][]string{
		"express":        {"4.18.2"},
		"jsr:@luca/flag": {"1.0.1"},
	})
}

func TestFlakeLock(t *testing.T) {
	f := mustParse(t, "flake.lock", `{
  "nodes": {
    "nixpkgs": {
      "locked": {
        "lastModified": 1720000000,
        "narHash": "sha256-abcdef",
        "owner": "NixOS",
        "repo": "nixpkgs",
        "rev": "deadbeefcafe1234567890",
        "type": "github"
      },
      "original": {"owner": "NixOS", "ref": "nixos-unstable", "repo": "nixpkgs", "type": "github"}
    },
    "flake-utils": {
      "locked": {
        "lastModified": 1710000000,
        "narHash": "sha256-xyz",
        "rev": "0123456789ab",
        "type": "github"
      }
    },
    "tarball-input": {
      "locked": {
        "narHash": "sha256-QQQQWWWWEEEE",
        "type": "tarball",
        "url": "https://example.com/x.tar.gz"
      }
    },
    "root": {
      "inputs": {"nixpkgs": "nixpkgs", "flake-utils": "flake-utils"}
    }
  },
  "root": "root",
  "version": 7
}`)
	if f.Ecosystem != Nix {
		t.Errorf("ecosystem = %s", f.Ecosystem)
	}
	// 1720000000 = 2024-07-03 UTC; 1710000000 = 2024-03-09 UTC
	wantPkgs(t, f, map[string][]string{
		"nixpkgs":       {"2024-07-03.deadbeef"},
		"flake-utils":   {"2024-03-09.01234567"},
		"tarball-input": {"QQQQWWWW"},
	})
}

func TestNixDiffSuppressesLevels(t *testing.T) {
	old := mustParse(t, "flake.lock", `{"nodes":{"nixpkgs":{"locked":{"lastModified":1710000000,"rev":"aaaaaaaaaaaa","type":"github"}},"root":{}},"root":"root","version":7}`)
	if old.Ecosystem.HasSemver() || old.Ecosystem.HasOSV() {
		t.Fatal("Nix should have neither semver nor OSV")
	}
}

func TestRenvLock(t *testing.T) {
	f := mustParse(t, "renv.lock", `{
  "R": {
    "Version": "4.3.1",
    "Repositories": [{"Name": "CRAN", "URL": "https://cloud.r-project.org"}]
  },
  "Bioconductor": {"Version": "3.17"},
  "Packages": {
    "dplyr": {
      "Package": "dplyr",
      "Version": "1.1.4",
      "Source": "Repository",
      "Repository": "CRAN",
      "Requirements": ["R", "cli", "generics", "methods", "utils"],
      "Hash": "fedd9d00c2944ff00a0e2696ccf048ec"
    },
    "cli": {
      "Package": "cli",
      "Version": "3.6.2",
      "Source": "Repository",
      "Repository": "CRAN",
      "Requirements": ["R", "utils"]
    },
    "generics": {
      "Package": "generics",
      "Version": "0.1.3",
      "Source": "Repository",
      "Repository": "RSPM"
    },
    "BiocGenerics": {
      "Package": "BiocGenerics",
      "Version": "0.46.0",
      "Source": "Bioconductor",
      "Requirements": ["R", "graphics", "methods"]
    },
    "lattice": {
      "Package": "lattice",
      "Version": "0.21-8",
      "Source": "Repository",
      "Repository": "CRAN"
    },
    "noversion": {"Package": "noversion", "Source": "Repository"}
  }
}`)
	if f.Ecosystem != CRAN {
		t.Errorf("ecosystem = %s", f.Ecosystem)
	}
	wantPkgs(t, f, map[string][]string{
		"dplyr":        {"1.1.4"},
		"cli":          {"3.6.2"},
		"generics":     {"0.1.3"},
		"BiocGenerics": {"0.46.0"},
		"lattice":      {"0.21-8"},
	})
	if got := f.PkgEco["BiocGenerics"]; got != Bioconductor {
		t.Errorf("BiocGenerics eco = %s, want Bioconductor", got)
	}
	if _, ok := f.PkgEco["dplyr"]; ok {
		t.Errorf("dplyr should not have a PkgEco override")
	}
	// Edges only between locked packages: dplyr -> cli, generics; the base
	// R packages (R, methods, utils, graphics) must not appear.
	wantEdges := map[string][]string{"dplyr": {"cli", "generics"}, "cli": nil, "BiocGenerics": nil}
	for from, want := range wantEdges {
		got := f.Deps[from]
		if len(got) != len(want) {
			t.Errorf("Deps[%s] = %v, want %v", from, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("Deps[%s] = %v, want %v", from, got, want)
			}
		}
	}
	if f.RootsKnown {
		t.Errorf("renv.lock records no direct-dependency roots")
	}
}

func TestRenvLockBareNA(t *testing.T) {
	// Real-world renv.lock files (e.g. tidyverse/datascience-box) carry
	// R's NA serialized unquoted, which is not valid JSON.
	f := mustParse(t, "renv.lock", `{
  "Packages": {
    "renv": {
      "Package": "renv",
      "Version": "1.0.7",
      "OS_type": NA,
      "Repository": "CRAN",
      "Source": "Repository",
      "Requirements": []
    },
    "NAmed": {
      "Package": "NAmed",
      "Version": "2.0",
      "Title": "has NA inside: \"NA\" and NAme-like words stay intact"
    }
  }
}`)
	wantPkgs(t, f, map[string][]string{"renv": {"1.0.7"}, "NAmed": {"2.0"}})
}
