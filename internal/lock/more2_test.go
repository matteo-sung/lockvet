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
