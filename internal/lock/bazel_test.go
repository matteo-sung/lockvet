package lock

import "testing"

const bazelModernLock = `{
  "lockFileVersion": 28,
  "registryFileHashes": {
    "https://bcr.bazel.build/bazel_registry.json": "8a28e4aff06ee60aed2a8c281907fb8bcbf3b753c91fb5a5c57da3215d5b3497",
    "https://bcr.bazel.build/modules/abseil-cpp/20230125.1/MODULE.bazel": "89047429cb0207707b2dface14ba7f8df85273d484c2572755be4bab7ce9c3a0",
    "https://bcr.bazel.build/modules/abseil-cpp/20240116.1/MODULE.bazel": "37bcdb4440fbb61df6a1c296ae01b327f19e9bb521f9b8e26ec854b6f97309ed",
    "https://bcr.bazel.build/modules/abseil-cpp/20240116.1/source.json": "63a4b2396d1c56bbd961a07d671fe4cad4bdd11a08fdd0b57e3f5b45b6d1a4c8",
    "https://bcr.bazel.build/modules/rules_java/7.6.1/MODULE.bazel": "2f14b7e8a1aa2f67ae92bc09d14b90a6f16fc6697b1712de53d7d6b0f22cd8e5",
    "https://bcr.bazel.build/modules/rules_java/7.6.1/source.json": "8f3f3076554e1558e8e468b2232991c510ecbcbed9e6f8c06ac31c93bcf38362",
    "https://corp.example.com/registry/modules/secret_rules/1.0.0/MODULE.bazel": "aaaa",
    "https://corp.example.com/registry/modules/secret_rules/1.0.0/source.json": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "selectedYankedVersions": {
    "protobuf@3.19.0": "CVE-2022-3171 (https://github.com/advisories/GHSA-h4h5-3hr4-j3g2)"
  }
}`

func TestBazelLockModern(t *testing.T) {
	f, err := parseBazelLock("MODULE.bazel.lock", []byte(bazelModernLock))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["abseil-cpp"]; len(got) != 1 || got[0] != "20240116.1" {
		t.Errorf("abseil-cpp = %v, want the source.json (selected) version only", got)
	}
	if got := f.Packages["rules_java"]; len(got) != 1 || got[0] != "7.6.1" {
		t.Errorf("rules_java = %v", got)
	}
	pin := f.Pin("rules_java", "7.6.1")
	if pin.Host != "bcr.bazel.build" {
		t.Errorf("host = %q", pin.Host)
	}
	if pin.Integrity == "" {
		t.Error("integrity pin missing")
	}
	if !f.NonRegistry["secret_rules"] {
		t.Error("private-registry module should be NonRegistry")
	}
	if f.Pin("secret_rules", "1.0.0").Host != "corp.example.com" {
		t.Errorf("private host = %q", f.Pin("secret_rules", "1.0.0").Host)
	}
	if r := f.PkgYanked["protobuf@3.19.0"]; r == "" {
		t.Error("selectedYankedVersions should land in PkgYanked")
	}
}

const bazelOldLock = `{
  "lockFileVersion": 3,
  "moduleFileHash": "x",
  "localOverrideHashes": {"<root>": "y", "patched_local": "z"},
  "moduleDepGraph": {
    "<root>": {
      "name": "myproject",
      "version": "",
      "deps": {"rules_license": "rules_license@0.0.7", "bazel_tools": "bazel_tools@_"}
    },
    "rules_license@0.0.7": {
      "name": "rules_license",
      "version": "0.0.7",
      "deps": {"bazel_tools": "bazel_tools@_", "platforms": "platforms@0.0.8"},
      "repoSpec": {
        "ruleClassName": "http_archive",
        "attributes": {"integrity": "sha256-RTHezLkTY5ww5cdRKgVNXYdWmNrrddjPkPKEN1/nw2A="}
      }
    },
    "platforms@0.0.8": {
      "name": "platforms",
      "version": "0.0.8",
      "deps": {},
      "repoSpec": {"ruleClassName": "http_archive", "attributes": {"integrity": "sha256-ABC="}}
    },
    "forked_thing@1.2.3": {
      "name": "forked_thing",
      "version": "1.2.3",
      "deps": {},
      "repoSpec": {"ruleClassName": "git_repository", "attributes": {}}
    },
    "bazel_tools@_": {"name": "bazel_tools", "version": "", "deps": {}}
  }
}`

func TestBazelLockOld(t *testing.T) {
	f, err := parseBazelLock("MODULE.bazel.lock", []byte(bazelOldLock))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["rules_license"]; len(got) != 1 || got[0] != "0.0.7" {
		t.Errorf("rules_license = %v", got)
	}
	if _, ok := f.Packages["bazel_tools"]; ok {
		t.Error("built-in bazel_tools@_ must not be a package")
	}
	if !f.RootsKnown || len(f.Roots) != 1 || f.Roots[0] != "rules_license" {
		t.Errorf("roots = %v (known=%v)", f.Roots, f.RootsKnown)
	}
	deps := f.Deps["rules_license"]
	if len(deps) != 1 || deps[0] != "platforms" {
		t.Errorf("rules_license deps = %v", deps)
	}
	if f.Pin("rules_license", "0.0.7").Integrity == "" {
		t.Error("SRI integrity pin missing")
	}
	if !f.NonRegistry["forked_thing"] {
		t.Error("git_repository module should be NonRegistry")
	}
	if !f.NonRegistry["patched_local"] {
		t.Error("localOverrideHashes module should be NonRegistry")
	}
}

func TestBazelLockRejectsOtherJSON(t *testing.T) {
	if _, err := parseBazelLock("MODULE.bazel.lock", []byte(`{"name":"x"}`)); err == nil {
		t.Error("want an error for JSON that is not a bzlmod lockfile")
	}
}
