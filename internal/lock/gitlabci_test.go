package lock

import "testing"

const gitlabCISample = `
stages:
  - build
  - test

include:
  - component: gitlab.com/components/opentofu/full-pipeline@2.0.0
    inputs:
      version: latest
      opentofu_version: 1.8.0
  - component: gitlab.com/gitlab-org/components/secret-detection/secret-detection@1.0
  - component: $CI_SERVER_FQDN/my-org/security/sast@3.1.4
  - component: gitlab.com/comp/proj/thing@$VERSION
  - project: my-group/my-deps
    ref: v1.2.0
    file: '/templates/build.yml'
  - project: my-group/unpinned
    file: '/templates/x.yml'
  - local: '/templates/local.yml'
  - template: Security/SAST.gitlab-ci.yml
  - remote: https://example.com/x.yml

default:
  image: alpine:3.20

variables:
  image: not-an-image-value
  IMAGE_TAG: "1.2"

build:
  image:
    name: golang:1.26-alpine
    entrypoint: [""]
  script:
    - |
      cat > x.yml <<EOF
      image: fake:1.0
      EOF
    - docker build .

test:
  image: node:22.1.0
  services:
    - postgres:16.3
    - name: redis:7.2
      alias: cache
    - name: docker:27-dind
      entrypoint:
        - dockerd
  script: make test

deploy:
  image: $CI_REGISTRY_IMAGE/app:latest
`

func TestParseGitLabCI(t *testing.T) {
	f, err := parseGitLabCI(".gitlab-ci.yml", []byte(gitlabCISample))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"gitlab.com/components/opentofu/full-pipeline":                       {"2.0.0"},
		"gitlab.com/gitlab-org/components/secret-detection/secret-detection": {"1.0"},
		"my-org/security/sast": {"3.1.4"},
		"my-group/my-deps":     {"v1.2.0"},
		"alpine":               {"3.20"},
		"golang":               {"1.26-alpine"},
		"node":                 {"22.1.0"},
		"postgres":             {"16.3"},
		"redis":                {"7.2"},
		"docker":               {"27-dind"},
	}
	for name, vs := range want {
		got := f.Packages[name]
		if len(got) != len(vs) || got[0] != vs[0] {
			t.Errorf("package %q = %v, want %v", name, got, vs)
		}
	}
	if len(f.Packages) != len(want) {
		t.Errorf("got %d packages, want %d: %v", len(f.Packages), len(want), f.Packages)
	}
	for _, absent := range []string{"gitlab.com/comp/proj/thing", "my-group/unpinned", "fake", "not-an-image-value"} {
		if _, ok := f.Packages[absent]; ok {
			t.Errorf("package %q should not be present", absent)
		}
	}
	if f.PkgEco["gitlab.com/components/opentofu/full-pipeline"] != GitLabCI {
		t.Errorf("component eco = %q", f.PkgEco["gitlab.com/components/opentofu/full-pipeline"])
	}
	if f.PkgEco["alpine"] != "" {
		t.Errorf("image should have no eco override")
	}
	if !f.NonRegistry["my-org/security/sast"] {
		t.Error("$CI_SERVER_FQDN component should be NonRegistry")
	}
	if !f.NonRegistry["my-group/my-deps"] {
		t.Error("project include should be NonRegistry")
	}
	if f.NonRegistry["gitlab.com/components/opentofu/full-pipeline"] {
		t.Error("host-qualified component should not be NonRegistry")
	}
}

func TestGitLabCIByBasename(t *testing.T) {
	for _, p := range []string{
		".gitlab-ci.yml", "sub/dir/.gitlab-ci.yml", ".gitlab-ci.yaml",
		"backend.gitlab-ci.yml", ".gitlab/ci/build.yml",
	} {
		pr := ByBasename(p)
		if pr == nil || pr.Kind != "gitlab-ci" {
			t.Errorf("ByBasename(%q) = %+v, want gitlab-ci", p, pr)
		}
	}
	// .gitlab/ files that are not CI-shaped parse to empty files.
	if pr := ByBasename(".gitlab/agents/prod/config.yaml"); pr == nil || pr.Kind != "gitlab-ci" {
		t.Errorf(".gitlab agent config should route to the lenient parser")
	}
	f, err := ByBasename(".gitlab/agents/prod/config.yaml").Parse(".gitlab/agents/prod/config.yaml",
		[]byte("gitops:\n  manifest_projects:\n  - id: g/p\nci_access:\n  image: sneaky:1.0\n"))
	if err != nil || len(f.Packages) != 0 {
		t.Errorf("non-CI .gitlab YAML should parse empty, got %v (%v)", f.Packages, err)
	}
	// CI-shaped fragment under .gitlab/ci/ does produce rows.
	f, err = ByBasename(".gitlab/ci/build.yml").Parse(".gitlab/ci/build.yml",
		[]byte("build:\n  image: alpine:3.20\n  script:\n    - make\n"))
	if err != nil || len(f.Packages) != 1 {
		t.Errorf("CI fragment should produce 1 package, got %v (%v)", f.Packages, err)
	}
}

func TestParseGitLabCIInstanceHost(t *testing.T) {
	CIInstanceHost = "gitlab.example.com"
	defer func() { CIInstanceHost = "" }()
	f, err := parseGitLabCI(".gitlab-ci.yml", []byte(gitlabCISample))
	if err != nil {
		t.Fatal(err)
	}
	// $CI_SERVER_FQDN component now resolves against the named instance:
	// host-qualified name, registry-eligible, GitLabCI eco.
	name := "gitlab.example.com/my-org/security/sast"
	if got := f.Packages[name]; len(got) != 1 || got[0] != "3.1.4" {
		t.Fatalf("resolved component = %v, want [3.1.4] (packages: %v)", got, f.Packages)
	}
	if f.NonRegistry[name] {
		t.Error("instance-resolved component should not be NonRegistry")
	}
	if f.PkgEco[name] != GitLabCI {
		t.Errorf("resolved component eco = %q, want GitLabCI", f.PkgEco[name])
	}
	if _, ok := f.Packages["my-org/security/sast"]; ok {
		t.Error("bare unresolved name should not remain")
	}
	// include:project pins keep their no-claims contract even when the
	// instance is known — a ref: can be a branch/SHA on a private project;
	// only component semver pins gain verification.
	if !f.NonRegistry["my-group/my-deps"] {
		t.Error("project include should stay NonRegistry")
	}
}
