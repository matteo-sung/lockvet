package lock

import (
	"reflect"
	"testing"
)

func TestParsePreCommitConfig(t *testing.T) {
	data := []byte(`# See https://pre-commit.com for more information
default_language_version:
  python: python3
repos:
-   repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.5.0
    hooks:
    -   id: trailing-whitespace
    -   id: end-of-file-fixer
-   repo: https://github.com/psf/black.git
    rev: "24.3.0"
    hooks:
    -   id: black
- repo: https://gitlab.com/some/group/hooks
  rev: v1.2.3  # pinned on purpose
  hooks:
  - id: thing
- repo: git@github.com:adrienverge/yamllint
  rev: v1.35.1
  hooks:
  - id: yamllint
- repo: local
  hooks:
  - id: my-local-hook
    name: local hook
    entry: ./scripts/check.sh
    language: script
- repo: meta
  hooks:
  - id: check-hooks-apply
`)
	f, err := parsePreCommitConfig(".pre-commit-config.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if f.Ecosystem != PreCommit || f.Kind != "pre-commit-config" {
		t.Fatalf("eco=%q kind=%q", f.Ecosystem, f.Kind)
	}
	want := map[string][]string{
		"github.com/pre-commit/pre-commit-hooks": {"v4.5.0"},
		"github.com/psf/black":                   {"24.3.0"},
		"gitlab.com/some/group/hooks":            {"v1.2.3"},
		"github.com/adrienverge/yamllint":        {"v1.35.1"},
	}
	if !reflect.DeepEqual(f.Packages, want) {
		t.Fatalf("packages = %v, want %v", f.Packages, want)
	}
	if !f.RootsKnown || len(f.Roots) != 4 {
		t.Fatalf("roots = %v (known=%v)", f.Roots, f.RootsKnown)
	}
}

func TestParsePreCommitConfigEdges(t *testing.T) {
	// A rev with spaces is not a ref; a repo with no rev pins nothing;
	// SHA revs are kept verbatim.
	data := []byte(`repos:
- repo: https://github.com/org/one
  rev: not a ref
  hooks: []
- repo: https://github.com/org/two
  hooks: []
- repo: https://github.com/org/three
  rev: 0e58ed8671d6b60d0890c21b07f8835ace038e67
  hooks: []
`)
	f, err := parsePreCommitConfig(".pre-commit-config.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"github.com/org/three": {"0e58ed8671d6b60d0890c21b07f8835ace038e67"},
	}
	if !reflect.DeepEqual(f.Packages, want) {
		t.Fatalf("packages = %v, want %v", f.Packages, want)
	}
}

func TestByBasenamePreCommit(t *testing.T) {
	for _, p := range []string{
		".pre-commit-config.yaml",
		"sub/dir/.pre-commit-config.yaml",
		`C:\repo\.pre-commit-config.yaml`,
		".pre-commit-config.yml",
	} {
		got := ByBasename(p)
		if got == nil || got.Kind != "pre-commit-config" {
			t.Fatalf("ByBasename(%q) = %v", p, got)
		}
	}
	// The hook DEFINITION file in hook repos is not a config.
	if got := ByBasename(".pre-commit-hooks.yaml"); got != nil {
		t.Fatalf(".pre-commit-hooks.yaml should not match, got %v", got)
	}
}
