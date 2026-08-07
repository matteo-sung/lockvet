package lock

import "testing"

func TestIsWorkflowPath(t *testing.T) {
	yes := []string{
		".github/workflows/ci.yml",
		"sub/dir/.github/workflows/release.yaml",
		".gitea/workflows/build.yml",
		".forgejo/workflows/build.yml",
		"action.yml",
		"pkg/my-action/action.yaml",
		`C:\repo\.github\workflows\ci.yml`,
	}
	for _, p := range yes {
		if !isWorkflowPath(p) {
			t.Errorf("isWorkflowPath(%q) = false, want true", p)
		}
		if ByBasename(p) == nil {
			t.Errorf("ByBasename(%q) = nil", p)
		}
	}
	no := []string{
		"ci.yml",
		"workflows/ci.yml",
		".github/dependabot.yml",
		".github/workflows/README.md",
		"docker-compose.yaml",
	}
	for _, p := range no {
		if isWorkflowPath(p) {
			t.Errorf("isWorkflowPath(%q) = true, want false", p)
		}
	}
}

func TestParseWorkflowUses(t *testing.T) {
	data := []byte(`
name: ci
on: [push]
jobs:
  reuse:
    uses: my-org/shared/.github/workflows/build.yml@v3
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0
      - name: quoted
        uses: "actions/setup-go@v6"
      - uses: 'github/codeql-action/init@abc1234def5678abc1234def5678abc1234def56'
      - uses: ./local-action
      - uses: docker://alpine:3.20
      - uses: ${{ matrix.action }}@v1
      - uses: tj-actions/changed-files@45.0.7
      - run: |
          echo "uses: not-a-dep/fake@v1 inside a script is still matched — acceptable"
`)
	f, err := parseWorkflowUses(".github/workflows/ci.yml", data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"my-org/shared":            "v3",
		"actions/checkout":         "08c6903cd8c0fde910a37f88322edcfb5dd907a8",
		"actions/setup-go":         "v6",
		"github/codeql-action":     "abc1234def5678abc1234def5678abc1234def56",
		"tj-actions/changed-files": "45.0.7",
	}
	for name, ver := range want {
		vs := f.Packages[name]
		if len(vs) != 1 || vs[0] != ver {
			t.Errorf("%s = %v, want [%s]", name, vs, ver)
		}
	}
	for _, absent := range []string{"./local-action", "local-action"} {
		if _, ok := f.Packages[absent]; ok {
			t.Errorf("%s should be skipped", absent)
		}
	}
	if !f.RootsKnown || len(f.Roots) == 0 {
		t.Errorf("workflow pins are direct: RootsKnown=%v Roots=%v", f.RootsKnown, f.Roots)
	}
	if f.Ecosystem != GitHubActions {
		t.Errorf("ecosystem = %s", f.Ecosystem)
	}
}

func TestSplitUses(t *testing.T) {
	cases := []struct {
		in        string
		name, ref string
		ok        bool
	}{
		{"actions/checkout@v5", "actions/checkout", "v5", true},
		{"actions/checkout@v5 # comment", "actions/checkout", "v5", true},
		{`"actions/checkout@v5"`, "actions/checkout", "v5", true},
		{"owner/repo/sub/path@main", "owner/repo", "main", true},
		{"./local", "", "", false},
		{"docker://img@sha256:abc", "", "", false},
		{"no-slash@v1", "", "", false},
		{"a/b@", "", "", false},
		{"@scope/pkg@v1", "", "", false},
	}
	for _, c := range cases {
		name, ref, ok := splitUses(c.in)
		if name != c.name || ref != c.ref || ok != c.ok {
			t.Errorf("splitUses(%q) = (%q,%q,%v), want (%q,%q,%v)", c.in, name, ref, ok, c.name, c.ref, c.ok)
		}
	}
}
