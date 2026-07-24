package ghpr

import "testing"

func TestParseCompare(t *testing.T) {
	good := map[string]CmpRef{
		"https://github.com/sharkdp/fd/compare/v10.1.0...v10.2.0":     {"sharkdp", "fd", "v10.1.0", "v10.2.0"},
		"github.com/sharkdp/fd/compare/main...feature/x":              {"sharkdp", "fd", "main", "feature/x"},
		"https://github.com/o/r/compare/main...user:branch":           {"o", "r", "main", "user:branch"},
		"https://github.com/o/r/compare/main...user:repo:branch":      {"o", "r", "main", "user:repo:branch"},
		"https://github.com/o/r/compare/a...b?expand=1":               {"o", "r", "a", "b"},
		"https://github.com/o/r/compare/a...b#files_bucket":           {"o", "r", "a", "b"},
		"https://www.github.com/o/r/compare/abc1234...def5678":        {"o", "r", "abc1234", "def5678"},
		"https://github.com/o/r/compare/release/1.0...release/2.0":    {"o", "r", "release/1.0", "release/2.0"},
		"http://github.com/grafana/grafana/compare/v11.0.0...v11.1.0": {"grafana", "grafana", "v11.0.0", "v11.1.0"},
	}
	for in, want := range good {
		got, ok := ParseCompare(in)
		if !ok || got != want {
			t.Errorf("ParseCompare(%q) = %v, %v; want %v, true", in, got, ok, want)
		}
	}

	bad := []string{
		"", "main...dev", "o/r", "o/r#1",
		"https://github.com/o/r/compare/",
		"https://github.com/o/r/compare/onlyone",
		"https://github.com/o/r/compare/...b",
		"https://github.com/o/r/compare/a...",
		"https://github.com/o/r/pull/123",
		"https://gitlab.com/o/r/compare/a...b",
	}
	for _, in := range bad {
		if got, ok := ParseCompare(in); ok {
			t.Errorf("ParseCompare(%q) = %v, true; want false", in, got)
		}
	}
}

func TestParseCommit(t *testing.T) {
	o, r, sha, ok := ParseCommit("https://github.com/sharkdp/fd/commit/3ded4c8e7c5a")
	if !ok || o != "sharkdp" || r != "fd" || sha != "3ded4c8e7c5a" {
		t.Errorf("ParseCommit url = %s/%s@%s, %v", o, r, sha, ok)
	}
	if _, _, _, ok := ParseCommit("https://github.com/o/r/commit/notahash"); ok {
		t.Error("ParseCommit accepted a non-hex sha")
	}
	if _, _, _, ok := ParseCommit("https://github.com/o/r/commit/abc"); ok {
		t.Error("ParseCommit accepted a too-short sha")
	}
	if _, _, _, ok := ParseCommit("o/r@abcdef1"); ok {
		t.Error("ParseCommit accepted a non-url form")
	}
}

func TestSplitBasehead(t *testing.T) {
	cases := []struct {
		in         string
		base, head string
		ok         bool
	}{
		{"a...b", "a", "b", true},
		{"a..b", "a", "b", true},
		{"v1.0.0...v2.0.0", "v1.0.0", "v2.0.0", true},
		{"release/1...release/2", "release/1", "release/2", true},
		{"main...user:branch", "main", "user:branch", true},
		{"a", "", "", false},
		{"...b", "", "", false},
		{"a...", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		b, h, ok := SplitBasehead(c.in)
		if ok != c.ok || b != c.base || h != c.head {
			t.Errorf("SplitBasehead(%q) = %q, %q, %v; want %q, %q, %v", c.in, b, h, ok, c.base, c.head, c.ok)
		}
	}
}

func TestHeadRepoRef(t *testing.T) {
	cases := []struct {
		ref  CmpRef
		repo string
		rev  string
	}{
		{CmpRef{"o", "r", "main", "dev"}, "o/r", "dev"},
		{CmpRef{"o", "r", "main", "user:branch"}, "user/r", "branch"},
		{CmpRef{"o", "r", "main", "user:other:branch"}, "user/other", "branch"},
	}
	for _, c := range cases {
		repo, rev := headRepoRef(c.ref)
		if repo != c.repo || rev != c.rev {
			t.Errorf("headRepoRef(%v) = %q, %q; want %q, %q", c.ref, repo, rev, c.repo, c.rev)
		}
	}
}
