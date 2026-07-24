package ghpr

import "testing"

func TestParse(t *testing.T) {
	good := map[string]Ref{
		"https://github.com/sharkdp/fd/pull/1723":         {"sharkdp", "fd", 1723},
		"http://github.com/sharkdp/fd/pull/1723":          {"sharkdp", "fd", 1723},
		"github.com/sharkdp/fd/pull/1723":                 {"sharkdp", "fd", 1723},
		"https://www.github.com/sharkdp/fd/pull/1723":     {"sharkdp", "fd", 1723},
		"https://github.com/sharkdp/fd/pull/1723/files":   {"sharkdp", "fd", 1723},
		"https://github.com/sharkdp/fd/pull/1723?diff=s":  {"sharkdp", "fd", 1723},
		"https://github.com/sharkdp/fd/pull/1723#issue-1": {"sharkdp", "fd", 1723},
		"sharkdp/fd#1723":                                 {"sharkdp", "fd", 1723},
		"matteo-sung/lockvet-demo#1":                      {"matteo-sung", "lockvet-demo", 1},
		"My-Org/some.repo_name#42":                        {"My-Org", "some.repo_name", 42},
	}
	for in, want := range good {
		got, ok := Parse(in)
		if !ok || got != want {
			t.Errorf("Parse(%q) = %v, %v; want %v, true", in, got, ok, want)
		}
	}

	bad := []string{
		"", "HEAD~5", "main", "v0.1.3", "owner/repo", "owner/repo#",
		"owner/repo#0", "owner/repo#-1", "owner#1", "a/b/c#1",
		"https://github.com/sharkdp/fd/issues/1723",
		"https://gitlab.com/o/r/pull/1",
		"https://github.com/sharkdp/fd/pull/", "pr",
		"HEAD~1..HEAD", "release-1.2#3x",
	}
	for _, in := range bad {
		if got, ok := Parse(in); ok {
			t.Errorf("Parse(%q) = %v, true; want false", in, got)
		}
	}
}
