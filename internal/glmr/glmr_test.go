package glmr

import "testing"

func TestParseMR(t *testing.T) {
	cases := []struct {
		in      string
		ok      bool
		host    string
		project string
		iid     int
	}{
		{"https://gitlab.com/gitlab-org/gitlab/-/merge_requests/12345", true, "gitlab.com", "gitlab-org/gitlab", 12345},
		{"gitlab.com/gitlab-org/gitlab/-/merge_requests/12345", true, "gitlab.com", "gitlab-org/gitlab", 12345},
		{"https://gitlab.com/group/sub/project/-/merge_requests/7/diffs", true, "gitlab.com", "group/sub/project", 7},
		{"https://gitlab.example.org:8443/team/app/-/merge_requests/3?tab=diffs#note_1", true, "gitlab.example.org:8443", "team/app", 3},
		{"gitlab-org/gitlab!12345", true, "gitlab.com", "gitlab-org/gitlab", 12345},
		{"group/sub/project!7", true, "gitlab.com", "group/sub/project", 7},
		{"owner/repo#123", false, "", "", 0},                                   // GitHub form
		{"https://github.com/owner/repo/pull/1", false, "", "", 0},             // GitHub URL
		{"https://gitlab.com/onlygroup/-/merge_requests/1x", false, "", "", 0}, // bad iid
		{"project!7", false, "", "", 0},                                        // no namespace
	}
	for _, c := range cases {
		ref, ok := ParseMR(c.in)
		if ok != c.ok {
			t.Errorf("ParseMR(%q) ok=%v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && (ref.Host != c.host || ref.Project != c.project || ref.IID != c.iid) {
			t.Errorf("ParseMR(%q) = %+v, want %s/%s!%d", c.in, ref, c.host, c.project, c.iid)
		}
	}
}

func TestParseCompare(t *testing.T) {
	ref, ok := ParseCompare("https://gitlab.com/veloren/veloren/-/compare/v0.16.0...v0.17.0")
	if !ok || ref.Project != "veloren/veloren" || ref.Base != "v0.16.0" || ref.Head != "v0.17.0" {
		t.Fatalf("compare url parse failed: %+v ok=%v", ref, ok)
	}
	ref, ok = ParseCompare("https://gitlab.example.org/a/b/-/compare/main...feat%2Fx?from_project_id=1")
	if !ok || ref.Host != "gitlab.example.org" || ref.Base != "main" || ref.Head != "feat/x" {
		t.Fatalf("escaped compare parse failed: %+v ok=%v", ref, ok)
	}
	if _, ok := ParseCompare("https://github.com/a/b/compare/x...y"); ok {
		t.Fatal("github compare url must not parse as gitlab")
	}
}

func TestParseCommit(t *testing.T) {
	host, proj, sha, ok := ParseCommit("https://gitlab.com/group/sub/app/-/commit/abcdef1234567")
	if !ok || host != "gitlab.com" || proj != "group/sub/app" || sha != "abcdef1234567" {
		t.Fatalf("commit url parse failed: %s %s %s ok=%v", host, proj, sha, ok)
	}
	if _, _, _, ok := ParseCommit("https://gitlab.com/g/p/-/commit/nothex"); ok {
		t.Fatal("non-hex sha must not parse")
	}
}
