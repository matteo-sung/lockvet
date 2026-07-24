package main

import "testing"

func TestSplitQueueScope(t *testing.T) {
	cases := []struct {
		in, host, rest string
	}{
		{"grafana", "", "grafana"},
		{"sharkdp/fd", "", "sharkdp/fd"},
		{"github.com/grafana", "github.com", "grafana"},
		{"https://github.com/sharkdp/fd", "github.com", "sharkdp/fd"},
		{"gitlab.com/gitlab-org", "gitlab.com", "gitlab-org"},
		{"https://gitlab.com/gitlab-org/gitlab/", "gitlab.com", "gitlab-org/gitlab"},
		{"gitlab.example.org/team/sub/proj", "gitlab.example.org", "team/sub/proj"},
		{"http://gitlab.internal:8080/g", "gitlab.internal:8080", "g"},
		// GitHub owners can't contain dots, so a dotted first segment is a host;
		// a dotted *repo* is fine.
		{"owner/repo.js", "", "owner/repo.js"},
	}
	for _, c := range cases {
		host, rest := splitQueueScope(c.in)
		if host != c.host || rest != c.rest {
			t.Errorf("splitQueueScope(%q) = %q,%q; want %q,%q", c.in, host, rest, c.host, c.rest)
		}
	}
}
