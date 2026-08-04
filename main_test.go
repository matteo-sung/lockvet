package main

import (
	"regexp"
	"strings"
	"testing"
)

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

func TestCompletionScriptsCoverAllFlags(t *testing.T) {
	// Every flag advertised in the FLAGS section of usage must appear in
	// all three completion scripts and in the man page.
	re := regexp.MustCompile(`(?m)^  (-[a-z][a-z-]*)`)
	var flags []string
	for _, m := range re.FindAllStringSubmatch(usage, -1) {
		flags = append(flags, m[1])
	}
	if len(flags) < 10 {
		t.Fatalf("only found %d flags in usage — regex broken?", len(flags))
	}
	man := strings.ReplaceAll(manPage, `\-`, "-") // roff-escaped dashes
	for _, f := range flags {
		if !strings.Contains(bashCompletion, f) {
			t.Errorf("bash completion missing %s", f)
		}
		if !strings.Contains(zshCompletion, f+"[") {
			t.Errorf("zsh completion missing %s", f)
		}
		if !strings.Contains(fishCompletion, "-o "+strings.TrimPrefix(f, "-")+" ") {
			t.Errorf("fish completion missing %s", f)
		}
		if !strings.Contains(man, f) {
			t.Errorf("man page missing %s", f)
		}
	}
	// Subcommands must be offered everywhere too.
	for _, sub := range []string{"pr", "mr", "compare", "queue", "diff", "completion", "man"} {
		for name, script := range map[string]string{"bash": bashCompletion, "zsh": zshCompletion, "fish": fishCompletion} {
			if !strings.Contains(script, sub) {
				t.Errorf("%s completion missing subcommand %s", name, sub)
			}
		}
	}
	// -fail-on values stay in sync across scripts.
	for _, cond := range []string{"major", "vuln", "downgrade", "fresh", "deprecated", "license"} {
		for name, s := range map[string]string{"bash": bashCompletion, "zsh": zshCompletion, "fish": fishCompletion, "man": man} {
			if !strings.Contains(s, cond) {
				t.Errorf("%s missing -fail-on value %q", name, cond)
			}
		}
	}
}
