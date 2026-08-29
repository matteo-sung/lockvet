package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// A removed package that was carrying advisories gets a neutral note in
// both renderers — worded as context ("removed, not fixed"), never as a
// fix, and the summary's fixed count stays untouched.
func TestRemovedVulnsNote(t *testing.T) {
	diffs := []diffx.FileDiff{{
		Path: "requirements.txt",
		Changes: []diffx.Change{{
			Name: "pyyaml", Ecosystem: "PyPI", Kind: diffx.Removed,
			Old: []string{"5.3.1"},
			RemovedVulns: []diffx.Vuln{{
				ID: "GHSA-8q59-q68h-6hv4", Severity: "critical",
				Summary: "arbitrary code execution via full_load",
			}},
		}},
	}}
	sum := diffx.Summarize(diffs)
	if sum.VulnsFixed != 0 || sum.VulnsIntroduced != 0 {
		t.Fatalf("removal leaked into vuln counts: %+v", sum)
	}

	var term bytes.Buffer
	Terminal(&term, diffs, sum, false, true, false, 30)
	if !strings.Contains(term.String(), "was carrying 1 known advisory (worst: critical, GHSA-8q59-q68h-6hv4) — removed, not fixed") {
		t.Errorf("terminal note missing:\n%s", term.String())
	}

	var md bytes.Buffer
	Markdown(&md, diffs, sum, true, false, 30)
	if !strings.Contains(md.String(), "was carrying 1 known advisory") || !strings.Contains(md.String(), "removed, not fixed") {
		t.Errorf("markdown note missing:\n%s", md.String())
	}
}
