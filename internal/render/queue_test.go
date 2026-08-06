package render

import (
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

func TestSortQueue(t *testing.T) {
	rows := []QueueRow{
		{Label: "clean", Sum: diffx.Summary{Total: 2, Patch: 2}},
		{Label: "none", NoChanges: true},
		{Label: "err", Err: "boom"},
		{Label: "vuln1", Sum: diffx.Summary{Total: 1, VulnsIntroduced: 1}},
		{Label: "major", Sum: diffx.Summary{Total: 3, Major: 1}},
		{Label: "vuln2", Sum: diffx.Summary{Total: 1, VulnsIntroduced: 2}},
		{Label: "fresh", Sum: diffx.Summary{Total: 1, Fresh: 1}},
	}
	SortQueue(rows)
	var got []string
	for _, r := range rows {
		got = append(got, r.Label)
	}
	want := "vuln2 vuln1 major fresh clean none err"
	if strings.Join(got, " ") != want {
		t.Errorf("order = %q, want %q", strings.Join(got, " "), want)
	}
}

func TestQueueTerminal(t *testing.T) {
	rows := []QueueRow{
		{Label: "#1", URL: "https://x/1", Title: "bump left-pad", Sum: diffx.Summary{Total: 4, Major: 1, VulnsIntroduced: 1, VulnsFixed: 2}},
		{Label: "#2", Title: "bump actions/checkout", NoChanges: true},
		{Label: "#3", Title: "broken", Err: "GitHub API: 404"},
	}
	var b strings.Builder
	QueueTerminal(&b, "open dependency PRs — repo:o/r", "PR", "", rows, false, true, true, 7)
	out := b.String()
	for _, want := range []string{
		"open dependency PRs — repo:o/r",
		"#1", "+1/−2", "bump left-pad",
		"no lockfile changes", "error: GitHub API: 404",
		"1 alarming (vulns/unlisted/typosquat/scripts/provenance)", "1 without lockfile changes", "1 failed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("color escapes with color=false:\n%s", out)
	}
}

func TestQueueMarkdown(t *testing.T) {
	rows := []QueueRow{
		{Label: "agent#7", URL: "https://github.com/o/agent/pull/7", Title: "bump | pipe", Sum: diffx.Summary{Total: 2, Fresh: 1}},
	}
	var b strings.Builder
	QueueMarkdown(&b, "open dependency PRs — org:o", "PR", rows, true, true, 7)
	out := b.String()
	for _, want := range []string{
		"### 🔍 lockvet queue — open dependency PRs — org:o",
		"[agent#7](https://github.com/o/agent/pull/7)",
		"bump \\| pipe",
		"| 2 |",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown output missing %q:\n%s", want, out)
		}
	}
}

func TestVisibleWidth(t *testing.T) {
	if w := visibleWidth("\x1b[31m+1\x1b[0m/\x1b[32m−2\x1b[0m"); w != 5 {
		t.Errorf("visibleWidth = %d, want 5", w)
	}
	if w := visibleWidth("plain"); w != 5 {
		t.Errorf("visibleWidth = %d, want 5", w)
	}
}
