package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

func auditDiffs() []diffx.FileDiff {
	return []diffx.FileDiff{{
		Path: "package-lock.json", Ecosystem: "npm",
		Changes: []diffx.Change{
			{Name: "chalk", Ecosystem: "npm", Kind: diffx.Added, New: []string{"5.6.1"},
				Origin:   "direct",
				Unlisted: true, UnlistedVersions: []string{"5.6.1"},
				IntroducedVulns: []diffx.Vuln{{ID: "MAL-2025-46969", Summary: "Malicious code in chalk (npm)", URL: "https://osv.dev/vulnerability/MAL-2025-46969"}}},
			{Name: "healthy", Ecosystem: "npm", Kind: diffx.Added, New: []string{"1.0.0"}, Origin: "transitive", Via: []string{"chalk"}},
		},
	}, {
		Path: "go.mod", Ecosystem: "Go",
		Changes: []diffx.Change{
			{Name: "github.com/pkg/errors", Ecosystem: "Go", Kind: diffx.Added, New: []string{"0.9.1"}, Origin: "direct"},
		},
	}}
}

func TestAuditTerminal(t *testing.T) {
	diffs := auditDiffs()
	var buf bytes.Buffer
	AuditTerminal(&buf, diffs, diffx.Summarize(diffs), false, true, true, 7)
	out := buf.String()
	for _, want := range []string{
		"audited 3 packages across 2 lockfiles",
		"1 advisory affecting 1 package",
		"affected by MAL-2025-46969",
		"not in registry index: 5.6.1",
		"✓", // clean go.mod
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal audit output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "healthy") {
		t.Errorf("finding-free package listed:\n%s", out)
	}
}

func TestAuditTerminalPluralAdvisories(t *testing.T) {
	diffs := auditDiffs()
	diffs[0].Changes[0].IntroducedVulns = append(diffs[0].Changes[0].IntroducedVulns,
		diffx.Vuln{ID: "GHSA-xxxx", Summary: "another"})
	var buf bytes.Buffer
	AuditTerminal(&buf, diffs, diffx.Summarize(diffs), false, true, true, 7)
	if !strings.Contains(buf.String(), "2 advisories affecting 1 package") {
		t.Errorf("plural advisories wrong:\n%s", buf.String())
	}
}

func TestAuditMarkdown(t *testing.T) {
	diffs := auditDiffs()
	var buf bytes.Buffer
	AuditMarkdown(&buf, diffs, diffx.Summarize(diffs), true, true, 7)
	out := buf.String()
	for _, want := range []string{
		"### 🔍 lockvet audit",
		"**3 packages audited** across 2 lockfiles",
		"**1 advisory** affecting **1 package**",
		"[MAL-2025-46969](https://osv.dev/vulnerability/MAL-2025-46969)",
		"no findings ✓",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown audit output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "`healthy`") {
		t.Errorf("finding-free package listed:\n%s", out)
	}
}

func TestAuditMarkdownNoFindings(t *testing.T) {
	diffs := []diffx.FileDiff{{Path: "go.mod", Ecosystem: "Go",
		Changes: []diffx.Change{{Name: "github.com/pkg/errors", Kind: diffx.Added, New: []string{"0.9.1"}}}}}
	var buf bytes.Buffer
	AuditMarkdown(&buf, diffs, diffx.Summarize(diffs), true, true, 7)
	if !strings.Contains(buf.String(), "No findings. 🎉") {
		t.Errorf("missing no-findings line:\n%s", buf.String())
	}
}

func TestSARIFAuditWording(t *testing.T) {
	diffs := auditDiffs()
	var buf bytes.Buffer
	if err := SARIFAudit(&buf, diffs, "test", nil); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "chalk is pinned at 5.6.1") {
		t.Errorf("audit SARIF should say \"is pinned at\":\n%s", out)
	}
	if strings.Contains(out, "was added at") {
		t.Errorf("audit SARIF should not use diff wording:\n%s", out)
	}
}
