package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const auditFixtureNPM = `{
  "name": "fix", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "fix", "version": "1.0.0", "dependencies": {"left-pad": "1.3.0"}},
    "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
  }
}`

func writeAuditFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	sub := filepath.Join(dir, "web")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/x\n\nrequire (\n\tgithub.com/pkg/errors v0.9.1\n)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "package-lock.json"), []byte(auditFixtureNPM), 0o644); err != nil {
		t.Fatal(err)
	}
	// Never descended into:
	nm := filepath.Join(sub, "node_modules", "dep")
	if err := os.MkdirAll(nm, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nm, "package-lock.json"), []byte(auditFixtureNPM), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDiscoverLockfiles(t *testing.T) {
	dir := writeAuditFixture(t)
	files, err := discoverLockfiles([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("want 2 lockfiles (node_modules skipped), got %v", files)
	}
	for _, f := range files {
		if strings.Contains(f, "node_modules") {
			t.Fatalf("descended into node_modules: %s", f)
		}
	}
}

func TestVetAuditOffline(t *testing.T) {
	dir := writeAuditFixture(t)
	v, err := vetAudit(nil, dir, vetOptions{freshDays: 7, noVulns: true, noMeta: true})
	if err != nil {
		t.Fatal(err)
	}
	if !v.audit {
		t.Fatal("outcome not marked as audit")
	}
	if v.message != "" {
		t.Fatalf("unexpected message %q", v.message)
	}
	if len(v.diffs) != 2 {
		t.Fatalf("want 2 lockfiles audited, got %d", len(v.diffs))
	}
	if v.sum.Total != 2 || v.sum.Added != 2 {
		t.Fatalf("want 2 packages, all Added; got %+v", v.sum)
	}
	if len(v.contents) != 2 {
		t.Fatalf("want raw contents for 2 lockfiles (SARIF anchoring), got %d", len(v.contents))
	}
}

func TestVetAuditOnlyFilterMessage(t *testing.T) {
	dir := writeAuditFixture(t)
	v, err := vetAudit(nil, dir, vetOptions{only: "no-such-package", freshDays: 7, noVulns: true, noMeta: true})
	if err != nil {
		t.Fatal(err)
	}
	if v.message == "" || !strings.Contains(v.message, "pinned in total") {
		t.Fatalf("want audit-flavoured only-filter message, got %q", v.message)
	}
}

func TestVetAuditNoLockfiles(t *testing.T) {
	v, err := vetAudit(nil, t.TempDir(), vetOptions{freshDays: 7, noVulns: true, noMeta: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(v.message, "no lockfiles found") {
		t.Fatalf("got %q", v.message)
	}
}

func TestVetAuditExplicitFileParseError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(p, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := vetAudit([]string{p}, ".", vetOptions{noVulns: true, noMeta: true}); err == nil {
		t.Fatal("want parse error for explicitly named file")
	}
}
