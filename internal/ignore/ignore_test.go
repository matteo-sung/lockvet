package ignore

import (
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/vers"
)

var now = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

func mkDiffs() []diffx.FileDiff {
	return []diffx.FileDiff{{
		Path: "package-lock.json", Kind: "package-lock.json", Ecosystem: "npm",
		Changes: []diffx.Change{
			{
				Name: "lodash", Kind: diffx.Upgraded, Old: []string{"4.17.20"}, New: []string{"4.17.21"},
				Level: vers.Patch, Fresh: true,
				IntroducedVulns: []diffx.Vuln{{ID: "GHSA-35jh-r3h4-6jhm"}, {ID: "GHSA-aaaa-bbbb-cccc"}},
			},
			{
				Name: "react", Kind: diffx.Upgraded, Old: []string{"18.3.1"}, New: []string{"19.0.0"},
				Level: vers.Major, LicenseChanged: true, OldLicense: "MIT", NewLicense: "BSD",
			},
			{
				Name: "@scope/pkg", Kind: diffx.Downgraded, Old: []string{"2.0.0"}, New: []string{"1.9.0"},
				Level: vers.Major, Unlisted: true, UnlistedVersions: []string{"1.9.0"},
			},
		},
	}}
}

func apply(t *testing.T, content string) ([]diffx.FileDiff, int, []string, diffx.Summary) {
	t.Helper()
	s, err := Parse(".lockvetignore", content)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	d := mkDiffs()
	n, warns := s.Apply(d, now)
	return d, n, warns, diffx.Summarize(d)
}

func TestAdvisoryID(t *testing.T) {
	d, n, _, sum := apply(t, "GHSA-35jh-r3h4-6jhm  # accepted, no fix upstream\n")
	if n != 1 {
		t.Fatalf("n=%d", n)
	}
	c := d[0].Changes[0]
	if len(c.IntroducedVulns) != 1 || c.IntroducedVulns[0].ID != "GHSA-aaaa-bbbb-cccc" {
		t.Fatalf("wrong vuln kept: %+v", c.IntroducedVulns)
	}
	if len(c.IgnoredVulns) != 1 || c.IgnoredVulns[0].ID != "GHSA-35jh-r3h4-6jhm" {
		t.Fatalf("wrong vuln ignored: %+v", c.IgnoredVulns)
	}
	if sum.VulnsIntroduced != 1 || sum.Ignored != 1 {
		t.Fatalf("sum: %+v", sum)
	}
	if !c.Fresh {
		t.Fatal("advisory rule must not touch other findings")
	}
}

func TestAdvisoryIDCaseInsensitive(t *testing.T) {
	_, n, _, _ := apply(t, "ghsa-35jh-r3h4-6jhm\n")
	if n != 1 {
		t.Fatalf("n=%d", n)
	}
}

func TestBarePackageIgnoresEverything(t *testing.T) {
	d, n, _, sum := apply(t, "lodash\n")
	c := d[0].Changes[0]
	if n != 3 { // two vulns + fresh
		t.Fatalf("n=%d", n)
	}
	if len(c.IntroducedVulns) != 0 || c.Fresh {
		t.Fatalf("not suppressed: %+v", c)
	}
	if sum.VulnsIntroduced != 0 || sum.Fresh != 0 || sum.Ignored != 3 {
		t.Fatalf("sum: %+v", sum)
	}
}

func TestKindScoped(t *testing.T) {
	d, _, _, sum := apply(t, "fresh:lodash\n")
	c := d[0].Changes[0]
	if c.Fresh {
		t.Fatal("fresh not suppressed")
	}
	if len(c.IntroducedVulns) != 2 {
		t.Fatal("vulns must survive a fresh: rule")
	}
	if sum.Fresh != 0 || sum.VulnsIntroduced != 2 {
		t.Fatalf("sum: %+v", sum)
	}
}

func TestVersionScoped(t *testing.T) {
	// Wrong version: nothing suppressed.
	_, n, _, _ := apply(t, "lodash@4.17.99\n")
	if n != 0 {
		t.Fatalf("n=%d", n)
	}
	_, n, _, _ = apply(t, "lodash@4.17.21\n")
	if n != 3 {
		t.Fatalf("n=%d", n)
	}
}

func TestScopedNpmName(t *testing.T) {
	d, n, _, sum := apply(t, "unlisted:@scope/pkg\n")
	if n != 1 || d[0].Changes[2].Unlisted {
		t.Fatalf("n=%d unlisted=%v", n, d[0].Changes[2].Unlisted)
	}
	if sum.Unlisted != 0 {
		t.Fatalf("sum: %+v", sum)
	}
}

func TestMajorAndDowngradeGateOnly(t *testing.T) {
	d, _, _, sum := apply(t, "major:react\ndowngrade:@scope/pkg\n")
	if sum.Major != 1 { // react's major ignored; @scope/pkg's major still counted
		t.Fatalf("major=%d", sum.Major)
	}
	if sum.Downgraded != 0 {
		t.Fatalf("downgraded=%d", sum.Downgraded)
	}
	// Display stays honest: the change keeps its level and kind.
	if d[0].Changes[1].Level != vers.Major || d[0].Changes[2].Kind != diffx.Downgraded {
		t.Fatal("level/kind must not be rewritten")
	}
}

func TestGlob(t *testing.T) {
	_, n, _, _ := apply(t, "license:re*\n")
	if n != 1 {
		t.Fatalf("n=%d", n)
	}
}

func TestUntilActiveAndExpired(t *testing.T) {
	// Active through the stated day.
	_, n, warns, _ := apply(t, "lodash until="+now.Format("2006-01-02")+"\n")
	if n != 3 || len(warns) != 0 {
		t.Fatalf("n=%d warns=%v", n, warns)
	}
	_, n, warns, _ = apply(t, "lodash until=2026-08-05\n")
	if n != 0 || len(warns) != 1 || !strings.Contains(warns[0], "expired 2026-08-05") {
		t.Fatalf("n=%d warns=%v", n, warns)
	}
}

func TestParseErrors(t *testing.T) {
	for _, bad := range []string{
		"lodash until=tomorrow\n",
		"lodash extra-token\n",
		"fresh: until=2026-01-01\n",
	} {
		if _, err := Parse("f", bad); err == nil {
			t.Fatalf("no error for %q", bad)
		}
	}
	// Unknown kind prefix is a package name, not an error (e.g. "npm:left-pad" alias styles).
	if _, err := Parse("f", "somepkg:with-colon\n"); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestCommentsAndBlanks(t *testing.T) {
	s, err := Parse("f", "\n# header\n  \nGHSA-x # trailing\n")
	if err != nil || len(s.Rules) != 1 {
		t.Fatalf("rules=%v err=%v", s.Rules, err)
	}
}

func TestNilSet(t *testing.T) {
	var s *Set
	d := mkDiffs()
	if n, w := s.Apply(d, now); n != 0 || w != nil {
		t.Fatal("nil set must be a no-op")
	}
}

func TestResolveMissingExplicit(t *testing.T) {
	if _, err := Resolve(t.TempDir()+"/nope", false, ""); err == nil {
		t.Fatal("explicit missing file must error")
	}
	// Missing default file is fine.
	s, err := Resolve("", false, t.TempDir())
	if err != nil || s != nil {
		t.Fatalf("s=%v err=%v", s, err)
	}
	// Disabled never reads.
	if s, _ := Resolve("", true, "."); s != nil {
		t.Fatal("disabled must return nil")
	}
}
