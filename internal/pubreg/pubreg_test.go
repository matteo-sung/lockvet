package pubreg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// fakePub serves package documents under /api/packages/. Missing names
// 404.
func fakePub(t *testing.T, docs map[string]string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if name, ok := strings.CutPrefix(r.URL.Path, "/api/packages/"); ok {
			if doc, ok := docs[name]; ok {
				fmt.Fprint(w, doc)
				return
			}
		}
		http.NotFound(w, r)
	}))
	old := BaseURL
	BaseURL = srv.URL
	return func() { BaseURL = old; srv.Close() }
}

func bump(name, from, to string) diffx.FileDiff {
	return diffx.FileDiff{Path: "pubspec.lock", Changes: []diffx.Change{{
		Name: name, Ecosystem: "Pub", Kind: diffx.Changed,
		Old: []string{from}, New: []string{to},
	}}}
}

func ts(age time.Duration) string {
	return time.Now().UTC().Add(-age).Format("2006-01-02T15:04:05.000000Z")
}

func doc(versions string, extra string) string {
	if extra != "" {
		extra = "," + extra
	}
	return fmt.Sprintf(`{"name":"x","latest":{"pubspec":{"repository":"https://github.com/dart-lang/http/tree/master/pkgs/http"}},"versions":[%s]%s}`,
		versions, extra)
}

func TestAgesFreshAndMonorepoSource(t *testing.T) {
	defer fakePub(t, map[string]string{
		"http": doc(
			fmt.Sprintf(`{"version":"1.5.0","published":%q},{"version":"1.2.0","published":%q}`,
				ts(3*24*time.Hour), ts(400*24*time.Hour)), ""),
	})()
	diffs := []diffx.FileDiff{bump("http", "1.2.0", "1.5.0")}
	checked, err := Annotate(diffs, 7)
	if err != nil || !checked {
		t.Fatalf("Annotate: checked=%v err=%v", checked, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 3 || !c.Fresh {
		t.Errorf("age/fresh = %d/%v, want 3/true", c.AgeDays, c.Fresh)
	}
	if c.SourceRepo != "https://github.com/dart-lang/http" {
		t.Errorf("SourceRepo = %q (monorepo path not stripped?)", c.SourceRepo)
	}
	if c.Unlisted {
		t.Errorf("listed version flagged unlisted")
	}
	if c.Deprecated {
		t.Errorf("healthy bump flagged deprecated")
	}
}

func TestDiscontinuedWithReplacement(t *testing.T) {
	defer fakePub(t, map[string]string{
		"pedantic": doc(
			`{"version":"1.11.1","published":"2021-06-01T00:00:00.000000Z"},{"version":"1.11.0","published":"2021-01-01T00:00:00.000000Z"}`,
			`"isDiscontinued":true,"replacedBy":"lints"`),
	})()
	diffs := []diffx.FileDiff{bump("pedantic", "1.11.0", "1.11.1")}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated {
		t.Fatal("discontinued package not deprecated")
	}
	want := "discontinued on pub.dev; replaced by lints"
	if c.DeprecatedReason != want {
		t.Errorf("reason = %q, want %q", c.DeprecatedReason, want)
	}
}

func TestRetractedVersionIsDeprecatedNotUnlisted(t *testing.T) {
	defer fakePub(t, map[string]string{
		"dio": doc(
			`{"version":"5.8.0","published":"2025-01-13T00:00:00.000000Z","retracted":true},{"version":"5.7.0","published":"2024-08-01T00:00:00.000000Z"}`,
			""),
	})()
	diffs := []diffx.FileDiff{bump("dio", "5.7.0", "5.8.0")}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated || c.DeprecatedReason != "version retracted by the publisher" {
		t.Errorf("retracted incoming version: Deprecated=%v reason=%q", c.Deprecated, c.DeprecatedReason)
	}
	if c.Unlisted {
		t.Errorf("retracted version stays listed on pub.dev; must not be unlisted")
	}
}

func TestRemovalNeverDeprecated(t *testing.T) {
	defer fakePub(t, map[string]string{
		"pedantic": doc(`{"version":"1.11.1","published":"2021-06-01T00:00:00.000000Z"}`,
			`"isDiscontinued":true`),
	})()
	diffs := []diffx.FileDiff{{Path: "pubspec.lock", Changes: []diffx.Change{{
		Name: "pedantic", Ecosystem: "Pub", Kind: diffx.Removed, Old: []string{"1.11.1"},
	}}}}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Deprecated {
		t.Errorf("removal flagged deprecated")
	}
}

func TestUnlistedOnlyWhenPackageKnown(t *testing.T) {
	defer fakePub(t, map[string]string{
		"args": doc(`{"version":"2.4.2","published":"2023-01-01T00:00:00.000000Z"}`, ""),
	})()
	diffs := []diffx.FileDiff{bump("args", "2.4.2", "9.9.9"), bump("no_such_pkg", "1.0.0", "1.0.1")}
	checked, err := Annotate(diffs, 7)
	if err != nil || !checked {
		t.Fatalf("checked=%v err=%v", checked, err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "9.9.9" {
		t.Errorf("unlisted = %v %v", c.Unlisted, c.UnlistedVersions)
	}
	if diffs[1].Changes[0].Unlisted {
		t.Errorf("package unknown to pub.dev must never be flagged")
	}
}

func TestNonRegistryAndOtherEcosystemsSkipped(t *testing.T) {
	defer fakePub(t, map[string]string{})() // any fetch would 404 → checked=false
	diffs := []diffx.FileDiff{
		{Path: "pubspec.lock", Changes: []diffx.Change{{
			Name: "local_pkg", Ecosystem: "Pub", Kind: diffx.Changed,
			Old: []string{"1.0.0"}, New: []string{"1.0.1"}, NonRegistry: true,
		}}},
		{Path: "package-lock.json", Changes: []diffx.Change{{
			Name: "left-pad", Ecosystem: "npm", Kind: diffx.Changed,
			Old: []string{"1.0.0"}, New: []string{"1.3.0"},
		}}},
	}
	checked, err := Annotate(diffs, 7)
	if err != nil {
		t.Fatal(err)
	}
	if checked {
		t.Errorf("nothing eligible, yet checked=true")
	}
}

func TestRepoURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://github.com/dart-lang/http/tree/master/pkgs/http", "https://github.com/dart-lang/http"},
		{"https://github.com/user/repo.git", "https://github.com/user/repo"},
		{"https://gitlab.com/group/repo", "https://gitlab.com/group/repo"},
		{"https://example.com/user/repo", ""},
		{"github.com/user/repo", ""},
	}
	for _, c := range cases {
		if got := repoURL(c.in); got != c.want {
			t.Errorf("repoURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := repoURL("", "https://github.com/x/y"); got != "https://github.com/x/y" {
		t.Errorf("homepage fallback = %q", got)
	}
}
