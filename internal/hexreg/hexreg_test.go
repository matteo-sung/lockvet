package hexreg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// fakeHex serves package documents under /api/packages/. Missing names
// 404.
func fakeHex(t *testing.T, docs map[string]string) func() {
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
	return diffx.FileDiff{Path: "mix.lock", Changes: []diffx.Change{{
		Name: name, Ecosystem: "Hex", Kind: diffx.Changed,
		Old: []string{from}, New: []string{to},
	}}}
}

func ts(age time.Duration) string {
	return time.Now().UTC().Add(-age).Format("2006-01-02T15:04:05.000000Z")
}

func doc(releases, retirements, links string) string {
	return fmt.Sprintf(`{"releases":[%s],"retirements":{%s},"meta":{"links":{%s}}}`,
		releases, retirements, links)
}

func TestAgesFreshAndSource(t *testing.T) {
	defer fakeHex(t, map[string]string{
		"jason": doc(
			fmt.Sprintf(`{"version":"1.4.4","inserted_at":%q},{"version":"1.4.0","inserted_at":%q}`,
				ts(3*24*time.Hour), ts(400*24*time.Hour)),
			"",
			`"GitHub":"https://github.com/michalmuskala/jason"`),
	})()
	diffs := []diffx.FileDiff{bump("jason", "1.4.0", "1.4.4")}
	checked, err := Annotate(diffs, 7)
	if err != nil || !checked {
		t.Fatalf("Annotate: checked=%v err=%v", checked, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 3 || !c.Fresh {
		t.Errorf("age/fresh = %d/%v, want 3/true", c.AgeDays, c.Fresh)
	}
	if c.SourceRepo != "https://github.com/michalmuskala/jason" {
		t.Errorf("SourceRepo = %q", c.SourceRepo)
	}
	if c.Unlisted {
		t.Errorf("listed version flagged unlisted")
	}
}

func TestRetirementIsDeprecation(t *testing.T) {
	defer fakeHex(t, map[string]string{
		"httpotion": doc(
			`{"version":"3.1.3","inserted_at":"2019-08-18T10:52:07.380651Z"},{"version":"3.1.2","inserted_at":"2018-05-01T00:00:00.000000Z"}`,
			`"3.1.3":{"reason":"deprecated","message":"Not really maintained, please check out Tesla"}`,
			""),
	})()
	diffs := []diffx.FileDiff{bump("httpotion", "3.1.2", "3.1.3")}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated {
		t.Fatal("retired incoming version not deprecated")
	}
	want := "retired: deprecated — Not really maintained, please check out Tesla"
	if c.DeprecatedReason != want {
		t.Errorf("reason = %q, want %q", c.DeprecatedReason, want)
	}

	// A removal of a retired version is good news, never flagged.
	diffs = []diffx.FileDiff{{Path: "mix.lock", Changes: []diffx.Change{{
		Name: "httpotion", Ecosystem: "Hex", Kind: diffx.Removed, Old: []string{"3.1.3"},
	}}}}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Deprecated {
		t.Error("removal flagged deprecated")
	}
}

func TestUnlistedOnlyWhenPackageKnown(t *testing.T) {
	defer fakeHex(t, map[string]string{
		"jason": doc(`{"version":"1.4.4","inserted_at":"2024-01-01T00:00:00.000000Z"}`, "", ""),
	})()
	diffs := []diffx.FileDiff{
		bump("jason", "1.4.4", "9.9.9"),       // known package, unknown version → flag
		bump("private_pkg", "1.0.0", "1.0.1"), // unknown package → never flag
	}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "9.9.9" {
		t.Errorf("unlisted = %v %v, want true [9.9.9]", c.Unlisted, c.UnlistedVersions)
	}
	if diffs[1].Changes[0].Unlisted {
		t.Error("package unknown to hex.pm flagged unlisted")
	}
}

func TestNonRegistryAndOtherEcosystemsSkipped(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.NotFound(w, r)
	}))
	defer srv.Close()
	old := BaseURL
	BaseURL = srv.URL
	defer func() { BaseURL = old }()

	diffs := []diffx.FileDiff{{Path: "mix.lock", Changes: []diffx.Change{
		{Name: "fork_pkg", Ecosystem: "Hex", Kind: diffx.Changed, Old: []string{"1.0.0"}, New: []string{"1.0.1"}, NonRegistry: true},
		{Name: "lodash", Ecosystem: "npm", Kind: diffx.Changed, Old: []string{"4.0.0"}, New: []string{"4.0.1"}},
	}}}
	checked, err := Annotate(diffs, 7)
	if err != nil || checked {
		t.Fatalf("checked=%v err=%v, want false nil", checked, err)
	}
	if requests != 0 {
		t.Errorf("made %d requests for skippable changes", requests)
	}
}

func TestRateLimitSurfacesHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	old := BaseURL
	BaseURL = srv.URL
	defer func() { BaseURL = old }()

	diffs := []diffx.FileDiff{bump("jason", "1.4.0", "1.4.4")}
	_, err := Annotate(diffs, 7)
	if err == nil || !strings.Contains(err.Error(), "HEX_API_KEY") {
		t.Fatalf("err = %v, want HEX_API_KEY hint", err)
	}
}

func TestRetirementReasonWording(t *testing.T) {
	for _, tc := range []struct {
		r    retirement
		want string
	}{
		{retirement{Reason: "security", Message: "backdoored"}, "retired: security issue — backdoored"},
		{retirement{Reason: "invalid"}, "retired: release is broken"},
		{retirement{Reason: "renamed", Message: "now called tesla"}, "retired: renamed — now called tesla"},
		{retirement{Reason: "other"}, "retired"},
		{retirement{}, "retired"},
	} {
		if got := retirementReason(tc.r); got != tc.want {
			t.Errorf("retirementReason(%+v) = %q, want %q", tc.r, got, tc.want)
		}
	}
}

func TestSourceFromLinks(t *testing.T) {
	for _, tc := range []struct {
		links map[string]string
		want  string
	}{
		{map[string]string{"GitHub": "https://github.com/a/b"}, "https://github.com/a/b"},
		{map[string]string{"github": "https://github.com/a/b.git"}, "https://github.com/a/b"},
		{map[string]string{"Website": "https://hexdocs.pm/x", "Repository": "https://gitlab.com/a/b/"}, "https://gitlab.com/a/b"},
		// Non-repo-flavoured key still wins when it's the only repo URL.
		{map[string]string{"Sponsor": "https://github.com/a/b"}, "https://github.com/a/b"},
		// Deep paths (org pages, trees) are not repos.
		{map[string]string{"GitHub": "https://github.com/a/b/tree/main/pkg"}, ""},
		{map[string]string{"Docs": "https://hexdocs.pm/jason"}, ""},
	} {
		if got := sourceFromLinks(tc.links); got != tc.want {
			t.Errorf("sourceFromLinks(%v) = %q, want %q", tc.links, got, tc.want)
		}
	}
}
