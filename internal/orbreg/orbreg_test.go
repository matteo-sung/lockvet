package orbreg

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

func fakeRegistry(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var q struct {
			Query string `json:"query"`
		}
		if err := json.Unmarshal(body, &q); err != nil {
			http.Error(w, "bad body", 400)
			return
		}
		switch {
		case strings.Contains(q.Query, `orb(name:"circleci/node")`):
			fmt.Fprint(w, `{"data":{"orb":{"versions":[
				{"version":"7.2.1","createdAt":"2026-08-01T17:50:48.733Z"},
				{"version":"7.2.0","createdAt":"2025-09-19T15:11:04.270Z"},
				{"version":"5.1.1","createdAt":"2023-06-01T00:00:00Z"},
				{"version":"5.1.0","createdAt":"2023-05-01T00:00:00Z"}]}}}`)
		case strings.Contains(q.Query, `orb(name:"ghost/nope")`):
			fmt.Fprint(w, `{"data":{"orb":null}}`)
		case strings.Contains(q.Query, `orbVersion(orbVersionRef:"circleci/node@7.2.1")`):
			fmt.Fprint(w, `{"data":{"orbVersion":{"source":"version: 2.1\ndescription: node\ndisplay:\n    home_url: https://nodejs.org/\n    source_url: https://github.com/circleci-public/node-orb\ncommands: {}\n"}}}`)
		case strings.Contains(q.Query, "orbVersion("):
			fmt.Fprint(w, `{"data":{"orbVersion":null}}`)
		default:
			fmt.Fprint(w, `{"data":{"orb":null}}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func setup(t *testing.T) {
	t.Helper()
	srv := fakeRegistry(t)
	oldURL, oldNow := BaseURL, Now
	BaseURL = srv.URL
	Now = func() time.Time { return time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC) }
	srcMemo.Range(func(k, _ any) bool { srcMemo.Delete(k); return true })
	t.Cleanup(func() { BaseURL, Now = oldURL, oldNow })
}

func TestAnnotateAges(t *testing.T) {
	setup(t)
	diffs := []diffx.FileDiff{{Path: ".circleci/config.yml", Changes: []diffx.Change{
		{Name: "circleci/node", Ecosystem: "CircleCI", Kind: diffx.Upgraded,
			Old: []string{"5.1.0"}, New: []string{"7.2.1"}},
	}}}
	ok, err := Annotate(diffs, 14)
	if err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 7 {
		t.Errorf("AgeDays = %d, want 7", c.AgeDays)
	}
	if !c.Fresh {
		t.Error("7-day-old release inside a 14-day window should be Fresh")
	}
	if c.SourceRepo != "https://github.com/circleci-public/node-orb" {
		t.Errorf("SourceRepo = %q", c.SourceRepo)
	}
	if c.Unlisted {
		t.Error("listed version must not be Unlisted")
	}
}

func TestAnnotateFloating(t *testing.T) {
	setup(t)
	diffs := []diffx.FileDiff{{Path: ".circleci/config.yml", Changes: []diffx.Change{
		{Name: "circleci/node", Ecosystem: "CircleCI", Kind: diffx.Added,
			New: []string{"volatile"}},
		{Name: "circleci/node", Ecosystem: "CircleCI", Kind: diffx.Added,
			New: []string{"5"}},
		{Name: "circleci/node", Ecosystem: "CircleCI", Kind: diffx.Added,
			New: []string{"5.1"}},
	}}}
	if ok, err := Annotate(diffs, 0); err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	want := []string{"7.2.1", "5.1.1", "5.1.1"}
	for i, w := range want {
		c := diffs[0].Changes[i]
		if c.ResolvedRefs[c.New[0]] != w {
			t.Errorf("pin %q resolved to %q, want %q", c.New[0], c.ResolvedRefs[c.New[0]], w)
		}
		if c.Unlisted {
			t.Errorf("floating pin %q must never be Unlisted", c.New[0])
		}
	}
}

func TestAnnotateUnlisted(t *testing.T) {
	setup(t)
	diffs := []diffx.FileDiff{{Path: ".circleci/config.yml", Changes: []diffx.Change{
		{Name: "circleci/node", Ecosystem: "CircleCI", Kind: diffx.Upgraded,
			Old: []string{"5.1.0"}, New: []string{"9.9.9"}},
	}}}
	if ok, err := Annotate(diffs, 0); err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "9.9.9" {
		t.Errorf("expected registry-verified unlisted 9.9.9, got %+v", c)
	}
}

func TestAnnotateUnknownOrbNoClaims(t *testing.T) {
	setup(t)
	diffs := []diffx.FileDiff{{Path: ".circleci/config.yml", Changes: []diffx.Change{
		{Name: "ghost/nope", Ecosystem: "CircleCI", Kind: diffx.Added, New: []string{"1.0.0"}},
	}}}
	ok, err := Annotate(diffs, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("an orb the registry answers null for verifies nothing")
	}
	if diffs[0].Changes[0].Unlisted {
		t.Error("null orb must make no unlisted claims")
	}
}

func TestLatest(t *testing.T) {
	setup(t)
	v, err := Latest("circleci/node")
	if err != nil || v != "7.2.1" {
		t.Errorf("Latest = %q, %v; want 7.2.1", v, err)
	}
	if _, err := Latest("ghost/nope"); err == nil {
		t.Error("Latest on a null orb should error")
	}
}
