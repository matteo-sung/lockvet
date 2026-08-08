package ansreg

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

func fakeGalaxy(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	const collBase = "/api/v3/plugin/ansible/content/published/collections/index/"
	mux.HandleFunc(collBase+"community/general/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case collBase + "community/general/":
			w.Write([]byte(`{"namespace":"community","name":"general","deprecated":false,
				"highest_version":{"version":"13.2.0"}}`))
		case collBase + "community/general/versions/13.2.0/":
			w.Write([]byte(`{"version":"13.2.0","created_at":"2026-08-06T20:08:50.245470Z",
				"metadata":{"repository":"https://github.com/ansible-collections/community.general"}}`))
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc(collBase+"community/kubevirt/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"deprecated":true,"highest_version":{"version":"1.1.0"}}`))
	})
	mux.HandleFunc(collBase+"community/kubevirt/versions/1.1.0/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"version":"1.1.0","created_at":"2023-05-08T20:27:29Z","metadata":{}}`))
	})
	mux.HandleFunc("/api/v1/roles/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/roles/10923/versions/" {
			// The full version list (the search summary is capped).
			// The live v1 API serves naive (offset-free) stamps;
			// keep one of each shape covered.
			w.Write([]byte(`{"count":2,"results":[
				{"name":"7.0.0","created":"2025-01-15T16:31:08.000000Z"},
				{"name":"6.1.0","created":"2023-04-01T05:00:00.123456"}]}`))
			return
		}
		if r.URL.Query().Get("namespace") == "geerlingguy" && r.URL.Query().Get("name") == "docker" {
			w.Write([]byte(`{"count":1,"results":[{"id":10923,"github_user":"geerlingguy","github_repo":"ansible-role-docker",
				"summary_fields":{"versions":[
					{"name":"7.0.0","release_date":"2025-01-15T10:31:08-06:00"}]}}]}`))
			return
		}
		w.Write([]byte(`{"count":0,"results":[]}`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func setup(t *testing.T) {
	t.Helper()
	srv := fakeGalaxy(t)
	oldBase, oldNow := BaseURL, Now
	BaseURL = srv.URL
	Now = func() time.Time { return time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { BaseURL, Now = oldBase, oldNow })
}

func change(eco, name string, newV ...string) diffx.FileDiff {
	return diffx.FileDiff{Changes: []diffx.Change{{
		Name: name, Ecosystem: eco, New: newV,
	}}}
}

func TestAnnotateCollection(t *testing.T) {
	setup(t)
	diffs := []diffx.FileDiff{change("Ansible Galaxy", "community.general", "13.2.0")}
	ok, err := Annotate(diffs, 3)
	if err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 1 || !c.Fresh {
		t.Errorf("age=%d fresh=%v, want 1/true", c.AgeDays, c.Fresh)
	}
	if c.SourceRepo != "https://github.com/ansible-collections/community.general" {
		t.Errorf("SourceRepo = %q", c.SourceRepo)
	}
	if c.Unlisted || c.Deprecated {
		t.Errorf("unexpected flags: unlisted=%v deprecated=%v", c.Unlisted, c.Deprecated)
	}
}

func TestAnnotateDeprecatedCollection(t *testing.T) {
	setup(t)
	diffs := []diffx.FileDiff{change("Ansible Galaxy", "community.kubevirt", "1.1.0")}
	if ok, err := Annotate(diffs, 3); err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated || c.DeprecatedReason == "" {
		t.Errorf("deprecated=%v reason=%q", c.Deprecated, c.DeprecatedReason)
	}
}

func TestAnnotateUnlistedCollection(t *testing.T) {
	setup(t)
	diffs := []diffx.FileDiff{change("Ansible Galaxy", "community.general", "99.9.9")}
	if ok, err := Annotate(diffs, 3); err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "99.9.9" {
		t.Errorf("unlisted=%v versions=%v", c.Unlisted, c.UnlistedVersions)
	}
}

func TestAnnotateUnknownCollectionNoClaims(t *testing.T) {
	setup(t)
	diffs := []diffx.FileDiff{change("Ansible Galaxy", "nosuch.thing", "1.0.0")}
	ok, err := Annotate(diffs, 3)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("unknown collection should not count as checked")
	}
	c := diffs[0].Changes[0]
	if c.Unlisted || c.Deprecated || c.AgeDays != 0 {
		t.Errorf("unknown collection got claims: %+v", c)
	}
}

func TestAnnotateRole(t *testing.T) {
	setup(t)
	diffs := []diffx.FileDiff{change("Ansible Galaxy role", "geerlingguy.docker", "7.0.0")}
	if ok, err := Annotate(diffs, 3); err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	c := diffs[0].Changes[0]
	if c.PublishedAt != "2025-01-15T16:31:08Z" {
		t.Errorf("PublishedAt = %q", c.PublishedAt)
	}
	if c.SourceRepo != "https://github.com/geerlingguy/ansible-role-docker" {
		t.Errorf("SourceRepo = %q", c.SourceRepo)
	}
	if c.Unlisted {
		t.Error("roles must never flag unlisted")
	}
}

func TestAnnotateRoleNaiveTimestamp(t *testing.T) {
	setup(t)
	// The live v1 versions endpoint serves offset-free stamps
	// (2023-04-01T05:00:00.123456); they must parse as UTC.
	diffs := []diffx.FileDiff{change("Ansible Galaxy role", "geerlingguy.docker", "6.1.0")}
	if ok, err := Annotate(diffs, 3); err != nil || !ok {
		t.Fatalf("Annotate = %v, %v", ok, err)
	}
	if got := diffs[0].Changes[0].PublishedAt; got != "2023-04-01T05:00:00Z" {
		t.Errorf("PublishedAt = %q, want naive stamp parsed as UTC", got)
	}
}

func TestAnnotateRoleAbsentVersionQuiet(t *testing.T) {
	setup(t)
	// 8.0.0 is not in the fake index (owner never re-imported): ages
	// only, no absence claims.
	diffs := []diffx.FileDiff{change("Ansible Galaxy role", "geerlingguy.docker", "8.0.0")}
	if _, err := Annotate(diffs, 3); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if c.Unlisted || c.PublishedAt != "" {
		t.Errorf("stale role index made claims: %+v", c)
	}
}

func TestNonRegistrySkipped(t *testing.T) {
	setup(t)
	d := change("Ansible Galaxy", "community.general", "13.2.0")
	d.Changes[0].NonRegistry = true
	ok, err := Annotate([]diffx.FileDiff{d}, 3)
	if err != nil || ok {
		t.Fatalf("NonRegistry should be skipped entirely: %v %v", ok, err)
	}
}

func TestLatest(t *testing.T) {
	setup(t)
	if v, err := Latest("community.general"); err != nil || v != "13.2.0" {
		t.Errorf("collection latest = %q, %v", v, err)
	}
	if v, err := Latest("geerlingguy.docker"); err != nil || v != "7.0.0" {
		t.Errorf("role latest = %q, %v", v, err)
	}
	if _, err := Latest("nosuch.thing"); err == nil {
		t.Error("unknown name should error")
	}
}
