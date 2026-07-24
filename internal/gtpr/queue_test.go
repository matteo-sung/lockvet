package gtpr

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func queueSrv(t *testing.T, h http.HandlerFunc) *client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &client{
		http: srv.Client(),
		base: srv.URL + "/",
	}
}

func TestQueueOwnerFiltersClientSide(t *testing.T) {
	c := queueSrv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/issues/search" {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		for k, want := range map[string]string{
			"type": "pulls", "state": "open", "sort": "recentupdate", "owner": "forgejo",
		} {
			if got := q.Get(k); got != want {
				t.Errorf("query %s = %q, want %q", k, got, want)
			}
		}
		if q.Get("page") != "1" {
			w.Write([]byte("[]"))
			return
		}
		fmt.Fprint(w, `[
		 {"number":10,"title":"human PR","html_url":"https://x/o/r/pulls/10",
		  "updated_at":"2026-07-24T12:00:00Z","user":{"login":"alice"},
		  "repository":{"full_name":"forgejo/forgejo"}},
		 {"number":11,"title":"Update dep a","html_url":"https://x/o/r/pulls/11",
		  "updated_at":"2026-07-24T11:00:00Z","user":{"login":"Renovate-Bot"},
		  "repository":{"full_name":"forgejo/forgejo"}},
		 {"number":3,"title":"Update dep b","html_url":"https://x/o/d/pulls/3",
		  "updated_at":"2026-07-24T10:00:00Z","user":{"login":"dependabot"},
		  "repository":{"full_name":"forgejo/docs"}}
		]`)
	})
	items, err := c.queueOwner("git.example.org", "forgejo", []string{"renovate-bot", "dependabot"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2 (case-insensitive author filter): %+v", len(items), items)
	}
	if items[0].Ref.String() != "git.example.org/forgejo/forgejo#11" {
		t.Errorf("items[0].Ref = %s", items[0].Ref)
	}
	if items[1].Ref.Repo != "docs" || items[1].Ref.Index != 3 {
		t.Errorf("items[1].Ref = %+v", items[1].Ref)
	}
	if items[0].Author != "Renovate-Bot" || items[0].URL != "https://x/o/r/pulls/11" {
		t.Errorf("items[0] = %+v", items[0])
	}
}

func TestQueueOwnerAnyAuthorAndLimit(t *testing.T) {
	c := queueSrv(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `[
		 {"number":1,"title":"a","html_url":"u1","updated_at":"2026-07-24T12:00:00Z",
		  "user":{"login":"alice"},"repository":{"full_name":"o/r"}},
		 {"number":2,"title":"b","html_url":"u2","updated_at":"2026-07-24T11:00:00Z",
		  "user":{"login":"bob"},"repository":{"full_name":"o/r"}}
		]`)
	})
	items, err := c.queueOwner("h", "o", nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Ref.Index != 1 {
		t.Fatalf("items = %+v", items)
	}
}

func TestQueueRepoServerSideAuthor(t *testing.T) {
	var authorsSeen []string
	c := queueSrv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/repos/forgejo/forgejo/issues" {
			t.Errorf("unexpected path %s", r.URL.EscapedPath())
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if q.Get("type") != "pulls" || q.Get("state") != "open" || q.Get("sort") != "recentupdate" {
			t.Errorf("query = %s", r.URL.RawQuery)
		}
		author := q.Get("created_by")
		authorsSeen = append(authorsSeen, author)
		if author == "viceice-bot" {
			fmt.Fprint(w, `[
			 {"number":13596,"title":"Update setup-forgejo","html_url":"u",
			  "updated_at":"2026-07-24T19:58:00Z","user":{"login":"viceice-bot"}},
			 {"number":13594,"title":"Update postcss","html_url":"u2",
			  "updated_at":"2026-07-24T09:12:00Z","user":{"login":"viceice-bot"}}
			]`)
			return
		}
		fmt.Fprint(w, `[
		 {"number":42,"title":"Update x","html_url":"u3",
		  "updated_at":"2026-07-24T12:00:00Z","user":{"login":"other-bot"}}
		]`)
	})
	items, err := c.queueRepo("codeberg.org", "forgejo", "forgejo", []string{"viceice-bot", "other-bot"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(authorsSeen, ",") != "viceice-bot,other-bot" {
		t.Errorf("created_by seen = %v", authorsSeen)
	}
	if len(items) != 3 {
		t.Fatalf("got %d items: %+v", len(items), items)
	}
	// Merged and re-sorted most-recently-updated first.
	want := []int{13596, 42, 13594}
	for i, n := range want {
		if items[i].Ref.Index != n {
			t.Errorf("items[%d] = #%d, want #%d", i, items[i].Ref.Index, n)
		}
		if items[i].Ref.Owner != "forgejo" || items[i].Ref.Repo != "forgejo" || items[i].Ref.Host != "codeberg.org" {
			t.Errorf("items[%d].Ref = %+v", i, items[i].Ref)
		}
	}
	if !items[0].Updated.Equal(time.Date(2026, 7, 24, 19, 58, 0, 0, time.UTC)) {
		t.Errorf("items[0].Updated = %v", items[0].Updated)
	}
}

func TestQueueRepoMissingAuthorSkipped(t *testing.T) {
	// Gitea 404s the issue listing when created_by names a user that
	// doesn't exist on the instance; that must not fail the whole queue
	// when the repo itself is fine.
	c := queueSrv(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.EscapedPath() == "/repos/o/r" && r.URL.RawQuery == "":
			fmt.Fprint(w, `{"id":1}`)
		case r.URL.EscapedPath() == "/repos/o/r/issues" && r.URL.Query().Get("created_by") == "real-bot":
			fmt.Fprint(w, `[{"number":7,"title":"Update x","html_url":"u",
			 "updated_at":"2026-07-24T12:00:00Z","user":{"login":"real-bot"}}]`)
		default:
			http.NotFound(w, r)
		}
	})
	items, err := c.queueRepo("h", "o", "r", []string{"ghost-bot", "real-bot"}, 30)
	if err != nil {
		t.Fatalf("missing author should be skipped, got %v", err)
	}
	if len(items) != 1 || items[0].Ref.Index != 7 {
		t.Fatalf("items = %+v", items)
	}
}

func TestQueueNotFoundHints(t *testing.T) {
	c := queueSrv(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	if _, err := c.queueOwner("h", "nope", nil, 5); err == nil || !strings.Contains(err.Error(), "user or organization") {
		t.Errorf("owner 404 err = %v", err)
	}
	if _, err := c.queueRepo("h", "no", "pe", nil, 5); err == nil || !strings.Contains(err.Error(), "GITEA_TOKEN") {
		t.Errorf("repo 404 err = %v", err)
	}
}

func TestListQueueScopeParsing(t *testing.T) {
	if _, _, err := ListQueue("codeberg.org", "", nil, 5); err == nil {
		t.Error("empty scope should error")
	}
	if _, _, err := ListQueue("codeberg.org", "a/b/c", nil, 5); err == nil {
		t.Error("3-segment scope should error")
	}
}

func TestIsGiteaHostFastPaths(t *testing.T) {
	cases := map[string]bool{
		"codeberg.org":            true,
		"gitea.com":               true,
		"gitea.example.org":       true,
		"forgejo.example.org:443": true,
		"github.com":              false,
		"gitlab.com":              false,
		"bitbucket.org":           false,
		"gitlab.torproject.org":   false,
		"www.gitlab.example.com":  false,
	}
	for host, want := range cases {
		if got := IsGiteaHost(host); got != want {
			t.Errorf("IsGiteaHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestProbeGitea(t *testing.T) {
	gitea := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/version" {
			fmt.Fprint(w, `{"version":"1.22.0"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer gitea.Close()
	if !probeGitea(gitea.URL) {
		t.Error("version endpoint should be detected as Gitea")
	}

	authWalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer authWalled.Close()
	if !probeGitea(authWalled.URL) {
		t.Error("401 on /api/v1/version should be treated as Gitea")
	}

	gl := httptest.NewServer(http.HandlerFunc(http.NotFound))
	defer gl.Close()
	if probeGitea(gl.URL) {
		t.Error("404 should not be detected as Gitea")
	}
}
