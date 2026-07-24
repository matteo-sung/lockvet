package ghpr

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestSplitRepoURL(t *testing.T) {
	cases := []struct {
		in          string
		owner, repo string
		ok          bool
	}{
		{"https://api.github.com/repos/grafana/agent", "grafana", "agent", true},
		{"https://api.github.com/repos/a/b", "a", "b", true},
		{"https://api.github.com/repos/only-owner", "", "", false},
		{"https://example.com/nope", "", "", false},
	}
	for _, c := range cases {
		o, r, ok := splitRepoURL(c.in)
		if o != c.owner || r != c.repo || ok != c.ok {
			t.Errorf("splitRepoURL(%q) = %q,%q,%v; want %q,%q,%v", c.in, o, r, ok, c.owner, c.repo, c.ok)
		}
	}
}

func TestListQueue(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/users/grafana":
			fmt.Fprint(w, `{"type":"Organization"}`)
		case "/search/issues":
			gotQuery = r.URL.Query().Get("q")
			fmt.Fprint(w, `{"total_count":2,"items":[
				{"number":7,"title":"bump a","html_url":"https://github.com/grafana/agent/pull/7",
				 "updated_at":"2026-07-01T00:00:00Z",
				 "repository_url":"https://api.github.com/repos/grafana/agent",
				 "user":{"login":"dependabot[bot]"},"pull_request":{}},
				{"number":9,"title":"not a PR","html_url":"x","updated_at":"2026-07-01T00:00:00Z",
				 "repository_url":"https://api.github.com/repos/grafana/agent",
				 "user":{"login":"someone"}}
			]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := testClient(srv, "tok")

	items, qual, err := c.listQueue("grafana", DefaultQueueAuthors, 30)
	if err != nil {
		t.Fatal(err)
	}
	if qual != "org:grafana" {
		t.Errorf("qual = %q, want org:grafana", qual)
	}
	if len(items) != 1 { // the issue without pull_request is dropped
		t.Fatalf("got %d items, want 1", len(items))
	}
	it := items[0]
	if it.Ref.String() != "grafana/agent#7" || it.Author != "dependabot[bot]" {
		t.Errorf("unexpected item: %+v", it)
	}
	want := "is:pr is:open archived:false org:grafana author:app/dependabot author:app/renovate"
	if gotQuery != want {
		t.Errorf("query = %q, want %q", gotQuery, want)
	}

	// repo scope needs no account lookup and uses repo: qualifier
	if _, qual, err = c.listQueue("grafana/agent", nil, 5); err != nil {
		t.Fatal(err)
	} else if qual != "repo:grafana/agent" {
		t.Errorf("qual = %q, want repo:grafana/agent", qual)
	}
	if u, _ := url.QueryUnescape(gotQuery); u != gotQuery {
		t.Errorf("query double-escaped: %q", gotQuery)
	}
}
