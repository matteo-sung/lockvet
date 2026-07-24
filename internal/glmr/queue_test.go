package glmr

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListQueueProjectThenGroup(t *testing.T) {
	var authorsSeen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorsSeen = append(authorsSeen, r.URL.Query().Get("author_username"))
		switch r.URL.EscapedPath() {
		case "/projects/gitlab-org%2Fgitlab/merge_requests", // EscapedPath keeps %2F
			"/projects/gitlab-org/gitlab/merge_requests":
			fmt.Fprint(w, `[
				{"iid":42,"title":"Update dependency foo to v2","web_url":"https://gitlab.com/gitlab-org/gitlab/-/merge_requests/42",
				 "updated_at":"2026-07-02T00:00:00Z","author":{"username":"renovate-bot"},
				 "references":{"full":"gitlab-org/gitlab!42"}}]`)
		default:
			http.Error(w, `{"message":"404 Not Found"}`, 404)
		}
	}))
	defer srv.Close()
	c := testClient(srv, "", "")

	items, err := c.listQueueIn("projects", "gitlab-org/gitlab", []string{"renovate-bot", "dependabot"}, 30)
	if err != nil {
		t.Fatalf("listQueueIn: %v", err)
	}
	// one MR per author query; the stub returns the same MR twice — that's
	// fine, real author filters are disjoint.
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2 (one per author query)", len(items))
	}
	it := items[0]
	if it.Ref.Project != "gitlab-org/gitlab" || it.Ref.IID != 42 {
		t.Errorf("Ref = %+v", it.Ref)
	}
	if it.Author != "renovate-bot" || it.Title != "Update dependency foo to v2" {
		t.Errorf("item = %+v", it)
	}
	if len(authorsSeen) != 2 || authorsSeen[0] != "renovate-bot" || authorsSeen[1] != "dependabot" {
		t.Errorf("author queries = %v", authorsSeen)
	}
}

func TestListQueueGroupRefFromReferences(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("non_archived") != "true" {
			t.Errorf("group query missing non_archived=true: %s", r.URL.RawQuery)
		}
		fmt.Fprint(w, `[
			{"iid":7,"title":"bump x","web_url":"https://gitlab.com/gitlab-org/charts/gitlab/-/merge_requests/7",
			 "updated_at":"2026-07-03T00:00:00Z","author":{"username":"dependabot"},
			 "references":{"full":"gitlab-org/charts/gitlab!7"}}]`)
	}))
	defer srv.Close()
	c := testClient(srv, "", "")

	items, err := c.listQueueIn("groups", "gitlab-org", []string{"dependabot"}, 30)
	if err != nil {
		t.Fatalf("listQueueIn: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1", len(items))
	}
	if items[0].Ref.Project != "gitlab-org/charts/gitlab" {
		t.Errorf("subgroup project not taken from references.full: %+v", items[0].Ref)
	}
}

func TestListQueueEmptyAuthorsSinglePass(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Has("author_username") {
			t.Errorf("unexpected author filter: %s", r.URL.RawQuery)
		}
		fmt.Fprint(w, `[]`)
	}))
	defer srv.Close()
	c := testClient(srv, "", "")
	if _, err := c.listQueueIn("groups", "g", nil, 10); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}
