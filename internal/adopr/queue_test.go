package adopr

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func queueSrv(t *testing.T, h http.HandlerFunc) (*httptest.Server, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv, srv.Close
}

const adoPR = `{"pullRequestId":%d,"title":"%s","creationDate":"%s",
 "createdBy":{"displayName":"%s","uniqueName":"%s"},
 "repository":{"name":"%s"}}`

func TestListQueueProjectScope(t *testing.T) {
	srv, _ := queueSrv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proj/_apis/git/pullrequests" {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("searchCriteria.status"); got != "active" {
			t.Errorf("status = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"value":[%s,%s,%s],"count":3}`,
			fmt.Sprintf(adoPR, 40, "human work", "2026-07-24T12:00:00Z", "Alice", "alice@example.com", "app"),
			fmt.Sprintf(adoPR, 41, "Bump lodash", "2026-07-24T11:00:00Z", "Renovate Bot", "svc@example.com", "app"),
			fmt.Sprintf(adoPR, 42, "Bump requests", "2026-07-24T10:00:00Z", "dependabot[bot]", "", "my api"))
	})
	items, label, err := listQueueAt(srv.URL, "proj", "", []string{"dependabot", "renovate"}, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2 (loose author filter): %+v", len(items), items)
	}
	if items[0].Ref.ID != 41 || items[0].Author != "Renovate Bot" {
		t.Errorf("item 0 = %+v", items[0])
	}
	// Repo names with spaces must come back percent-encoded path segments.
	if items[1].Ref.Repo != "my%20api" {
		t.Errorf("repo = %q, want %q", items[1].Ref.Repo, "my%20api")
	}
	if !strings.Contains(items[1].URL, "/_git/my%20api/pullrequest/42") {
		t.Errorf("url = %q", items[1].URL)
	}
	if !strings.HasPrefix(label, "project:") {
		t.Errorf("label = %q", label)
	}
}

func TestListQueueRepoScope(t *testing.T) {
	srv, _ := queueSrv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proj/_apis/git/repositories/app/pullrequests" {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"value":[%s],"count":1}`,
			fmt.Sprintf(adoPR, 7, "Bump x", "2026-07-24T10:00:00Z", "Renovate Bot", "", "app"))
	})
	items, label, err := listQueueAt(srv.URL, "proj", "app", nil, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Ref.ID != 7 {
		t.Fatalf("items = %+v", items)
	}
	if !strings.HasPrefix(label, "repo:") {
		t.Errorf("label = %q", label)
	}
}

func TestListQueueNotFoundHint(t *testing.T) {
	srv, _ := queueSrv(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	_, _, err := listQueueAt(srv.URL, "nope", "", nil, 30)
	if err == nil || !strings.Contains(err.Error(), "check the project") {
		t.Fatalf("err = %v, want project hint", err)
	}
}

// listQueueAt is ListQueue with the instance pointed at a test server.
func listQueueAt(instance, project, repo string, authors []string, limit int) ([]QueueItem, string, error) {
	return ListQueue(instance, project, repo, authors, limit)
}
