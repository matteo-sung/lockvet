package bbpr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func commentBody(t *testing.T, r *http.Request) string {
	t.Helper()
	b, _ := io.ReadAll(r.Body)
	var m struct {
		Content struct {
			Raw string `json:"raw"`
		} `json:"content"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("bad payload: %v", err)
	}
	return m.Content.Raw
}

func TestPostCommentCreates(t *testing.T) {
	var posted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repositories/ws/repo/pullrequests/5/comments":
			// unrelated and deleted comments must be skipped
			fmt.Fprintf(w, `{"values":[
				{"id":1,"content":{"raw":"lgtm"}},
				{"id":2,"deleted":true,"content":{"raw":%q}}
			]}`, marker+" old deleted report")
		case r.Method == "POST" && r.URL.Path == "/repositories/ws/repo/pullrequests/5/comments":
			if r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("missing bearer token, got %q", r.Header.Get("Authorization"))
			}
			posted = commentBody(t, r)
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":99,"links":{"html":{"href":"https://bitbucket.org/ws/repo/pull-requests/5#comment-99"}}}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := testClient(srv, "tok")
	url, updated, err := c.postComment(Ref{Workspace: "ws", Repo: "repo", ID: 5}, marker+"\n\nhello")
	if err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Fatal("must create, not update")
	}
	if !strings.Contains(url, "#comment-99") {
		t.Fatalf("bad url: %s", url)
	}
	if !strings.HasPrefix(posted, marker) {
		t.Fatalf("posted comment must start with the report heading: %q", posted)
	}
}

func TestPostCommentUpdates(t *testing.T) {
	var put string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repositories/ws/repo/pullrequests/5/comments":
			fmt.Fprintf(w, `{"values":[{"id":42,"content":{"raw":%q}}]}`, marker+"\n\nold report")
		case r.Method == "PUT" && r.URL.Path == "/repositories/ws/repo/pullrequests/5/comments/42":
			put = commentBody(t, r)
			fmt.Fprint(w, `{"id":42,"links":{"html":{"href":"https://bitbucket.org/ws/repo/pull-requests/5#comment-42"}}}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	c := testClient(srv, "tok")
	_, updated, err := c.postComment(Ref{Workspace: "ws", Repo: "repo", ID: 5}, marker+"\n\nnew report")
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("must update the existing comment")
	}
	if !strings.Contains(put, "new report") {
		t.Fatalf("update payload wrong: %q", put)
	}
}

func TestPostCommentNeedsAuth(t *testing.T) {
	c := &client{api: "https://api.bitbucket.org/2.0/"}
	if _, _, err := c.postComment(Ref{Workspace: "w", Repo: "r", ID: 1}, "x"); err == nil ||
		!strings.Contains(err.Error(), "BITBUCKET_TOKEN") {
		t.Fatalf("want auth hint, got %v", err)
	}
}
