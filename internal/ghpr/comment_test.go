package ghpr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testClient(srv *httptest.Server, token string) *client {
	return &client{
		http:  &http.Client{Timeout: 5 * time.Second},
		api:   srv.URL + "/",
		token: token,
	}
}

func TestPostCommentCreates(t *testing.T) {
	var posted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/repos/o/r/issues/7/comments"):
			fmt.Fprint(w, `[{"id":1,"body":"unrelated","html_url":"x"}]`)
		case r.Method == "POST" && r.URL.Path == "/repos/o/r/issues/7/comments":
			b, _ := io.ReadAll(r.Body)
			var m map[string]string
			json.Unmarshal(b, &m)
			posted = m["body"]
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":2,"html_url":"https://example.com/c/2"}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	url, updated, err := testClient(srv, "tok").postComment(Ref{Owner: "o", Repo: "r", Number: 7}, "## report")
	if err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Error("want create, got update")
	}
	if url != "https://example.com/c/2" {
		t.Errorf("url = %q", url)
	}
	if !strings.HasPrefix(posted, CommentMarker) || !strings.Contains(posted, "## report") {
		t.Errorf("posted body missing marker or report: %q", posted)
	}
}

func TestPostCommentUpdatesExisting(t *testing.T) {
	var patchedID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/repos/o/r/issues/7/comments"):
			fmt.Fprintf(w, `[{"id":1,"body":"hi"},{"id":42,"body":%q}]`, CommentMarker+"\n\nold")
		case r.Method == "PATCH" && r.URL.Path == "/repos/o/r/issues/comments/42":
			patchedID = "42"
			fmt.Fprint(w, `{"id":42,"html_url":"https://example.com/c/42"}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	url, updated, err := testClient(srv, "tok").postComment(Ref{Owner: "o", Repo: "r", Number: 7}, "new")
	if err != nil {
		t.Fatal(err)
	}
	if !updated || patchedID != "42" {
		t.Errorf("want update of #42; updated=%v patched=%q", updated, patchedID)
	}
	if url != "https://example.com/c/42" {
		t.Errorf("url = %q", url)
	}
}

func TestPostCommentRequiresToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should be made without a token")
	}))
	defer srv.Close()

	_, _, err := testClient(srv, "").postComment(Ref{Owner: "o", Repo: "r", Number: 7}, "x")
	if err == nil || !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Errorf("want token error, got %v", err)
	}
}
