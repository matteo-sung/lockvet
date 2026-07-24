package gtpr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/ghpr"
)

func TestPostCommentCreates(t *testing.T) {
	var posted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/o/r/issues/5/comments":
			fmt.Fprint(w, `[{"id":1,"body":"lgtm","html_url":"u1"}]`)
		case r.Method == "POST" && r.URL.Path == "/repos/o/r/issues/5/comments":
			if r.Header.Get("Authorization") != "token tok" {
				t.Errorf("missing Authorization header")
			}
			b, _ := io.ReadAll(r.Body)
			var m map[string]string
			json.Unmarshal(b, &m)
			posted = m["body"]
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":99,"html_url":"https://x/o/r/pulls/5#issuecomment-99"}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	ref := Ref{Host: "x", Owner: "o", Repo: "r", Index: 5}
	url, updated, err := testClient(srv, "tok").postComment(ref, "## report")
	if err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Error("want create, got update")
	}
	if url != "https://x/o/r/pulls/5#issuecomment-99" {
		t.Errorf("url = %q", url)
	}
	if !strings.HasPrefix(posted, ghpr.CommentMarker) || !strings.Contains(posted, "## report") {
		t.Errorf("posted body = %q", posted)
	}
}

func TestPostCommentUpdates(t *testing.T) {
	var patched string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/repos/o/r/issues/5/comments":
			fmt.Fprintf(w, `[{"id":1,"body":"lgtm"},{"id":2,"body":%q,"html_url":"u2"}]`,
				ghpr.CommentMarker+"\n\nold report")
		case r.Method == "PATCH" && r.URL.Path == "/repos/o/r/issues/comments/2":
			b, _ := io.ReadAll(r.Body)
			var m map[string]string
			json.Unmarshal(b, &m)
			patched = m["body"]
			fmt.Fprint(w, `{"id":2,"html_url":"u2"}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	ref := Ref{Host: "x", Owner: "o", Repo: "r", Index: 5}
	url, updated, err := testClient(srv, "tok").postComment(ref, "new report")
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Error("want update, got create")
	}
	if url != "u2" {
		t.Errorf("url = %q", url)
	}
	if !strings.Contains(patched, "new report") {
		t.Errorf("patched body = %q", patched)
	}
}

func TestPostCommentNeedsToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("no request expected without a token: %s %s", r.Method, r.URL)
	}))
	defer srv.Close()

	_, _, err := testClient(srv, "").postComment(Ref{Host: "x", Owner: "o", Repo: "r", Index: 5}, "b")
	if err == nil || !strings.Contains(err.Error(), "GITEA_TOKEN") {
		t.Fatalf("want token hint, got %v", err)
	}
}
