package glmr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/ghpr"
)

func testClient(srv *httptest.Server, token, jobToken string) *client {
	return &client{
		http:     &http.Client{Timeout: 5 * time.Second},
		base:     srv.URL + "/",
		token:    token,
		jobToken: jobToken,
	}
}

func TestPostCommentCreates(t *testing.T) {
	var posted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/projects/g%2Fp/merge_requests/5/notes") ||
			r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/projects/g/p/merge_requests/5/notes"):
			// system notes and unrelated notes must be skipped
			fmt.Fprintf(w, `[{"id":1,"body":%q,"system":true},{"id":2,"body":"lgtm","system":false}]`,
				ghpr.CommentMarker+" system-ish")
		case r.Method == "POST" && strings.Contains(r.URL.Path, "/merge_requests/5/notes"):
			if r.Header.Get("PRIVATE-TOKEN") != "tok" {
				t.Errorf("missing PRIVATE-TOKEN header")
			}
			b, _ := io.ReadAll(r.Body)
			var m map[string]string
			json.Unmarshal(b, &m)
			posted = m["body"]
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":99}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	ref := Ref{Host: "gitlab.example.org", Project: "g/p", IID: 5}
	url, updated, err := testClient(srv, "tok", "").postComment(ref, "## report")
	if err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Error("want create, got update")
	}
	if want := "https://gitlab.example.org/g/p/-/merge_requests/5#note_99"; url != want {
		t.Errorf("url = %q, want %q", url, want)
	}
	if !strings.HasPrefix(posted, ghpr.CommentMarker) || !strings.Contains(posted, "## report") {
		t.Errorf("posted body missing marker or report: %q", posted)
	}
}

func TestPostCommentUpdatesExisting(t *testing.T) {
	var put bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET":
			fmt.Fprintf(w, `[{"id":7,"body":%q,"system":false}]`, ghpr.CommentMarker+"\n\nold")
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/notes/7"):
			put = true
			fmt.Fprint(w, `{"id":7}`)
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	ref := Ref{Host: "gitlab.com", Project: "g/p", IID: 5}
	url, updated, err := testClient(srv, "tok", "").postComment(ref, "new")
	if err != nil {
		t.Fatal(err)
	}
	if !updated || !put {
		t.Errorf("want PUT update; updated=%v put=%v", updated, put)
	}
	if want := "https://gitlab.com/g/p/-/merge_requests/5#note_7"; url != want {
		t.Errorf("url = %q, want %q", url, want)
	}
}

func TestPostCommentTokenErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no request should be made without a usable token")
	}))
	defer srv.Close()

	ref := Ref{Host: "gitlab.com", Project: "g/p", IID: 5}

	_, _, err := testClient(srv, "", "").postComment(ref, "x")
	if err == nil || !strings.Contains(err.Error(), "GITLAB_TOKEN") {
		t.Errorf("want token error, got %v", err)
	}

	// A job token alone is not enough: the notes API rejects JOB-TOKEN auth.
	_, _, err = testClient(srv, "", "jobtok").postComment(ref, "x")
	if err == nil || !strings.Contains(err.Error(), "CI_JOB_TOKEN cannot post notes") {
		t.Errorf("want job-token hint, got %v", err)
	}
}
