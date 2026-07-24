package bbpr

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/ghpr"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in        string
		ok        bool
		workspace string
		repo      string
		id        int
	}{
		{"https://bitbucket.org/atlassian/aui/pull-requests/5394", true, "atlassian", "aui", 5394},
		{"bitbucket.org/atlassian/aui/pull-requests/5394", true, "atlassian", "aui", 5394},
		{"https://bitbucket.org/ws/repo.name/pull-requests/7/diff#chg", true, "ws", "repo.name", 7},
		{"https://bitbucket.org/ws/repo/pull-requests/0", false, "", "", 0}, // bad id
		{"https://github.com/owner/repo/pull/1", false, "", "", 0},          // GitHub URL
		{"owner/repo#123", false, "", "", 0},                                // GitHub shorthand
		{"https://gitlab.com/g/p/-/merge_requests/3", false, "", "", 0},     // GitLab URL
		{"https://bitbucket.org/ws/repo/pull-requests/", false, "", "", 0},  // no id
	}
	for _, c := range cases {
		ref, ok := Parse(c.in)
		if ok != c.ok {
			t.Errorf("Parse(%q) ok=%v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && (ref.Workspace != c.workspace || ref.Repo != c.repo || ref.ID != c.id) {
			t.Errorf("Parse(%q) = %+v, want %s/%s#%d", c.in, ref, c.workspace, c.repo, c.id)
		}
	}
}

func TestParseCompare(t *testing.T) {
	// Bitbucket order: SOURCE..DESTINATION (head..base).
	ref, ok := ParseCompare("https://bitbucket.org/ws/repo/branches/compare/feature..main")
	if !ok || ref.Head != "feature" || ref.Base != "main" || ref.Workspace != "ws" || ref.Repo != "repo" {
		t.Fatalf("compare url parse failed: %+v ok=%v", ref, ok)
	}
	// Bitbucket's own UI links use an encoded \r as the separator.
	ref, ok = ParseCompare("https://bitbucket.org/ws/repo/branches/compare/feature%2Fx%0Dmain")
	if !ok || ref.Head != "feature/x" || ref.Base != "main" {
		t.Fatalf("%%0D compare parse failed: %+v ok=%v", ref, ok)
	}
	if _, ok := ParseCompare("https://github.com/a/b/compare/x...y"); ok {
		t.Fatal("github compare url must not parse as bitbucket")
	}
	if _, ok := ParseCompare("https://bitbucket.org/ws/repo/branches/compare/onlyone"); ok {
		t.Fatal("spec without separator must not parse")
	}
}

func TestParseCommit(t *testing.T) {
	w, r, sha, ok := ParseCommit("https://bitbucket.org/atlassian/aui/commits/8c4205a86de7")
	if !ok || w != "atlassian" || r != "aui" || sha != "8c4205a86de7" {
		t.Fatalf("commit url parse failed: %s %s %s ok=%v", w, r, sha, ok)
	}
	if _, _, _, ok := ParseCommit("https://bitbucket.org/w/r/commits/nothex"); ok {
		t.Fatal("non-hex sha must not parse")
	}
}

func testClient(srv *httptest.Server, token string) *client {
	return &client{
		http:  &http.Client{Timeout: 5 * time.Second},
		api:   srv.URL + "/",
		token: token,
	}
}

func TestFetch(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repositories/ws/repo/pullrequests/7":
			fmt.Fprintf(w, `{"title":"bump deps",
				"source":{"branch":{"name":"renovate/all"}},
				"destination":{"branch":{"name":"main"},"repository":{"full_name":"ws/repo"}}}`)
		case "/repositories/ws/repo/pullrequests/7/diffstat":
			if r.URL.Query().Get("page") == "2" {
				fmt.Fprint(w, `{"values":[]}`)
				return
			}
			// page 1 → next page, like the real API
			fmt.Fprintf(w, `{"values":[
				{"status":"modified",
				 "old":{"path":"yarn.lock","links":{"self":{"href":"%s/raw/base/yarn.lock"}}},
				 "new":{"path":"yarn.lock","links":{"self":{"href":"%s/raw/head/yarn.lock"}}}},
				{"status":"modified",
				 "old":{"path":"README.md","links":{"self":{"href":"%s/raw/base/README.md"}}},
				 "new":{"path":"README.md","links":{"self":{"href":"%s/raw/head/README.md"}}}}
			],"next":"%s/repositories/ws/repo/pullrequests/7/diffstat?page=2"}`,
				srv.URL, srv.URL, srv.URL, srv.URL, srv.URL)
		case "/repositories/ws/repo/pullrequests/7/diffstat/": // never hit
			w.WriteHeader(500)
		default:
			switch {
			case r.URL.Path == "/repositories/ws/repo/pullrequests/7/diffstat" && r.URL.Query().Get("page") == "2":
				fmt.Fprint(w, `{"values":[]}`)
			case r.URL.Query().Get("page") == "2":
				fmt.Fprint(w, `{"values":[]}`)
			case r.URL.Path == "/raw/base/yarn.lock":
				fmt.Fprint(w, "old lock")
			case r.URL.Path == "/raw/head/yarn.lock":
				fmt.Fprint(w, "new lock")
			default:
				t.Errorf("unexpected request: %s", r.URL)
				w.WriteHeader(500)
			}
		}
	}))
	defer srv.Close()

	c := testClient(srv, "")
	// inline Fetch's body against the test client
	stats, err := c.allDiffstats("repositories/ws/repo/pullrequests/7/diffstat?pagelen=100")
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 {
		t.Fatalf("want 2 diffstats, got %d", len(stats))
	}
	res, err := c.fill(&ghpr.Result{}, stats, func(p string) bool { return strings.HasSuffix(p, "yarn.lock") })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || string(res.Files[0].Old) != "old lock" || string(res.Files[0].New) != "new lock" {
		t.Fatalf("unexpected result: %+v", res.Files)
	}
}

func TestRawRejectsForeignHost(t *testing.T) {
	c := &client{http: &http.Client{Timeout: time.Second}, api: "https://api.bitbucket.org/2.0/"}
	if _, err := c.raw("https://evil.example.com/steal"); err == nil {
		t.Fatal("raw must refuse hrefs outside the API base")
	}
}
