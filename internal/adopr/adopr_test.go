package adopr

import (
	"encoding/json"
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
		in       string
		ok       bool
		instance string
		project  string
		repo     string
		id       int
	}{
		{"https://dev.azure.com/fabrikam/Web/_git/app/pullrequest/12", true, "https://dev.azure.com/fabrikam", "Web", "app", 12},
		{"dev.azure.com/fabrikam/Web/_git/app/pullrequest/12", true, "https://dev.azure.com/fabrikam", "Web", "app", 12},
		{"https://dev.azure.com/fabrikam/Web/_git/app/pullrequest/12?_a=files", true, "https://dev.azure.com/fabrikam", "Web", "app", 12},
		{"https://fabrikam.visualstudio.com/Web/_git/app/pullrequest/7", true, "https://fabrikam.visualstudio.com", "Web", "app", 7},
		{"https://tfs.corp.example/tfs/DefaultCollection/Web/_git/app/pullrequest/3", true, "https://tfs.corp.example/tfs/DefaultCollection", "Web", "app", 3},
		{"https://dev.azure.com/o/My%20Project/_git/My%20Repo/pullrequest/5", true, "https://dev.azure.com/o", "My%20Project", "My%20Repo", 5},
		{"https://dev.azure.com/o/p/_git/r/pullrequest/0", false, "", "", "", 0},   // bad id
		{"https://github.com/owner/repo/pull/1", false, "", "", "", 0},             // GitHub URL
		{"https://gitlab.com/g/p/-/merge_requests/3", false, "", "", "", 0},        // GitLab URL
		{"https://bitbucket.org/x/p/_git/r/pullrequest/1", false, "", "", "", 0},   // wrong host
		{"owner/repo#123", false, "", "", "", 0},                                   // GitHub shorthand
		{"https://dev.azure.com/o/p/_git/r/pullrequests/12", false, "", "", "", 0}, // wrong path
	}
	for _, c := range cases {
		ref, ok := Parse(c.in)
		if ok != c.ok {
			t.Errorf("Parse(%q) ok=%v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && (ref.Instance != c.instance || ref.Project != c.project || ref.Repo != c.repo || ref.ID != c.id) {
			t.Errorf("Parse(%q) = %+v, want %s %s/%s#%d", c.in, ref, c.instance, c.project, c.repo, c.id)
		}
	}
}

func TestParseCompareAndCommit(t *testing.T) {
	ref, ok := ParseCompare("https://dev.azure.com/o/p/_git/r/branchCompare?baseVersion=GBmain&targetVersion=GBfeature%2Fx&_a=files")
	if !ok || ref.Base != "main" || ref.BaseType != "branch" || ref.Head != "feature/x" || ref.HeadType != "branch" {
		t.Fatalf("branchCompare parse failed: %+v ok=%v", ref, ok)
	}
	ref, ok = ParseCompare("https://dev.azure.com/o/p/_git/r/branchCompare?baseVersion=GTv1.0.0&targetVersion=GC0a1b2c3d")
	if !ok || ref.Base != "v1.0.0" || ref.BaseType != "tag" || ref.Head != "0a1b2c3d" || ref.HeadType != "commit" {
		t.Fatalf("tag/commit compare parse failed: %+v ok=%v", ref, ok)
	}
	if _, ok := ParseCompare("https://dev.azure.com/o/p/_git/r/branchCompare?baseVersion=main&targetVersion=GBx"); ok {
		t.Fatal("missing GB prefix must not parse")
	}
	inst, proj, repo, sha, ok := ParseCommit("https://dev.azure.com/o/p/_git/r/commit/0123456789abcdef0123456789abcdef01234567")
	if !ok || inst != "https://dev.azure.com/o" || proj != "p" || repo != "r" || !strings.HasPrefix(sha, "0123") {
		t.Fatalf("commit parse failed: %s %s %s %s ok=%v", inst, proj, repo, sha, ok)
	}
	if _, _, _, _, ok := ParseCommit("https://github.com/a/b/commit/0123456"); ok {
		t.Fatal("github commit url must not parse as azure devops")
	}
}

const (
	oldLock = `{"name":"a","lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.0.0"}}}`
	newLock = `{"name":"a","lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}`
)

// newTestServer emulates the handful of Azure DevOps routes adopr uses.
func newTestServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/o/p/_apis/git/repositories/r/pullRequests/12", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"title":"bump left-pad","sourceRefName":"refs/heads/dep/left-pad","targetRefName":"refs/heads/main",
			"lastMergeSourceCommit":{"commitId":"headsha"},"lastMergeTargetCommit":{"commitId":"targetsha"}}`)
	})
	mux.HandleFunc("/o/p/_apis/git/repositories/r/diffs/commits", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("diffCommonCommit") != "true" {
			t.Errorf("diffs called without diffCommonCommit=true")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"allChangesIncluded":true,"commonCommit":"basesha","baseCommit":"targetsha","targetCommit":"headsha",
			"changes":[{"changeType":"edit","item":{"path":"/package-lock.json","gitObjectType":"blob"}},
			           {"changeType":"edit","item":{"path":"/README.md","gitObjectType":"blob"}},
			           {"changeType":"edit","item":{"path":"/src","gitObjectType":"tree"}}]}`)
	})
	mux.HandleFunc("/o/p/_apis/git/repositories/r/items", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("versionDescriptor.version") {
		case "basesha":
			fmt.Fprint(w, oldLock)
		case "headsha":
			fmt.Fprint(w, newLock)
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("/o/p/_apis/git/repositories/r/commits/abc1234", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"commitId":"abc1234full","parents":["parentsha"]}`)
	})
	return httptest.NewServer(mux)
}

func testClient(srv *httptest.Server) *client {
	return &client{
		http:    &http.Client{Timeout: 5 * time.Second},
		apiBase: srv.URL + "/o/p/_apis/git/",
	}
}

func TestFetch(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	ref := Ref{Instance: srv.URL + "/o", Project: "p", Repo: "r", ID: 12}
	c := testClient(srv)

	// Inline Fetch's flow against the test server.
	var pr struct {
		Title                 string `json:"title"`
		SourceRefName         string `json:"sourceRefName"`
		TargetRefName         string `json:"targetRefName"`
		LastMergeSourceCommit struct {
			CommitID string `json:"commitId"`
		} `json:"lastMergeSourceCommit"`
		LastMergeTargetCommit struct {
			CommitID string `json:"commitId"`
		} `json:"lastMergeTargetCommit"`
	}
	if err := c.getJSON(fmt.Sprintf("repositories/%s/pullRequests/%d?api-version=7.1", ref.Repo, ref.ID), &pr); err != nil {
		t.Fatal(err)
	}
	if pr.Title != "bump left-pad" || pr.LastMergeSourceCommit.CommitID != "headsha" {
		t.Fatalf("pr meta wrong: %+v", pr)
	}
	diff, err := c.diff("r", pr.LastMergeTargetCommit.CommitID, "commit", pr.LastMergeSourceCommit.CommitID, "commit")
	if err != nil {
		t.Fatal(err)
	}
	if diff.CommonCommit != "basesha" || len(diff.Changes) != 3 {
		t.Fatalf("diff wrong: %+v", diff)
	}
	res, err := c.fill(&ghpr.Result{}, "r", diff, "headsha", func(p string) bool { return strings.HasSuffix(p, "package-lock.json") })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || res.Files[0].Path != "package-lock.json" ||
		string(res.Files[0].Old) != oldLock || string(res.Files[0].New) != newLock {
		t.Fatalf("unexpected result: %+v", res.Files)
	}
}

func TestResolveCommitUsesFirstParent(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	c := testClient(srv)
	var commit struct {
		CommitID string   `json:"commitId"`
		Parents  []string `json:"parents"`
	}
	if err := c.getJSON("repositories/r/commits/abc1234?api-version=7.1", &commit); err != nil {
		t.Fatal(err)
	}
	if commit.Parents[0] != "parentsha" || commit.CommitID != "abc1234full" {
		t.Fatalf("commit resolve wrong: %+v", commit)
	}
}

func TestPostCommentCreatesThenUpdates(t *testing.T) {
	var created, patched bool
	mux := http.NewServeMux()
	threads := `{"value":[]}`
	mux.HandleFunc("/o/p/_apis/git/repositories/r/pullRequests/12/threads", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost {
			var body struct {
				Comments []struct {
					Content string `json:"content"`
				} `json:"comments"`
				Status string `json:"status"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			if len(body.Comments) != 1 || !strings.HasPrefix(body.Comments[0].Content, marker) {
				t.Errorf("posted comment missing marker heading: %+v", body)
			}
			if body.Status != "closed" {
				t.Errorf("thread status = %q, want closed", body.Status)
			}
			created = true
			threads = fmt.Sprintf(`{"value":[{"id":1,"comments":[{"id":1,"content":%q}]}]}`, body.Comments[0].Content)
			fmt.Fprint(w, `{"id":1}`)
			return
		}
		fmt.Fprint(w, threads)
	})
	mux.HandleFunc("/o/p/_apis/git/repositories/r/pullRequests/12/threads/1/comments/1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("expected PATCH, got %s", r.Method)
		}
		patched = true
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":1}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := testClient(srv)
	c.token = "pat"
	ref := Ref{Instance: srv.URL + "/o", Project: "p", Repo: "r", ID: 12}

	body := marker + "\n\nfirst report"
	if _, updated, err := c.postComment(ref, body); err != nil || updated {
		t.Fatalf("create: updated=%v err=%v", updated, err)
	}
	if !created {
		t.Fatal("no thread created")
	}
	if _, updated, err := c.postComment(ref, marker+"\n\nsecond report"); err != nil || !updated {
		t.Fatalf("update: updated=%v err=%v", updated, err)
	}
	if !patched {
		t.Fatal("existing comment not patched")
	}
}

func TestUnauthenticatedCommentFails(t *testing.T) {
	c := &client{http: &http.Client{}, apiBase: "http://invalid.invalid/"}
	if _, _, err := c.postComment(Ref{}, "x"); err == nil || !strings.Contains(err.Error(), "AZURE_DEVOPS_TOKEN") {
		t.Fatalf("want auth hint, got %v", err)
	}
}

func TestSignInPageDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html>Sign in</html>")
	}))
	defer srv.Close()
	c := testClient(srv)
	var v any
	err := c.getJSON("repositories/r/pullRequests/1?api-version=7.1", &v)
	if err == nil || !strings.Contains(err.Error(), "sign-in") {
		t.Fatalf("want sign-in error, got %v", err)
	}
}

func TestRedirectToSignInDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/_signin", http.StatusFound)
	}))
	defer srv.Close()
	c := testClient(srv)
	c.http.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	var v any
	err := c.getJSON("repositories/r/pullRequests/1?api-version=7.1", &v)
	if err == nil || !strings.Contains(err.Error(), "AZURE_DEVOPS_TOKEN") {
		t.Fatalf("want auth hint on 302, got %v", err)
	}
}
