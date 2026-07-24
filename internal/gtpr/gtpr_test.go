package gtpr

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in    string
		ok    bool
		host  string
		owner string
		repo  string
		index int
	}{
		{"https://codeberg.org/forgejo/forgejo/pulls/13594", true, "codeberg.org", "forgejo", "forgejo", 13594},
		{"codeberg.org/forgejo/forgejo/pulls/13594", true, "codeberg.org", "forgejo", "forgejo", 13594},
		{"https://gitea.com/gitea/tea/pulls/1057/files?x=1#issue", true, "gitea.com", "gitea", "tea", 1057},
		{"https://git.example.org:3000/o/r/pulls/7", true, "git.example.org:3000", "o", "r", 7},
		{"https://github.com/owner/repo/pull/1", false, "", "", "", 0},  // GitHub, singular
		{"https://github.com/owner/repo/pulls/1", false, "", "", "", 0}, // GitHub host excluded
		{"https://gitlab.com/o/r/pulls/1", false, "", "", "", 0},        // GitLab host excluded
		{"https://bitbucket.org/o/r/pulls/1", false, "", "", "", 0},     // Bitbucket host excluded
		{"localhost/o/r/pulls/1", false, "", "", "", 0},                 // no dot in host
		{"https://codeberg.org/forgejo/pulls/1", false, "", "", "", 0},  // too few segments
		{"https://codeberg.org/a/b/c/pulls/1", false, "", "", "", 0},    // too many segments
		{"https://codeberg.org/o/r/pulls/0", false, "", "", "", 0},      // bad index
		{"owner/repo#123", false, "", "", "", 0},                        // GitHub shorthand
	}
	for _, c := range cases {
		ref, ok := Parse(c.in)
		if ok != c.ok {
			t.Errorf("Parse(%q) ok=%v, want %v", c.in, ok, c.ok)
			continue
		}
		if ok && (ref.Host != c.host || ref.Owner != c.owner || ref.Repo != c.repo || ref.Index != c.index) {
			t.Errorf("Parse(%q) = %+v", c.in, ref)
		}
	}
}

func TestParseCommit(t *testing.T) {
	ref, ok := ParseCommit("https://codeberg.org/forgejo/forgejo/commit/714ddd0044f3815e6a4e7d2d7f6e0f2e7737249a")
	if !ok || ref.Host != "codeberg.org" || ref.Owner != "forgejo" || ref.Repo != "forgejo" || !strings.HasPrefix(ref.SHA, "714ddd") {
		t.Fatalf("commit url parse failed: %+v ok=%v", ref, ok)
	}
	if _, ok := ParseCommit("https://github.com/o/r/commit/abcdef1"); ok {
		t.Fatal("github commit url must not parse as gitea")
	}
	if _, ok := ParseCommit("https://codeberg.org/o/r/commit/nothex"); ok {
		t.Fatal("non-hex sha must not parse")
	}
}

func testClient(srv *httptest.Server, token string) *client {
	return &client{
		http:  &http.Client{Timeout: 5 * time.Second},
		base:  srv.URL + "/",
		token: token,
	}
}

func TestFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/o/r/pulls/5":
			fmt.Fprint(w, `{"title":"bump deps","merge_base":"base111","head":{"ref":"feat","sha":"head222"},"base":{"ref":"main"}}`)
		case r.URL.Path == "/repos/o/r/pulls/5/files":
			fmt.Fprint(w, `[
				{"filename":"go.mod","status":"changed"},
				{"filename":"README.md","status":"changed"},
				{"filename":"web/package-lock.json","status":"added"},
				{"filename":"old/Cargo.lock","status":"deleted"}
			]`)
		case r.URL.Path == "/repos/o/r/raw/go.mod" && r.URL.Query().Get("ref") == "base111":
			fmt.Fprint(w, "module m // old")
		case r.URL.Path == "/repos/o/r/raw/go.mod" && r.URL.Query().Get("ref") == "head222":
			fmt.Fprint(w, "module m // new")
		case r.URL.Path == "/repos/o/r/raw/web/package-lock.json" && r.URL.Query().Get("ref") == "head222":
			fmt.Fprint(w, "{}")
		case r.URL.Path == "/repos/o/r/raw/old/Cargo.lock" && r.URL.Query().Get("ref") == "base111":
			fmt.Fprint(w, "# lock")
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	ref := Ref{Host: "x", Owner: "o", Repo: "r", Index: 5}
	res, err := testClient(srv, "").fetch(ref, func(p string) bool { return p != "README.md" })
	if err != nil {
		t.Fatal(err)
	}
	if res.Title != "bump deps" || len(res.Files) != 3 {
		t.Fatalf("res = %+v", res)
	}
	if string(res.Files[0].Old) != "module m // old" || string(res.Files[0].New) != "module m // new" {
		t.Errorf("modified file sides wrong: %+v", res.Files[0])
	}
	if res.Files[1].Old != nil || string(res.Files[1].New) != "{}" {
		t.Errorf("added file must have no old side: %+v", res.Files[1])
	}
	if string(res.Files[2].Old) != "# lock" || res.Files[2].New != nil {
		t.Errorf("deleted file must have no new side: %+v", res.Files[2])
	}
}

func TestFetchCommit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/repos/o/r/git/commits/abc1234"):
			fmt.Fprint(w, `{"sha":"abc1234ffffffffff","parents":[{"sha":"par5678ffffffffff"}],
				"files":[{"filename":"Cargo.lock","status":"modified"},{"filename":"src/main.rs","status":"modified"}]}`)
		case r.URL.Path == "/repos/o/r/raw/Cargo.lock" && r.URL.Query().Get("ref") == "par5678ffffffffff":
			fmt.Fprint(w, "old")
		case r.URL.Path == "/repos/o/r/raw/Cargo.lock" && r.URL.Query().Get("ref") == "abc1234ffffffffff":
			fmt.Fprint(w, "new")
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	ref := CommitRef{Host: "x", Owner: "o", Repo: "r", SHA: "abc1234"}
	res, err := testClient(srv, "").fetchCommit(ref, func(p string) bool { return strings.HasSuffix(p, ".lock") })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 1 || string(res.Files[0].Old) != "old" || string(res.Files[0].New) != "new" {
		t.Fatalf("res = %+v", res)
	}
	if res.HeadLabel != "abc1234fffff" {
		t.Errorf("head label = %q", res.HeadLabel)
	}
}
