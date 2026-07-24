package gtpr

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseCompare(t *testing.T) {
	cases := []struct {
		in         string
		ok         bool
		host, base string
		head       string
	}{
		{"https://codeberg.org/forgejo/forgejo/compare/v11.0.0...v11.0.1", true, "codeberg.org", "v11.0.0", "v11.0.1"},
		{"codeberg.org/o/r/compare/a..b", true, "codeberg.org", "a", "b"},
		{"https://gitea.example.com:3000/o/r/compare/main...feature/x", true, "gitea.example.com:3000", "main", "feature/x"},
		{"https://codeberg.org/o/r/compare/v1...v2.diff", true, "codeberg.org", "v1", "v2"},
		{"https://codeberg.org/o/r/compare/v1...v2.patch?foo=1#bar", true, "codeberg.org", "v1", "v2"},
		{"https://codeberg.org/release/notes/compare/v10.0/forgejo...v11.0/forgejo", true, "codeberg.org", "v10.0/forgejo", "v11.0/forgejo"},
		{"https://github.com/o/r/compare/a...b", false, "", "", ""},   // GitHub path handles it
		{"https://gitlab.com/o/r/compare/a...b", false, "", "", ""},   // foreign host
		{"https://codeberg.org/o/r/compare/onlyoneref", false, "", "", ""},
		{"https://codeberg.org/o/r/pulls/5", false, "", "", ""},
	}
	for _, c := range cases {
		ref, ok := ParseCompare(c.in)
		if ok != c.ok {
			t.Errorf("ParseCompare(%q) ok = %v, want %v", c.in, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if ref.Host != c.host || ref.Base != c.base || ref.Head != c.head {
			t.Errorf("ParseCompare(%q) = %+v, want host=%q base=%q head=%q", c.in, ref, c.host, c.base, c.head)
		}
	}
}

func TestFetchCompare(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("ref")
		switch {
		case r.URL.Path == "/repos/o/r/compare/v1...v2":
			fmt.Fprint(w, `{"total_commits":2,"commits":[
				{"sha":"c1","files":[{"filename":"go.mod"},{"filename":"README.md"},{"filename":"new/Cargo.lock"}]},
				{"sha":"c2","files":[{"filename":"go.mod"},{"filename":"gone/poetry.lock"},{"filename":"same/bun.lock"}]}
			]}`)
		case r.URL.Path == "/repos/o/r/raw/go.mod" && q == "v1":
			fmt.Fprint(w, "module m // old")
		case r.URL.Path == "/repos/o/r/raw/go.mod" && q == "v2":
			fmt.Fprint(w, "module m // new")
		case r.URL.Path == "/repos/o/r/raw/new/Cargo.lock" && q == "v1":
			w.WriteHeader(404) // added after v1
		case r.URL.Path == "/repos/o/r/raw/new/Cargo.lock" && q == "v2":
			fmt.Fprint(w, "# lock")
		case r.URL.Path == "/repos/o/r/raw/gone/poetry.lock" && q == "v1":
			fmt.Fprint(w, "[[package]]")
		case r.URL.Path == "/repos/o/r/raw/gone/poetry.lock" && q == "v2":
			w.WriteHeader(404) // deleted before v2
		case r.URL.Path == "/repos/o/r/raw/same/bun.lock" && (q == "v1" || q == "v2"):
			fmt.Fprint(w, "identical") // touched but reverted within range
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	ref := CmpRef{Host: "x", Owner: "o", Repo: "r", Base: "v1", Head: "v2"}
	res, err := testClient(srv, "").fetchCompare(ref, func(p string) bool { return p != "README.md" })
	if err != nil {
		t.Fatal(err)
	}
	if res.BaseLabel != "o/r@v1" || res.HeadLabel != "v2" {
		t.Errorf("labels = %q, %q", res.BaseLabel, res.HeadLabel)
	}
	if len(res.Files) != 3 {
		t.Fatalf("want 3 files (identical bun.lock skipped), got %d: %+v", len(res.Files), res.Files)
	}
	// sorted: go.mod, gone/poetry.lock, new/Cargo.lock
	if string(res.Files[0].Old) != "module m // old" || string(res.Files[0].New) != "module m // new" {
		t.Errorf("modified file sides wrong: %+v", res.Files[0])
	}
	if res.Files[2].Old != nil || string(res.Files[2].New) != "# lock" {
		t.Errorf("added file must have no old side: %+v", res.Files[2])
	}
	if string(res.Files[1].Old) != "[[package]]" || res.Files[1].New != nil {
		t.Errorf("deleted file must have no new side: %+v", res.Files[1])
	}
}

func TestFetchCompareEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"total_commits":0,"commits":[]}`)
	}))
	defer srv.Close()

	ref := CmpRef{Host: "x", Owner: "o", Repo: "r", Base: "v2", Head: "v2"}
	res, err := testClient(srv, "").fetchCompare(ref, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 0 {
		t.Fatalf("want no files, got %+v", res.Files)
	}
}

func TestFetchCompareBadRevision(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()

	ref := CmpRef{Host: "x", Owner: "o", Repo: "r", Base: "v1", Head: "nope"}
	_, err := testClient(srv, "").fetchCompare(ref, func(string) bool { return true })
	if err == nil {
		t.Fatal("want error for unknown revision")
	}
	if got := err.Error(); !strings.Contains(got, "do both revisions exist") {
		t.Errorf("error should hint at bad revisions: %q", got)
	}
}
