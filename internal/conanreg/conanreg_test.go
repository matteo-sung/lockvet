package conanreg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

func fakeServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/conans/search", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("q") {
		case "zlib":
			fmt.Fprint(w, `{"results":["zlib/1.2.11@_/_","zlib/1.3.1@_/_","zlibng/9.9.9@_/_"]}`)
		case "ghost":
			fmt.Fprint(w, `{"results":[]}`)
		default:
			http.NotFound(w, r)
		}
	})
	mux.HandleFunc("/v2/conans/zlib/1.3.1/_/_/revisions", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"revisions":[
		  {"revision":"new","time":"2024-02-22T09:20:06.497+0000"},
		  {"revision":"old","time":"2024-01-23T08:39:53.687+0000"}]}`)
	})
	return httptest.NewServer(mux)
}

func TestAnnotate(t *testing.T) {
	srv := fakeServer(t)
	defer srv.Close()
	oldURL, oldNow := BaseURL, Now
	BaseURL = srv.URL
	Now = func() time.Time { return time.Date(2024, 2, 25, 0, 0, 0, 0, time.UTC) }
	defer func() { BaseURL, Now = oldURL, oldNow }()

	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		{Ecosystem: "ConanCenter", Name: "zlib", Kind: diffx.Upgraded, Old: []string{"1.2.11"}, New: []string{"1.3.1"}},
		{Ecosystem: "ConanCenter", Name: "zlib", Kind: diffx.Added, New: []string{"9.9.9"}},
		{Ecosystem: "ConanCenter", Name: "ghost", Kind: diffx.Added, New: []string{"1.0.0"}},
		{Ecosystem: "ConanCenter", Name: "corp", Kind: diffx.Added, New: []string{"1.0.0"}, NonRegistry: true},
		{Ecosystem: "npm", Name: "left-pad", Kind: diffx.Added, New: []string{"1.3.0"}},
	}}}
	ok, err := Annotate(diffs, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected checked=true")
	}
	c := diffs[0].Changes[0]
	// Age must come from the OLDEST revision (Jan 23), not the re-export.
	if c.PublishedAt != "2024-01-23T08:39:53Z" {
		t.Errorf("PublishedAt = %q", c.PublishedAt)
	}
	if c.AgeDays != 32 {
		t.Errorf("AgeDays = %d", c.AgeDays)
	}
	if c.Fresh {
		t.Error("32-day-old version must not be fresh")
	}
	if c.Unlisted {
		t.Error("listed version flagged unlisted")
	}
	// No unlisted claims for Conan, ever: lockfile refs do not record
	// their remote, so absence from ConanCenter proves nothing.
	if u := diffs[0].Changes[1]; u.Unlisted || u.PublishedAt != "" {
		t.Errorf("version unknown to ConanCenter must carry no claims: unlisted=%v published=%q", u.Unlisted, u.PublishedAt)
	}
	if g := diffs[0].Changes[2]; g.Unlisted {
		t.Error("package unknown to registry entirely must not be flagged")
	}
	if nr := diffs[0].Changes[3]; nr.Unlisted || nr.PublishedAt != "" {
		t.Error("NonRegistry change must be untouched")
	}
	if np := diffs[0].Changes[4]; np.Unlisted || np.PublishedAt != "" {
		t.Error("non-Conan change must be untouched")
	}
}

func TestAnnotateFresh(t *testing.T) {
	srv := fakeServer(t)
	defer srv.Close()
	oldURL, oldNow := BaseURL, Now
	BaseURL = srv.URL
	Now = func() time.Time { return time.Date(2024, 1, 25, 0, 0, 0, 0, time.UTC) }
	defer func() { BaseURL, Now = oldURL, oldNow }()

	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		{Ecosystem: "ConanCenter", Name: "zlib", Kind: diffx.Upgraded, Old: []string{"1.2.11"}, New: []string{"1.3.1"}},
	}}}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; !c.Fresh || c.AgeDays != 1 {
		t.Errorf("fresh=%v age=%d, want fresh 1-day-old", c.Fresh, c.AgeDays)
	}
}

func TestDisabled(t *testing.T) {
	Enabled = false
	defer func() { Enabled = true }()
	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		{Ecosystem: "ConanCenter", Name: "zlib", New: []string{"1.3.1"}},
	}}}
	ok, err := Annotate(diffs, 7)
	if err != nil || ok {
		t.Fatalf("disabled layer must be a no-op, got ok=%v err=%v", ok, err)
	}
}
