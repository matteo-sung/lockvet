package hcache

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	d, err := os.MkdirTemp("", "hcache-test-*")
	if err != nil {
		panic(err)
	}
	os.Setenv("LOCKVET_CACHE_DIR", d) // resolved once by dir()
	code := m.Run()
	os.RemoveAll(d)
	os.Exit(code)
}

// counter serves distinct bodies per hit so cache hits are observable.
func counter(t *testing.T, status int, lastMod string) (*httptest.Server, *int) {
	t.Helper()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if lastMod != "" {
			w.Header().Set("Last-Modified", lastMod)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprintf(w, `{"hit":%d}`, hits)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func get(t *testing.T, c *http.Client, u string, hdr map[string]string) (string, http.Header) {
	t.Helper()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), resp.Header
}

func TestGetCachedWithHeaders(t *testing.T) {
	Configure(false, time.Hour)
	defer Configure(true, DefaultTTL)
	lm := "Wed, 21 Oct 2015 07:28:00 GMT"
	srv, hits := counter(t, 200, lm)
	c := Client(5 * time.Second)

	b1, _ := get(t, c, srv.URL+"/pkg/a", nil)
	b2, h2 := get(t, c, srv.URL+"/pkg/a", nil)
	if *hits != 1 {
		t.Fatalf("upstream hits = %d, want 1", *hits)
	}
	if b1 != b2 || b1 != `{"hit":1}` {
		t.Fatalf("bodies differ: %q vs %q", b1, b2)
	}
	// mvnreg derives ages from Last-Modified — it must survive the cache.
	if got := h2.Get("Last-Modified"); got != lm {
		t.Fatalf("Last-Modified from cache = %q, want %q", got, lm)
	}
	if got := h2.Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type from cache = %q", got)
	}
}

func TestNegativeAnswersNeverCached(t *testing.T) {
	Configure(false, time.Hour)
	defer Configure(true, DefaultTTL)
	srv, hits := counter(t, 404, "")
	c := Client(5 * time.Second)
	get(t, c, srv.URL+"/pkg/missing", nil)
	get(t, c, srv.URL+"/pkg/missing", nil)
	if *hits != 2 {
		t.Fatalf("404 hits = %d, want 2 (negative answers are evidence)", *hits)
	}
}

func TestTTLExpiry(t *testing.T) {
	Configure(false, 50*time.Millisecond)
	defer Configure(true, DefaultTTL)
	srv, hits := counter(t, 200, "")
	c := Client(5 * time.Second)
	get(t, c, srv.URL+"/pkg/ttl", nil)
	time.Sleep(80 * time.Millisecond)
	get(t, c, srv.URL+"/pkg/ttl", nil)
	if *hits != 2 {
		t.Fatalf("hits = %d, want 2 after TTL expiry", *hits)
	}
}

func TestAcceptHeaderSelectsEntry(t *testing.T) {
	Configure(false, time.Hour)
	defer Configure(true, DefaultTTL)
	srv, hits := counter(t, 200, "")
	c := Client(5 * time.Second)
	get(t, c, srv.URL+"/pkg/accept", map[string]string{"Accept": "application/vnd.npm.install-v1+json"})
	get(t, c, srv.URL+"/pkg/accept", map[string]string{"Accept": "application/json"})
	if *hits != 2 {
		t.Fatalf("hits = %d, want 2 (distinct Accept = distinct entries)", *hits)
	}
}

func TestAuthNeverCrossesAnonymous(t *testing.T) {
	Configure(false, time.Hour)
	defer Configure(true, DefaultTTL)
	srv, hits := counter(t, 200, "")
	c := Client(5 * time.Second)
	get(t, c, srv.URL+"/pkg/auth", map[string]string{"Authorization": "Bearer sekrit"})
	get(t, c, srv.URL+"/pkg/auth", nil)
	if *hits != 2 {
		t.Fatalf("hits = %d, want 2 (authed and anonymous must not share)", *hits)
	}
	// The credential itself must not appear in any cache file.
	files, _ := os.ReadDir(filepath.Join(os.Getenv("LOCKVET_CACHE_DIR"), "http"))
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(os.Getenv("LOCKVET_CACHE_DIR"), "http", f.Name()))
		if err == nil && strings.Contains(string(b), "sekrit") {
			t.Fatalf("credential leaked into cache file %s", f.Name())
		}
	}
}

func TestPostAllowlist(t *testing.T) {
	Configure(false, time.Hour)
	defer Configure(true, DefaultTTL)
	srv, hits := counter(t, 200, "")
	c := Client(5 * time.Second)

	post := func(body string) string {
		resp, err := c.Post(srv.URL+"/v1/querybatch", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	// Host not allowlisted: every POST goes upstream.
	post(`{"q":1}`)
	post(`{"q":1}`)
	if *hits != 2 {
		t.Fatalf("non-allowlisted POST hits = %d, want 2", *hits)
	}

	// Allowlist the test host: identical bodies share an entry, different
	// bodies do not.
	u, _ := url.Parse(srv.URL)
	postHosts[u.Hostname()] = true
	defer delete(postHosts, u.Hostname())
	b1 := post(`{"q":2}`)
	b2 := post(`{"q":2}`)
	post(`{"q":3}`)
	if *hits != 4 {
		t.Fatalf("allowlisted POST hits = %d, want 4", *hits)
	}
	if b1 != b2 {
		t.Fatalf("cached POST bodies differ: %q vs %q", b1, b2)
	}
}

func TestDisabledPassesThrough(t *testing.T) {
	Configure(true, time.Hour)
	srv, hits := counter(t, 200, "")
	c := Client(5 * time.Second)
	get(t, c, srv.URL+"/pkg/off", nil)
	get(t, c, srv.URL+"/pkg/off", nil)
	if *hits != 2 {
		t.Fatalf("disabled cache hits = %d, want 2", *hits)
	}
}

func TestCorruptEntryRefetched(t *testing.T) {
	Configure(false, time.Hour)
	defer Configure(true, DefaultTTL)
	srv, hits := counter(t, 200, "")
	c := Client(5 * time.Second)
	get(t, c, srv.URL+"/pkg/corrupt", nil)

	d := filepath.Join(os.Getenv("LOCKVET_CACHE_DIR"), "http")
	files, _ := os.ReadDir(d)
	for _, f := range files {
		p := filepath.Join(d, f.Name())
		if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), "/pkg/corrupt") {
			os.WriteFile(p, []byte("not json"), 0o600)
		}
	}
	b, _ := get(t, c, srv.URL+"/pkg/corrupt", nil)
	if *hits != 2 || b != `{"hit":2}` {
		t.Fatalf("corrupt entry not refetched: hits=%d body=%q", *hits, b)
	}
}

func TestLargeBodyNotStored(t *testing.T) {
	Configure(false, time.Hour)
	defer Configure(true, DefaultTTL)
	hits := 0
	big := strings.Repeat("x", maxBody+10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		io.WriteString(w, big)
	}))
	defer srv.Close()
	c := Client(30 * time.Second)
	b1, _ := get(t, c, srv.URL+"/pkg/big", nil)
	if len(b1) != len(big) {
		t.Fatalf("large body truncated: %d != %d", len(b1), len(big))
	}
	get(t, c, srv.URL+"/pkg/big", nil)
	if hits != 2 {
		t.Fatalf("hits = %d, want 2 (oversized bodies never stored)", hits)
	}
}
