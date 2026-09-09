package hcache

import (
	"encoding/json"
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

func TestAnonAuthKeyedAsAnonymous(t *testing.T) {
	Configure(false, time.Hour)
	defer Configure(true, DefaultTTL)
	var sawMarker bool
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get(AnonAuthHeader) != "" {
			sawMarker = true
		}
		fmt.Fprint(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	c := Client(5 * time.Second)
	// Two runs with ROTATED anonymous tokens must share one cache entry.
	get(t, c, srv.URL+"/pkg/anontok", map[string]string{
		"Authorization": "Bearer rotating-tok-1", AnonAuthHeader: "1"})
	get(t, c, srv.URL+"/pkg/anontok", map[string]string{
		"Authorization": "Bearer rotating-tok-2", AnonAuthHeader: "1"})
	if hits != 1 {
		t.Fatalf("hits = %d, want 1 (anon-token entries must be shared)", hits)
	}
	if sawMarker {
		t.Fatal("cache marker header leaked onto the wire")
	}
	// A REAL credential (no marker) must not read the anon entry.
	get(t, c, srv.URL+"/pkg/anontok", map[string]string{
		"Authorization": "Bearer sekrit-user-cred"})
	if hits != 2 {
		t.Fatalf("hits = %d, want 2 (user credential must not share anon entry)", hits)
	}
}

// ageEntry rewrites the Stored timestamp of the cache entry for url so
// tests can simulate entries laid down hours or days ago.
func ageEntry(t *testing.T, u string, age time.Duration) {
	t.Helper()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir(), key(req, nil, false))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("cache entry for %s: %v", u, err)
	}
	agePath(t, path, age)
}

func TestStaleIfError(t *testing.T) {
	Configure(false, time.Hour)
	defer Configure(true, DefaultTTL)
	StaleNote() // drain anything earlier tests left behind
	srv, _ := counter(t, 200, "")
	c := Client(2 * time.Second)
	u := srv.URL + "/pkg/stale-if-error"
	body, _ := get(t, c, u, nil)
	if body != `{"hit":1}` {
		t.Fatalf("first fetch = %q", body)
	}
	ageEntry(t, u, 2*time.Hour) // past TTL, inside the sweep horizon
	srv.Close()                 // network gone
	body, _ = get(t, c, u, nil)
	if body != `{"hit":1}` {
		t.Fatalf("stale fallback = %q, want the cached answer", body)
	}
	note := StaleNote()
	if !strings.Contains(note, "network unreachable") || !strings.Contains(note, "2h") {
		t.Fatalf("StaleNote = %q, want unreachable warning mentioning 2h", note)
	}
	if StaleNote() != "" {
		t.Fatal("StaleNote must reset after reporting")
	}
}

func TestStaleRespectsSweepHorizon(t *testing.T) {
	Configure(false, time.Hour)
	defer Configure(true, DefaultTTL)
	StaleNote()
	srv, _ := counter(t, 200, "")
	c := Client(2 * time.Second)
	u := srv.URL + "/pkg/stale-horizon"
	get(t, c, u, nil)
	ageEntry(t, u, 25*time.Hour) // past max(24h, 2×TTL): sweep would have removed it
	srv.Close()
	req, _ := http.NewRequest("GET", u, nil)
	if _, err := c.Do(req); err == nil {
		t.Fatal("want transport error when the only entry is past the horizon")
	}
	if StaleNote() != "" {
		t.Fatal("no stale answer was served; StaleNote must be empty")
	}
	rq, _ := http.NewRequest("GET", u, nil)
	if _, err := os.Stat(filepath.Join(dir(), key(rq, nil, false))); !os.IsNotExist(err) {
		t.Fatal("entry past the horizon must be removed on load")
	}
}

func TestNoFallbackWhenServerAnswers(t *testing.T) {
	Configure(false, time.Hour)
	defer Configure(true, DefaultTTL)
	StaleNote()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			fmt.Fprint(w, `{"hit":1}`)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	c := Client(2 * time.Second)
	u := srv.URL + "/pkg/server-answers"
	get(t, c, u, nil)
	ageEntry(t, u, 2*time.Hour)
	req, _ := http.NewRequest("GET", u, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want the server's own 503 — an answer is an answer", resp.StatusCode)
	}
	if StaleNote() != "" {
		t.Fatal("server answered; stale fallback must not engage")
	}
}

func TestExpiredEntrySurvivesForFallback(t *testing.T) {
	Configure(false, time.Hour)
	defer Configure(true, DefaultTTL)
	StaleNote()
	srv, hits := counter(t, 200, "")
	c := Client(2 * time.Second)
	u := srv.URL + "/pkg/expired-survives"
	get(t, c, u, nil)
	ageEntry(t, u, 2*time.Hour)
	// Live refetch succeeds: entry is refreshed, not served stale.
	body, _ := get(t, c, u, nil)
	if body != `{"hit":2}` || *hits != 2 {
		t.Fatalf("expired entry must refetch when the network works (body=%q hits=%d)", body, *hits)
	}
	if StaleNote() != "" {
		t.Fatal("fresh refetch must not count as stale")
	}
}

func TestStalePostFallback(t *testing.T) {
	// querybatch-shaped: an allowlisted POST keyed on its body must fall
	// back to its own body's entry, not another query's.
	Configure(false, time.Hour)
	defer Configure(true, DefaultTTL)
	StaleNote()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		b, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, `{"echo":%q,"hit":%d}`, string(b), hits)
	}))
	t.Cleanup(srv.Close)
	host := srv.Listener.Addr().String()
	postHosts[strings.Split(host, ":")[0]] = true // allowlist 127.0.0.1 for the test
	defer delete(postHosts, strings.Split(host, ":")[0])

	c := Client(2 * time.Second)
	post := func(body string) (string, error) {
		req, err := http.NewRequest("POST", srv.URL+"/v1/querybatch", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	a, _ := post(`{"queries":["a"]}`)
	if _, err := post(`{"queries":["b"]}`); err != nil {
		t.Fatal(err)
	}
	// Age both entries past TTL, then take the network away.
	for _, e := range mustDir(t) {
		agePath(t, e, 3*time.Hour)
	}
	srv.Close()
	got, err := post(`{"queries":["a"]}`)
	if err != nil || got != a {
		t.Fatalf("stale POST fallback = %q, %v; want cached %q", got, err, a)
	}
	if note := StaleNote(); !strings.Contains(note, "3h") {
		t.Fatalf("StaleNote = %q, want 3h", note)
	}
}

// mustDir lists current cache entry paths.
func mustDir(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(dir())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".tmp-") {
			out = append(out, filepath.Join(dir(), e.Name()))
		}
	}
	return out
}

// agePath rewrites Stored on one entry file (see ageEntry).
func agePath(t *testing.T, path string, age time.Duration) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.IndexByte(string(b), '\n')
	var m meta
	if err := json.Unmarshal(b[:i], &m); err != nil {
		t.Fatal(err)
	}
	m.Stored = time.Now().UTC().Add(-age)
	line, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(append(line, '\n'), b[i+1:]...), 0o600); err != nil {
		t.Fatal(err)
	}
}
