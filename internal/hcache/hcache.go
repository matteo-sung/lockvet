// Package hcache is a small on-disk cache for registry and advisory HTTP
// responses. Repeat runs of lockvet re-ask the same registries the same
// questions (running `lockvet`, then `lockvet -md`, then `lockvet -json`
// refetches everything three times); caching answers for a short window
// makes repeat runs fast and stays inside tight anonymous rate limits
// (hex.pm allows 100 req/min, Bitbucket ~60/hr, npm and PyPI throttle too).
//
// Scope — metadata only, never code under review:
//
//   - Cached: OSV.dev and deps.dev answers, and the package-registry
//     documents lockvet reads (npm, PyPI, crates.io, RubyGems, Packagist,
//     NuGet, Hex, Go proxy, pub.dev, CocoaPods, Terraform, Maven, JSR,
//     Conan), plus taglink's git ref advertisements and GitHub release
//     notes.
//   - Never cached: forge API responses (PR state, compared files, file
//     contents) — those must always be live, or lockvet could vet a stale
//     diff.
//
// Only 200 responses are stored. 404s are part of lockvet's evidence for
// the ▲ unlisted flag (version absent from its registry) and must be
// re-proven on every run — a just-published version has to clear the flag
// immediately, so negative answers are never cached.
//
// Entries expire after the configured TTL (default 1h; `-cache-ttl 0` or
// `-no-cache` disables). The default window means advisory data can be up
// to an hour old on repeat runs — comparable to OSV's own propagation
// latency; pass -no-cache when it matters. Files live under
// os.UserCacheDir()/lockvet/http (override: LOCKVET_CACHE_DIR), are
// user-private (0700/0600), and a best-effort background sweep removes
// entries older than max(24h, 2×TTL).
package hcache

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultTTL is how long a cached answer is served before refetching.
	DefaultTTL = time.Hour
	// maxBody: responses larger than this are returned but not stored.
	maxBody = 8 << 20 // 8 MiB
)

// postHosts lists the hosts whose POST endpoints are pure queries (the
// request body is the question, the response the answer) and therefore
// safe to cache keyed on the body. Everything else POSTed is passed through.
var postHosts = map[string]bool{
	"api.osv.dev":  true, // /v1/querybatch
	"api.deps.dev": true, // /v3alpha/versionbatch
}

var (
	mu       sync.Mutex
	disabled = true // pass-through until Configure — keeps tests and library use inert
	ttl      = DefaultTTL
	dirOnce  sync.Once
	cacheDir string // "" = unusable → pass-through
)

// Configure sets cache behaviour; the CLI calls it once after flag
// parsing, before any requests. Until then every Client is pass-through.
// A non-positive ttl disables the cache entirely.
func Configure(off bool, d time.Duration) {
	mu.Lock()
	defer mu.Unlock()
	disabled = off || d <= 0
	if d > 0 {
		ttl = d
	}
}

func enabled() bool {
	mu.Lock()
	defer mu.Unlock()
	return !disabled
}

func currentTTL() time.Duration {
	mu.Lock()
	defer mu.Unlock()
	return ttl
}

// dir resolves (once) the cache directory, creating it. Empty = unusable.
func dir() string {
	dirOnce.Do(func() {
		if runtime.GOOS == "js" { // wasm: no real filesystem
			return
		}
		d := os.Getenv("LOCKVET_CACHE_DIR")
		if d == "" {
			base, err := os.UserCacheDir()
			if err != nil {
				return
			}
			d = filepath.Join(base, "lockvet")
		}
		d = filepath.Join(d, "http")
		if err := os.MkdirAll(d, 0o700); err != nil {
			return
		}
		cacheDir = d
		go sweep(d, currentTTL())
	})
	return cacheDir
}

// Client returns an *http.Client with the given timeout whose GET (and
// allowlisted POST) responses are served from / stored in the on-disk cache.
func Client(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &transport{base: http.DefaultTransport}}
}

type transport struct {
	base http.RoundTripper
}

type meta struct {
	URL    string      `json:"url"`
	Status int         `json:"status"`
	Stored time.Time   `json:"stored"`
	Header http.Header `json:"header"`
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !enabled() {
		return t.base.RoundTrip(req)
	}
	d := dir()
	if d == "" {
		return t.base.RoundTrip(req)
	}

	var body []byte // POST body, part of the key
	switch req.Method {
	case http.MethodGet:
	case http.MethodPost:
		if !postHosts[req.URL.Hostname()] || req.Body == nil {
			return t.base.RoundTrip(req)
		}
		var err error
		body, err = io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	default:
		return t.base.RoundTrip(req)
	}

	path := filepath.Join(d, key(req, body))
	if resp := load(path, req, currentTTL()); resp != nil {
		return resp, nil
	}

	resp, err := t.base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return resp, err // negative answers are evidence; never cached
	}
	full, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	if len(full) > maxBody {
		// Too big to store: splice what was read back in front of the rest.
		resp.Body = readCloser{io.MultiReader(bytes.NewReader(full), resp.Body), resp.Body}
		return resp, nil
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(full))
	resp.ContentLength = int64(len(full))
	store(path, resp, full)
	return resp, nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

// key builds the cache filename: method, URL, the headers that select a
// representation (Accept — npm's abbreviated docs), a fingerprint of the
// credential used (so authed and anonymous answers never cross), and the
// POST body if any.
func key(req *http.Request, body []byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n", req.Method, req.URL.String(), req.Header.Get("Accept"))
	if auth := req.Header.Get("Authorization"); auth != "" {
		fmt.Fprintf(h, "%x\n", sha256.Sum256([]byte(auth)))
	}
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// load returns a cached response, or nil on miss/expiry/corruption.
func load(path string, req *http.Request, ttl time.Duration) *http.Response {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	r := bufio.NewReader(f)
	line, err := r.ReadBytes('\n')
	if err != nil {
		return nil
	}
	var m meta
	if json.Unmarshal(line, &m) != nil || m.Status != http.StatusOK {
		os.Remove(path)
		return nil
	}
	if time.Since(m.Stored) > ttl {
		os.Remove(path)
		return nil
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil
	}
	h := m.Header.Clone()
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        h,
		Body:          io.NopCloser(bytes.NewReader(b)),
		ContentLength: int64(len(b)),
		Request:       req,
	}
}

// store writes meta line + body atomically (temp file + rename).
func store(path string, resp *http.Response, body []byte) {
	m := meta{URL: resp.Request.URL.String(), Status: resp.StatusCode, Stored: time.Now().UTC(), Header: sanitizeHeader(resp.Header)}
	line, err := json.Marshal(m)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(line, '\n')); err == nil {
		if _, err := tmp.Write(body); err == nil {
			if tmp.Close() == nil {
				os.Chmod(tmp.Name(), 0o600)
				os.Rename(tmp.Name(), path)
				return
			}
		}
	}
	tmp.Close()
}

// sanitizeHeader keeps the response headers callers actually read
// (content typing, upload times, validators) and drops connection- and
// credential-flavoured ones from the stored copy.
func sanitizeHeader(h http.Header) http.Header {
	out := http.Header{}
	for _, k := range []string{"Content-Type", "Last-Modified", "Etag", "Date", "Content-Language"} {
		if v := h.Values(k); len(v) > 0 {
			out[http.CanonicalHeaderKey(k)] = v
		}
	}
	return out
}

// sweep removes entries older than max(24h, 2×ttl); best effort.
func sweep(d string, ttl time.Duration) {
	horizon := 24 * time.Hour
	if 2*ttl > horizon {
		horizon = 2 * ttl
	}
	cutoff := time.Now().Add(-horizon)
	entries, err := os.ReadDir(d)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".tmp-") {
			if info, err := e.Info(); err == nil && info.ModTime().Before(time.Now().Add(-time.Hour)) {
				os.Remove(filepath.Join(d, e.Name()))
			}
			continue
		}
		if info, err := e.Info(); err == nil && info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(d, e.Name()))
		}
	}
}
