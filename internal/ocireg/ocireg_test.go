package ocireg

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/hcache"
)

const (
	idxDigest  = "sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d"
	armDigest  = "sha256:f27cad91174956c1d8b1e5f2a37e9b4f2c5b9ed177cb5f2be25c0b7c54036f18"
	oldDigest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	fakeDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

// hubServer fakes the Docker Hub API for library/alpine.
func hubServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v2/repositories/library/alpine", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"name":"alpine"}`)
	})
	mux.HandleFunc("/v2/repositories/library/alpine/tags/3.21", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"name": "3.21", "last_updated": time.Now().UTC().Add(-40 * 24 * time.Hour).Format(time.RFC3339),
			"digest": idxDigest,
			"images": []map[string]any{{"digest": armDigest, "architecture": "arm64"}},
		})
	})
	mux.HandleFunc("/v2/repositories/library/alpine/tags/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // any other tag
	})
	// Distribution API on the same fake host (RegistryBaseURL points here
	// too): token endpoint + manifest probes.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"token":"testtok"}`)
	})
	mux.HandleFunc("/v2/library/alpine/manifests/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer testtok" {
			w.Header().Set("Www-Authenticate", `Bearer realm="http://ignored/token",service="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ref := strings.TrimPrefix(r.URL.Path, "/v2/library/alpine/manifests/")
		switch ref {
		case oldDigest: // an older build of the tag: still resolvable
			w.Header().Set("Docker-Content-Digest", oldDigest)
			fmt.Fprint(w, `{"schemaVersion":2}`)
		case idxDigest, armDigest:
			w.Header().Set("Docker-Content-Digest", idxDigest)
			fmt.Fprint(w, `{"schemaVersion":2}`)
		default:
			http.NotFound(w, r)
		}
	})
	return httptest.NewServer(mux)
}

func withServer(t *testing.T, srv *httptest.Server) {
	t.Helper()
	oldHub, oldReg := HubBaseURL, RegistryBaseURL
	HubBaseURL, RegistryBaseURL = srv.URL, srv.URL
	t.Cleanup(func() {
		HubBaseURL, RegistryBaseURL = oldHub, oldReg
		srv.Close()
	})
}

func change(name string, newV []string, pins map[string]string) []diffx.FileDiff {
	return []diffx.FileDiff{{
		Path: "Dockerfile", Ecosystem: "Docker",
		Changes: []diffx.Change{{
			Name: name, Ecosystem: "Docker", Kind: diffx.Upgraded,
			Old: []string{"3.20"}, New: newV, NewPins: pins,
		}},
	}}
}

func TestHubAgeAndVerifiedDigest(t *testing.T) {
	withServer(t, hubServer(t))
	diffs := change("alpine", []string{"3.21"}, map[string]string{"3.21": idxDigest})
	ok, err := Annotate(diffs, 14)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	c := diffs[0].Changes[0]
	if !c.DigestVerified {
		t.Fatal("digest should verify")
	}
	if c.AgeDays < 39 || c.AgeDays > 41 || c.Fresh {
		t.Fatalf("age=%d fresh=%v", c.AgeDays, c.Fresh)
	}
	if c.Unlisted || c.TagMismatch {
		t.Fatalf("unexpected flags: %+v", c)
	}
}

func TestPlatformDigestVerifies(t *testing.T) {
	withServer(t, hubServer(t))
	diffs := change("alpine", []string{"3.21"}, map[string]string{"3.21": armDigest})
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	if !diffs[0].Changes[0].DigestVerified {
		t.Fatal("per-platform digest should verify")
	}
}

func TestStaleDigestIsTagMismatch(t *testing.T) {
	withServer(t, hubServer(t))
	diffs := change("alpine", []string{"3.21"}, map[string]string{"3.21": oldDigest})
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.TagMismatch || c.DigestVerified || c.Unlisted {
		t.Fatalf("want tag mismatch, got %+v", c)
	}
	if len(c.TagMismatches) != 1 || !strings.Contains(c.TagMismatches[0], "tag now serves") {
		t.Fatalf("mismatch text: %v", c.TagMismatches)
	}
}

func TestUnknownDigestIsUnlisted(t *testing.T) {
	withServer(t, hubServer(t))
	diffs := change("alpine", []string{"3.21"}, map[string]string{"3.21": fakeDigest})
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || c.TagMismatch || c.DigestVerified {
		t.Fatalf("want unlisted, got %+v", c)
	}
}

func TestMissingTagIsUnlisted(t *testing.T) {
	withServer(t, hubServer(t))
	diffs := change("alpine", []string{"9.99"}, nil)
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "9.99" {
		t.Fatalf("want tag unlisted, got %+v", c)
	}
}

func TestUnknownRepoFlagsNothing(t *testing.T) {
	mux := http.NewServeMux() // 404 for everything
	withServer(t, httptest.NewServer(mux))
	diffs := change("alpine", []string{"9.99"}, nil)
	ok, err := Annotate(diffs, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ok || diffs[0].Changes[0].Unlisted {
		t.Fatalf("unknown repo must make no claims: ok=%v %+v", ok, diffs[0].Changes[0])
	}
}

func TestPrivateHostNeverQueried(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request: %s", r.URL)
	}))
	withServer(t, srv)
	diffs := change("registry.example.com:5000/team/svc", []string{"2.0"}, nil)
	// The allowlist keys on the image's own host, so the fake server must
	// not be contacted at all.
	ok, err := Annotate(diffs, 0)
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestGenericRegistryTokenFlow(t *testing.T) {
	// ghcr-style: tags/list + manifests behind an anonymous token.
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("scope") != "repository:acme/tool:pull" {
			t.Errorf("scope = %q", r.URL.Query().Get("scope"))
		}
		fmt.Fprint(w, `{"token":"testtok"}`)
	})
	authed := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer testtok" {
			w.Header().Set("Www-Authenticate", `Bearer realm="http://ignored/token",service="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("/v2/acme/tool/tags/list", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) {
			fmt.Fprint(w, `{"name":"acme/tool","tags":["v1.2.3"]}`)
		}
	})
	mux.HandleFunc("/v2/acme/tool/manifests/v1.2.3", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) {
			w.Header().Set("Docker-Content-Digest", idxDigest)
			fmt.Fprintf(w, `{"schemaVersion":2,"manifests":[{"digest":%q}]}`, armDigest)
		}
	})
	mux.HandleFunc("/v2/acme/tool/manifests/", func(w http.ResponseWriter, r *http.Request) {
		if authed(w, r) {
			http.NotFound(w, r)
		}
	})
	withServer(t, httptest.NewServer(mux))
	diffs := change("ghcr.io/acme/tool", []string{"v1.2.3"}, map[string]string{"v1.2.3": armDigest})
	ok, err := Annotate(diffs, 0)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	c := diffs[0].Changes[0]
	if !c.DigestVerified || c.Unlisted || c.TagMismatch {
		t.Fatalf("got %+v", c)
	}
	// No age claims off-Hub.
	if c.PublishedAt != "" {
		t.Fatalf("unexpected age: %q", c.PublishedAt)
	}
}

func TestDigestOnlyPinExistence(t *testing.T) {
	withServer(t, hubServer(t))
	short := oldDigest[:19]
	diffs := change("alpine", []string{short}, map[string]string{short: oldDigest})
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; c.Unlisted {
		t.Fatalf("existing digest flagged: %+v", c)
	}
	short2 := fakeDigest[:19]
	diffs = change("alpine", []string{short2}, map[string]string{short2: fakeDigest})
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; !c.Unlisted {
		t.Fatalf("fabricated digest not flagged: %+v", c)
	}
}

// TestTokenRotationWithCache replays the bug where the anonymous pull
// token was cached past its lifetime: the registry here invalidates each
// token as soon as the next one is issued, and the response cache is ON.
// A second annotate run (fresh repos, as in a new process) must fetch a
// fresh token — not replay a stale cached one and silently drop claims.
func TestTokenRotationWithCache(t *testing.T) {
	t.Setenv("LOCKVET_CACHE_DIR", t.TempDir())
	hcache.Configure(false, time.Hour)
	defer hcache.Configure(true, hcache.DefaultTTL)

	tokenCalls := 0
	current := ""
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		current = fmt.Sprintf("tok-%d", tokenCalls)
		fmt.Fprintf(w, `{"token":%q}`, current)
	})
	mux.HandleFunc("/v2/library/redis/tags/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+current {
			w.Header().Set("Www-Authenticate", `Bearer realm="http://ignored/token",service="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"tags":["7.4"]}`)
	})
	mux.HandleFunc("/v2/library/redis/manifests/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+current {
			w.Header().Set("Www-Authenticate", `Bearer realm="http://ignored/token",service="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ref := strings.TrimPrefix(r.URL.Path, "/v2/library/redis/manifests/")
		if ref == "7.4" || ref == idxDigest {
			w.Header().Set("Docker-Content-Digest", idxDigest)
			fmt.Fprint(w, `{"schemaVersion":2}`)
			return
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	withServer(t, srv)

	mk := func() []diffx.FileDiff {
		return []diffx.FileDiff{{
			Path: "Dockerfile", Ecosystem: "Docker",
			Changes: []diffx.Change{{
				Name: "ghcr.io/library/redis", Ecosystem: "Docker", Kind: diffx.Upgraded,
				Old: []string{"7.2"}, New: []string{"7.4"},
				NewPins: map[string]string{"7.4": oldDigest},
			}},
		}}
	}
	for run := 1; run <= 2; run++ {
		diffs := mk()
		if _, err := Annotate(diffs, 0); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
		c := diffs[0].Changes[0]
		// oldDigest is not what the tag serves and the registry 404s it →
		// the unlisted claim must survive a warm cache + rotated token.
		if !c.Unlisted {
			t.Fatalf("run %d: unlisted claim lost (cached stale token?): %+v", run, c)
		}
	}
	if tokenCalls < 2 {
		t.Fatalf("token endpoint called %d times; a cached token outlived its rotation", tokenCalls)
	}
	// No token may be written into any cache file.
	dir := filepath.Join(os.Getenv("LOCKVET_CACHE_DIR"), "http")
	files, _ := os.ReadDir(dir)
	for _, f := range files {
		if b, err := os.ReadFile(filepath.Join(dir, f.Name())); err == nil {
			if strings.Contains(string(b), "tok-") {
				t.Fatalf("token leaked into cache file %s", f.Name())
			}
		}
	}
}
