// Package ocireg verifies container base-image changes (Dockerfile FROM
// pins, Compose image: values) against the image registries themselves.
// There is no OSV.dev ecosystem and no deps.dev system for whole images,
// so for Docker diffs this package IS the metadata layer:
//
//   - Release ages and the ⏱ cooldown flag for Docker Hub images, from
//     the Hub API's per-tag last_updated (the same endpoint the Hub
//     website shows).
//   - An incoming tag the registry does not serve — while the image
//     repository itself IS known — is what a deleted tag, a wrong
//     repository or a made-up reference looks like (▲ unlisted lane).
//   - Digest pins (image:tag@sha256:…) are verified against what the
//     registry serves for the tag TODAY: an exact match (index digest or
//     any per-platform manifest digest) marks the row verified; a pinned
//     digest the registry knows but the tag no longer serves lands in
//     the tag-mismatch lane (image tags DO move — a rebuilt base image
//     looks like this, and so does a pin that never came from the tag);
//     a digest the registry has never seen at all is unlisted.
//
// Lookups run against a fixed allowlist of public registries (Docker
// Hub, ghcr.io, quay.io, mcr.microsoft.com, gcr.io, registry.k8s.io,
// public.ecr.aws, registry.gitlab.com) using the standard OCI
// distribution API with anonymous pull tokens where the registry asks
// for them. Images pinned from any other host — private registries,
// mirrors, localhost — are left alone entirely: lockvet never sends
// requests to hosts it does not recognize.
//
// Neither hub.docker.com nor the token endpoints send CORS headers, so
// the browser (wasm) build sets Enabled=false: the playground still
// parses Dockerfiles and explains digest movements, it just cannot make
// registry claims.
package ocireg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/hcache"
	"github.com/matteo-sung/lockvet/internal/lock"
)

// HubBaseURL is the Docker Hub API base; a var so tests can fake it.
var HubBaseURL = "https://hub.docker.com"

// RegistryBaseURL overrides the OCI distribution API base for ALL hosts
// when non-empty (tests). Production resolves per host.
var RegistryBaseURL = ""

// Enabled gates the whole layer; the wasm build sets it to false (no
// CORS on the Hub API or the registry token endpoints).
var Enabled = true

// Now is a var so tests can pin the clock.
var Now = time.Now

// HTTP/1.1 only: hub.docker.com sits behind a CDN that challenges Go's
// HTTP/2 fingerprint with an interactive page (403 "Just a moment…")
// while answering the identical request over HTTP/1.1. The distribution
// API hosts are indifferent, so one h1 client serves everything.
var client = hcache.ClientHTTP1(20 * time.Second)

// tokenClient fetches anonymous pull tokens and deliberately bypasses
// the response cache: tokens are short-lived credentials — caching one
// both writes a credential to disk and serves it back after expiry
// (every later probe then 401s and the digest claims silently vanish).
var tokenClient = func() *http.Client {
	t := &http.Transport{}
	t.Protocols = new(http.Protocols)
	t.Protocols.SetHTTP1(true)
	return &http.Client{Timeout: 20 * time.Second, Transport: t}
}()

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const maxConcurrent = 6

const acceptManifests = "application/vnd.oci.image.index.v1+json, " +
	"application/vnd.docker.distribution.manifest.list.v2+json, " +
	"application/vnd.oci.image.manifest.v1+json, " +
	"application/vnd.docker.distribution.manifest.v2+json"

// publicHosts is the allowlist of registries lockvet will query.
// docker.io routes to registry-1.docker.io for the distribution API and
// additionally to the Hub API for tag timestamps.
var publicHosts = map[string]string{
	"docker.io":         "https://registry-1.docker.io",
	"ghcr.io":           "https://ghcr.io",
	"quay.io":           "https://quay.io",
	"mcr.microsoft.com": "https://mcr.microsoft.com",
	"gcr.io":            "https://gcr.io",
	"registry.k8s.io":   "https://registry.k8s.io",
	// k8s.gcr.io is the frozen legacy Kubernetes registry: every request
	// 302-redirects to registry.k8s.io with identical repository paths,
	// so pins against the old host verify against the live one.
	"k8s.gcr.io":          "https://registry.k8s.io",
	"public.ecr.aws":      "https://public.ecr.aws",
	"registry.gitlab.com": "https://registry.gitlab.com",
}

// Annotate verifies Docker-ecosystem changes against their registries;
// see the package comment. The returned bool reports whether at least
// one image was actually checked. Best-effort: per-image failures skip
// that image; only total failure returns an error. freshDays mirrors
// -fresh-days.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	if !Enabled {
		return false, nil
	}
	type slot struct{ fd, ci int }
	byName := map[string][]slot{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != string(lock.Docker) || c.NonRegistry || len(c.New) == 0 {
				continue
			}
			host, _ := lock.ImageHost(c.Name)
			if _, ok := publicHosts[host]; !ok {
				continue // unrecognized host: never queried
			}
			byName[c.Name] = append(byName[c.Name], slot{i, j})
		}
	}
	if len(byName) == 0 {
		return false, nil
	}

	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)

	var mu sync.Mutex
	checked := false
	failures := 0
	var firstErr error
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		go func(name string, slots []slot) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r := newRepo(name)
			err := r.probe()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			if !r.known {
				return // registry does not know the repo: flag nothing
			}
			checked = true
			for _, s := range slots {
				annotateChange(&diffs[s.fd].Changes[s.ci], r, freshDays)
			}
		}(name, byName[name])
	}
	wg.Wait()
	if failures == len(names) && firstErr != nil {
		return false, firstErr
	}
	return checked, nil
}

// repo is one image repository being checked.
type repo struct {
	name  string // as pinned ("alpine", "ghcr.io/acme/tool")
	host  string // registry host ("docker.io")
	path  string // repository path on the registry ("library/alpine")
	hub   bool   // docker.io: the Hub API adds tag timestamps
	known bool   // the registry knows the repository

	mu     sync.Mutex
	token  string            // anonymous pull token, once acquired
	tags   map[string]tagRes // tag → lookup result
	exists map[string]int    // digest → HTTP status of existence probe
}

type tagRes struct {
	status    int             // HTTP status of the tag lookup
	digests   map[string]bool // digests the tag serves (index + platforms)
	served    string          // the index/manifest digest the tag serves
	published string          // RFC3339 last_updated (Hub only)
}

func newRepo(name string) *repo {
	host, path := lock.ImageHost(name)
	return &repo{
		name: name, host: host, path: path, hub: host == "docker.io",
		tags: map[string]tagRes{}, exists: map[string]int{},
	}
}

// registryBase resolves the distribution-API base for the repo's host.
func (r *repo) registryBase() string {
	if RegistryBaseURL != "" {
		return RegistryBaseURL
	}
	return publicHosts[r.host]
}

// probe establishes whether the registry knows the repository at all.
// Docker Hub answers via the Hub API; everywhere else a tags/list call
// (n=1) with an anonymous pull token settles it.
func (r *repo) probe() error {
	if r.hub {
		u := ""
		if RegistryBaseURL != "" {
			u = RegistryBaseURL + "/v2/repositories/" + r.path
		} else {
			u = HubBaseURL + "/v2/repositories/" + r.path
		}
		status, _, err := r.get(u, "", false)
		if err != nil {
			return err
		}
		r.known = status == http.StatusOK
		return nil
	}
	status, _, err := r.get(r.registryBase()+"/v2/"+r.path+"/tags/list?n=1", "", true)
	if err != nil {
		return err
	}
	r.known = status == http.StatusOK
	return nil
}

// lookupTag resolves what the registry serves for a tag (memoized).
func (r *repo) lookupTag(tag string) tagRes {
	r.mu.Lock()
	if t, ok := r.tags[tag]; ok {
		r.mu.Unlock()
		return t
	}
	r.mu.Unlock()
	t := r.fetchTag(tag)
	r.mu.Lock()
	r.tags[tag] = t
	r.mu.Unlock()
	return t
}

func (r *repo) fetchTag(tag string) tagRes {
	t := tagRes{digests: map[string]bool{}}
	if r.hub {
		// The Hub API gives digest, per-platform digests AND the tag's
		// last_updated in one response.
		base := HubBaseURL
		if RegistryBaseURL != "" {
			base = RegistryBaseURL
		}
		status, body, err := r.get(base+"/v2/repositories/"+r.path+"/tags/"+url.PathEscape(tag), "", false)
		if err != nil {
			t.status = -1
			return t
		}
		t.status = status
		if status != http.StatusOK {
			return t
		}
		var res struct {
			LastUpdated string `json:"last_updated"`
			Digest      string `json:"digest"`
			Images      []struct {
				Digest string `json:"digest"`
			} `json:"images"`
		}
		if json.Unmarshal(body, &res) != nil {
			t.status = -1
			return t
		}
		t.published = res.LastUpdated
		if res.Digest != "" {
			t.digests[res.Digest] = true
			t.served = res.Digest
		}
		for _, im := range res.Images {
			if im.Digest != "" {
				t.digests[im.Digest] = true
			}
		}
		return t
	}
	status, body, digest, err := r.getManifest(tag)
	if err != nil {
		t.status = -1
		return t
	}
	t.status = status
	if status != http.StatusOK {
		return t
	}
	if digest != "" {
		t.digests[digest] = true
		t.served = digest
	}
	// A manifest LIST body names the per-platform manifests: a digest
	// pin may point at any of them.
	var idx struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if json.Unmarshal(body, &idx) == nil {
		for _, m := range idx.Manifests {
			if m.Digest != "" {
				t.digests[m.Digest] = true
			}
		}
	}
	return t
}

// digestExists probes whether the registry knows a manifest by digest at
// all (memoized). Content-addressed storage: a digest that was ever
// served for this repository stays resolvable.
func (r *repo) digestExists(digest string) int {
	r.mu.Lock()
	if s, ok := r.exists[digest]; ok {
		r.mu.Unlock()
		return s
	}
	r.mu.Unlock()
	status, _, _, err := r.getManifest(digest)
	if err != nil {
		status = -1
	}
	r.mu.Lock()
	r.exists[digest] = status
	r.mu.Unlock()
	return status
}

// getManifest fetches /v2/{path}/manifests/{ref} from the distribution
// API, returning status, body and the Docker-Content-Digest header.
func (r *repo) getManifest(ref string) (int, []byte, string, error) {
	u := r.registryBase() + "/v2/" + r.path + "/manifests/" + url.PathEscape(ref)
	status, body, hdr, err := r.doGet(u, acceptManifests, true)
	if err != nil {
		return 0, nil, "", err
	}
	digest := hdr.Get("Docker-Content-Digest")
	if digest == "" && status == http.StatusOK && len(body) > 0 {
		// Content-addressed fallback: a manifest's digest is by
		// definition the sha256 of the exact bytes served. Covers
		// registries (or cached responses) that omit the header.
		sum := sha256.Sum256(body)
		digest = "sha256:" + hex.EncodeToString(sum[:])
	}
	return status, body, digest, nil
}

func (r *repo) get(u, accept string, auth bool) (int, []byte, error) {
	status, body, _, err := r.doGet(u, accept, auth)
	return status, body, err
}

// doGet performs a GET, transparently acquiring an anonymous pull token
// when the registry answers 401 with a Bearer challenge.
func (r *repo) doGet(u, accept string, auth bool) (int, []byte, http.Header, error) {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return 0, nil, nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if auth {
			r.mu.Lock()
			tok := r.token
			r.mu.Unlock()
			if tok != "" {
				req.Header.Set("Authorization", "Bearer "+tok)
				// Anonymous pull token: cache the answer as anonymous so
				// rotated tokens keep hitting the same entries.
				req.Header.Set(hcache.AnonAuthHeader, "1")
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && auth && attempt == 0 {
			if err := r.fetchToken(resp.Header.Get("Www-Authenticate")); err != nil {
				return resp.StatusCode, body, resp.Header, nil // no anonymous access: treat as the 401
			}
			continue
		}
		return resp.StatusCode, body, resp.Header, nil
	}
}

// fetchToken acquires an anonymous pull token from the endpoint named in
// a Bearer challenge ("Bearer realm=…,service=…").
func (r *repo) fetchToken(challenge string) error {
	if !strings.HasPrefix(challenge, "Bearer ") {
		return fmt.Errorf("no bearer challenge")
	}
	params := map[string]string{}
	for _, kv := range strings.Split(strings.TrimPrefix(challenge, "Bearer "), ",") {
		if eq := strings.IndexByte(kv, '='); eq > 0 {
			params[strings.TrimSpace(kv[:eq])] = strings.Trim(strings.TrimSpace(kv[eq+1:]), `"`)
		}
	}
	realm := params["realm"]
	if realm == "" {
		return fmt.Errorf("no realm in challenge")
	}
	if RegistryBaseURL != "" {
		// Tests: keep token traffic on the test server.
		if u, err := url.Parse(realm); err == nil {
			realm = RegistryBaseURL + u.Path
		}
	}
	q := url.Values{}
	if params["service"] != "" {
		q.Set("service", params["service"])
	}
	q.Set("scope", "repository:"+r.path+":pull")
	req, err := http.NewRequest(http.MethodGet, realm+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := tokenClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token endpoint: %s", resp.Status)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil {
		return err
	}
	t := tok.Token
	if t == "" {
		t = tok.AccessToken
	}
	if t == "" {
		return fmt.Errorf("empty token")
	}
	r.mu.Lock()
	r.token = t
	r.mu.Unlock()
	return nil
}

func annotateChange(c *diffx.Change, r *repo, freshDays int) {
	latest := c.PublishedAt
	for _, v := range c.New {
		pinned := pinnedDigest(c, v)
		if strings.HasPrefix(v, "sha256:") || strings.HasPrefix(v, "sha512:") {
			// Digest-only pin: the displayed version is the short digest;
			// existence is the only claim the registry can settle.
			if pinned != "" && r.digestExists(pinned) == http.StatusNotFound {
				c.Unlisted = true
				c.UnlistedVersions = appendUnique(c.UnlistedVersions, v)
			}
			continue
		}
		t := r.lookupTag(v)
		switch t.status {
		case http.StatusOK:
			if ts := t.published; ts != "" {
				if tm, err := time.Parse(time.RFC3339, ts); err == nil {
					if s := tm.UTC().Format(time.RFC3339); s > latest {
						latest = s
					}
				}
			}
			if pinned == "" {
				continue
			}
			if t.digests[pinned] {
				c.DigestVerified = true
				continue
			}
			// The tag no longer serves the pinned digest. A digest the
			// registry has seen stays resolvable (content-addressed), so
			// a 404 here means the pin never came from this repository.
			switch r.digestExists(pinned) {
			case http.StatusOK:
				c.TagMismatch = true
				c.TagMismatches = append(c.TagMismatches,
					v+" (pinned "+short(pinned)+", tag now serves "+short(t.served)+")")
			case http.StatusNotFound:
				c.Unlisted = true
				c.UnlistedVersions = appendUnique(c.UnlistedVersions, short(pinned))
			}
		case http.StatusNotFound:
			// Repo known (probe passed), tag absent.
			c.Unlisted = true
			c.UnlistedVersions = appendUnique(c.UnlistedVersions, v)
		}
	}
	if latest != "" && latest != c.PublishedAt {
		if t, err := time.Parse(time.RFC3339, latest); err == nil {
			c.PublishedAt = latest
			if age := int(Now().Sub(t).Hours() / 24); age >= 0 {
				c.AgeDays = age
				c.Fresh = freshDays > 0 && Now().Sub(t) < time.Duration(freshDays)*24*time.Hour
			}
		}
	}
	sort.Strings(c.UnlistedVersions)
}

// pinnedDigest returns the digest the new lockfile pins for a version,
// if any.
func pinnedDigest(c *diffx.Change, v string) string {
	for _, f := range strings.Fields(c.NewPins[v]) {
		if strings.HasPrefix(f, "sha256:") || strings.HasPrefix(f, "sha512:") {
			return f
		}
	}
	return ""
}

func short(d string) string {
	if i := strings.IndexByte(d, ':'); i >= 0 && len(d) > i+13 {
		return d[:i+13] + "…"
	}
	return d
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
