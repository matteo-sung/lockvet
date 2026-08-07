// Package bzlreg asks the Bazel Central Registry what it knows about the
// modules a MODULE.bazel.lock diff touches. There is no OSV.dev ecosystem
// and no deps.dev system for Bazel modules, so — like Packagist, hex.pm,
// pub.dev, CRAN, Hackage and conda before it — this package IS the
// metadata layer for Bazel, not a fallback:
//
//   - Yanked versions, with the registry's own reason (BCR yanks releases
//     for CVEs and broken artifacts — protobuf 3.19.0 carries
//     "CVE-2022-3171", 33.3 "Incorrect release artifacts"), land in the
//     deprecation lane. Yanked versions STAY in the registry's version
//     list, which makes the next signal trustworthy:
//   - Unlisted detection: a version absent from the module's metadata.json
//     while the module IS known is real evidence (the registry is a git
//     repository — versions are added, never silently dropped; yanks stay
//     listed). Absence is re-proven with an uncached fetch AND a live
//     probe of the per-version MODULE.bazel file before any claim, so CDN
//     cache lag on a same-hour release can never flag it.
//   - The upstream source repository from metadata.json's repository
//     list ("github:owner/repo"), which the changelog layers turn into
//     verified compare links and release notes.
//
// Release ages are honestly absent: the registry records no publish
// timestamps (they live only in the registry's git history, which would
// cost a clone per lookup). License-change detection likewise: BCR module
// metadata carries no license field.
//
// bcr.bazel.build sends no CORS headers, so the browser (wasm) playground
// skips this layer; the native CLI is unaffected.
package bzlreg

import (
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
	"github.com/matteo-sung/lockvet/internal/vers"
)

// BaseURL is the Bazel Central Registry; a var so tests can fake it.
var BaseURL = "https://bcr.bazel.build"

// Enabled gates the whole layer; the wasm playground sets it false
// (no CORS on bcr.bazel.build).
var Enabled = true

var client = hcache.Client(20 * time.Second)

// liveClient is deliberately uncached: absence evidence for unlisted
// claims is re-proven on every run, like every other unlisted path.
var liveClient = &http.Client{Timeout: 20 * time.Second}

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const maxConcurrent = 8

// metadata is BCR's modules/{name}/metadata.json.
type metadata struct {
	Homepage   string            `json:"homepage"`
	Repository []string          `json:"repository"`
	Versions   []string          `json:"versions"`
	Yanked     map[string]string `json:"yanked_versions"`
}

// Annotate fills Bazel Central Registry metadata on the diffs; see the
// package comment for what it covers. The returned bool reports whether
// at least one module was actually vetted against the registry. freshDays
// is accepted for signature symmetry with the other layers but unused:
// BCR records no publish timestamps.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	_ = freshDays
	if !Enabled {
		return false, nil
	}
	type slot struct{ fd, ci int }
	byPkg := map[string][]slot{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "Bazel" || c.NonRegistry {
				continue
			}
			byPkg[c.Name] = append(byPkg[c.Name], slot{i, j})
		}
	}
	if len(byPkg) == 0 {
		return false, nil
	}

	names := make([]string, 0, len(byPkg))
	for n := range byPkg {
		names = append(names, n)
	}
	sort.Strings(names)
	metas, err := fetchAll(names)
	if err != nil {
		return false, err
	}

	checked := false
	for name, slots := range byPkg {
		m := metas[name]
		if m == nil {
			continue // not in the registry at all, or fetch failed: flag nothing
		}
		checked = true
		for _, s := range slots {
			annotateChange(&diffs[s.fd].Changes[s.ci], name, m)
		}
	}
	return checked, nil
}

func annotateChange(c *diffx.Change, name string, m *metadata) {
	listed := map[string]bool{}
	for _, v := range m.Versions {
		listed[v] = true
	}

	// Yanked versions → the deprecation lane, with the registry's reason.
	if !c.Deprecated {
		for _, v := range c.New {
			if reason, ok := m.Yanked[v]; ok {
				c.Deprecated = true
				msg := fmt.Sprintf("version %s is yanked from the Bazel Central Registry", v)
				if reason != "" {
					msg += ": " + reason
				}
				c.DeprecatedReason = msg
				break
			}
		}
	}

	// Unlisted: incoming versions the registry's version list lacks
	// (yanked versions stay listed, so absence is real evidence). Absence
	// is re-proven live before any claim: first the metadata.json again
	// uncached, then the per-version MODULE.bazel file itself — either
	// knowing the version clears it (CDN cache lag on a fresh release).
	if len(listed) > 0 {
		var missing []string
		for _, v := range c.New {
			if listed[v] {
				continue
			}
			if _, yanked := m.Yanked[v]; yanked {
				continue
			}
			if live := liveVersions(name); live != nil {
				if live[v] {
					continue
				}
			} else {
				continue // can't re-prove absence: make no claim
			}
			if moduleFileExists(name, v) {
				continue
			}
			missing = append(missing, v)
		}
		if len(missing) > 0 {
			c.Unlisted = true
			c.UnlistedVersions = missing
		}
	}

	// Upstream repository, for the changelog layers.
	if c.SourceRepo == "" {
		if repo := repoURL(m); repo != "" {
			c.SourceRepo = repo
		}
	}
}

// repoURL maps BCR's repository entries ("github:owner/repo",
// occasionally full URLs) to a browsable https URL, falling back to a
// forge-shaped homepage.
func repoURL(m *metadata) string {
	for _, r := range m.Repository {
		if owner, ok := strings.CutPrefix(r, "github:"); ok && strings.Contains(owner, "/") {
			return "https://github.com/" + owner
		}
		if strings.HasPrefix(r, "https://") || strings.HasPrefix(r, "http://") {
			return strings.TrimSuffix(r, ".git")
		}
	}
	h := m.Homepage
	if strings.HasPrefix(h, "https://github.com/") || strings.HasPrefix(h, "https://gitlab.com/") {
		if strings.Count(strings.Trim(h, "/"), "/") == 4 { // scheme//host/owner/repo
			return strings.TrimSuffix(h, "/")
		}
	}
	return ""
}

var (
	liveMu   sync.Mutex
	liveMemo = map[string]map[string]bool{}
)

// liveVersions re-fetches the module's version list bypassing the cache;
// nil means the truth could not be established. Memoized per run.
func liveVersions(name string) map[string]bool {
	liveMu.Lock()
	if got, ok := liveMemo[name]; ok {
		liveMu.Unlock()
		return got
	}
	liveMu.Unlock()
	m, err := fetchMetadata(liveClient, name, true)
	var set map[string]bool
	if err == nil && m != nil {
		set = map[string]bool{}
		for _, v := range m.Versions {
			set[v] = true
		}
		for v := range m.Yanked {
			set[v] = true
		}
	}
	liveMu.Lock()
	liveMemo[name] = set
	liveMu.Unlock()
	return set
}

// moduleFileExists live-probes the per-version MODULE.bazel — the other
// file the registry serves for a release. 200 means the registry does
// know the version (metadata cache lag); only a clean miss keeps a claim.
func moduleFileExists(name, version string) bool {
	u := fmt.Sprintf("%s/modules/%s/%s/MODULE.bazel", BaseURL,
		url.PathEscape(name), url.PathEscape(version))
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := liveClient.Do(req)
	if err != nil {
		return true // network trouble: refuse to claim absence
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode != http.StatusNotFound
}

func fetchAll(names []string) (map[string]*metadata, error) {
	out := make(map[string]*metadata, len(names))
	var mu sync.Mutex
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var firstErr error
	for _, name := range names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			m, err := fetchMetadata(client, name, false)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			if m != nil {
				out[name] = m
			}
		}(name)
	}
	wg.Wait()
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// fetchMetadata reads modules/{name}/metadata.json; (nil, nil) on 404.
func fetchMetadata(cl *http.Client, name string, noCache bool) (*metadata, error) {
	u := fmt.Sprintf("%s/modules/%s/metadata.json", BaseURL, url.PathEscape(name))
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if noCache {
		req.Header.Set("Cache-Control", "no-cache")
	}
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	default:
		return nil, fmt.Errorf("bcr.bazel.build answered HTTP %d for %s", resp.StatusCode, name)
	}
	var m metadata
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("bcr.bazel.build: bad metadata for %s: %v", name, err)
	}
	return &m, nil
}

// Latest returns the newest non-yanked release of a BCR module, for
// `lockvet pkg bazel:<name>` — pre-releases (36.0-rc1) are skipped when
// any stable release exists.
func Latest(name string) (string, error) {
	m, err := fetchMetadata(client, name, false)
	if err != nil {
		return "", err
	}
	if m == nil {
		return "", fmt.Errorf("the Bazel Central Registry: module %s not found — check the name (typo here beats typo in your MODULE.bazel)", name)
	}
	best, bestAny := "", ""
	for _, v := range m.Versions {
		if _, yanked := m.Yanked[v]; yanked {
			continue
		}
		if bestAny == "" || vers.Compare(bestAny, v) < 0 {
			bestAny = v
		}
		if strings.Contains(v, "-") {
			continue
		}
		if best == "" || vers.Compare(best, v) < 0 {
			best = v
		}
	}
	if best == "" {
		best = bestAny
	}
	if best == "" {
		return "", fmt.Errorf("the Bazel Central Registry: every version of %s is yanked", name)
	}
	return best, nil
}
