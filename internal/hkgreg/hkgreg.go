// Package hkgreg asks Hackage what it knows about the Haskell packages
// a diff touches (stack.yaml.lock and cabal.project.freeze pin Hackage
// releases). deps.dev has no Hackage system at all, so — like Packagist,
// hex.pm, pub.dev and CRAN before it — this package IS the metadata
// layer for Haskell, not a fallback:
//
//   - Release ages and the ⏱ cooldown flag, from the per-version
//     upload-time endpoint (hackage.haskell.org is the canonical
//     registry, so timestamps are authoritative, not mirrored).
//   - Deprecated packages from Hackage's registry-wide deprecation
//     list, including the maintainer's suggested replacements
//     (cryptonite → crypton and friends), land in the deprecation lane.
//   - Deprecated *versions* (Hackage's preferred-versions mechanism —
//     its yank equivalent; the tarball stays but solvers avoid it)
//     land in the same lane.
//   - Unlisted detection: Hackage never deletes versions — deprecated
//     ones stay in the package's version map — so a version absent
//     from the map while the package IS known is real evidence
//     (admin removals and malicious uploads look exactly like this).
//     Absence is re-proven with an uncached fetch before any claim, so
//     a same-hour release can never be flagged off a stale cache.
//   - The upstream source repository from the release's .cabal file
//     (source-repository head, with homepage as fallback), which the
//     changelog layers turn into verified compare links and release
//     notes.
//
// License-change detection is honestly skipped: Hackage's per-version
// license metadata uses SPDX for new uploads but legacy identifiers
// historically, and the .cabal-per-version fetches to compare both
// sides would double the request budget for a signal that is noisy
// across the cabal-license-format migration.
//
// hackage.haskell.org sends no CORS headers, so the browser (wasm)
// playground skips this layer; the native CLI is unaffected.
package hkgreg

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

// BaseURL is the Hackage server; a var so tests can fake it.
var BaseURL = "https://hackage.haskell.org"

// Enabled gates the whole layer; the wasm playground sets it false
// (no CORS on hackage.haskell.org).
var Enabled = true

// Now is a var so tests can pin the clock.
var Now = time.Now

var client = hcache.Client(20 * time.Second)

// liveClient is deliberately uncached: absence evidence for unlisted
// claims is re-proven on every run, like every other unlisted path.
var liveClient = &http.Client{Timeout: 20 * time.Second}

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const maxConcurrent = 8

// pkg is what lockvet keeps per Hackage package.
type pkg struct {
	versions map[string]string // version → status ("normal" or deprecated/unpreferred)
	uploaded map[string]string // version → RFC3339 upload time (incoming versions only)
	source   string            // upstream repository URL, may be ""
}

// Annotate fills Hackage metadata on the diffs; see the package comment
// for what it covers. The returned bool reports whether at least one
// package was actually vetted against Hackage (deps.dev never covers
// Hackage, so this decides whether release metadata was checked at all
// for Haskell). freshDays mirrors -fresh-days. Best-effort: per-package
// failures skip that package; only total failure returns an error.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	if !Enabled {
		return false, nil
	}
	type slot struct{ fd, ci int }
	byPkg := map[string][]slot{}
	incoming := map[string]map[string]bool{} // name → versions to date
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "Hackage" || c.NonRegistry {
				continue
			}
			byPkg[c.Name] = append(byPkg[c.Name], slot{i, j})
			for _, v := range c.New {
				if incoming[c.Name] == nil {
					incoming[c.Name] = map[string]bool{}
				}
				incoming[c.Name][v] = true
			}
		}
	}
	if len(byPkg) == 0 {
		return false, nil
	}

	deprecated := deprecatedPackages() // best-effort; nil on failure

	names := make([]string, 0, len(byPkg))
	for n := range byPkg {
		names = append(names, n)
	}
	sort.Strings(names)
	pkgs, err := fetchAll(names, incoming)
	if err != nil {
		return false, err
	}

	checked := false
	for name, slots := range byPkg {
		p := pkgs[name]
		if p == nil {
			continue // not on Hackage at all, or fetch failed: flag nothing
		}
		checked = true
		for _, s := range slots {
			annotateChange(&diffs[s.fd].Changes[s.ci], name, p, deprecated[name], freshDays)
		}
	}
	return checked, nil
}

func annotateChange(c *diffx.Change, name string, p *pkg, replacements []string, freshDays int) {
	// Release age: keep the most recently uploaded incoming version,
	// exactly like the deps.dev layer does elsewhere.
	latest := c.PublishedAt
	for _, v := range c.New {
		if ts := p.uploaded[v]; ts > latest {
			latest = ts
		}
	}
	if latest != "" && latest != c.PublishedAt {
		if t, err := time.Parse(time.RFC3339, latest); err == nil {
			c.PublishedAt = t.UTC().Format(time.RFC3339)
			if age := int(Now().Sub(t).Hours() / 24); age >= 0 {
				c.AgeDays = age
				c.Fresh = freshDays > 0 && Now().Sub(t) < time.Duration(freshDays)*24*time.Hour
			}
		}
	}

	// Deprecation lane. Package-level deprecation taints every incoming
	// version (removals are good news and stay quiet); the maintainer's
	// suggested replacements ride along.
	if replacements != nil && len(c.New) > 0 {
		c.Deprecated = true
		if c.DeprecatedReason == "" {
			reason := "deprecated on Hackage"
			if len(replacements) > 0 {
				reason += "; use " + humanList(replacements) + " instead"
			}
			c.DeprecatedReason = reason
		}
	}
	// Version-level: Hackage's preferred-versions can mark individual
	// releases deprecated (its yank equivalent).
	if !c.Deprecated {
		for _, v := range c.New {
			if st, ok := p.versions[v]; ok && st != "" && st != "normal" {
				c.Deprecated = true
				if c.DeprecatedReason == "" {
					c.DeprecatedReason = fmt.Sprintf("version %s is marked %s on Hackage (solvers avoid it)", v, st)
				}
				break
			}
		}
	}

	// Unlisted: incoming versions the version map lacks while the
	// package IS known. Hackage never deletes versions (deprecated ones
	// stay listed), so absence is real evidence — but it is re-proven
	// with an uncached fetch so a stale 1h cache can never flag a
	// release published minutes ago.
	if len(p.versions) > 0 {
		var missing []string
		for _, v := range c.New {
			if _, ok := p.versions[v]; ok {
				continue
			}
			if live := liveVersions(name); live != nil {
				if _, ok := live[v]; ok {
					continue // cache lag: Hackage knows it after all
				}
			} else {
				continue // can't re-prove absence: make no claim
			}
			missing = append(missing, v)
		}
		if len(missing) > 0 {
			c.Unlisted = true
			c.UnlistedVersions = missing
		}
	}

	// Upstream repository, for the changelog layers.
	if c.SourceRepo == "" && p.source != "" {
		c.SourceRepo = p.source
	}
}

// humanList renders ["a","b","c"] as "a, b or c", capped at three.
func humanList(items []string) string {
	if len(items) > 3 {
		items = items[:3]
	}
	switch len(items) {
	case 1:
		return items[0]
	default:
		return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
	}
}

// Latest returns the current preferred Hackage release of name, for
// `lockvet pkg hackage:<name>` — the highest version not marked
// deprecated/unpreferred.
func Latest(name string) (string, error) {
	vsn, err := fetchVersions(client, name)
	if err != nil {
		return "", err
	}
	if vsn == nil {
		return "", fmt.Errorf("Hackage: package %s not found", name)
	}
	best := ""
	for v, st := range vsn {
		if st != "normal" {
			continue
		}
		if best == "" || vers.Compare(best, v) < 0 {
			best = v
		}
	}
	if best == "" {
		return "", fmt.Errorf("Hackage: every version of %s is deprecated", name)
	}
	return best, nil
}

func fetchAll(names []string, incoming map[string]map[string]bool) (map[string]*pkg, error) {
	out := make(map[string]*pkg, len(names))
	var mu sync.Mutex
	var firstErr error
	failures := 0
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			p, err := fetchPkg(name, incoming[name])
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			if p != nil {
				out[name] = p
			}
		}(name)
	}
	wg.Wait()
	if failures == len(names) && firstErr != nil {
		return nil, firstErr // total failure: report it
	}
	return out, nil
}

// fetchPkg returns nil, nil when Hackage does not know the package.
func fetchPkg(name string, incoming map[string]bool) (*pkg, error) {
	vsn, err := fetchVersions(client, name)
	if err != nil || vsn == nil {
		return nil, err
	}
	p := &pkg{versions: vsn, uploaded: map[string]string{}}

	// Upload times: one small GET per incoming version Hackage lists.
	// Also pick the newest listed incoming version for the .cabal fetch.
	newestIn := ""
	for v := range incoming {
		if _, ok := vsn[v]; !ok {
			continue
		}
		if ts := uploadTime(name, v); ts != "" {
			p.uploaded[v] = ts
		}
		if newestIn == "" || vers.Compare(newestIn, v) < 0 {
			newestIn = v
		}
	}
	if newestIn != "" {
		p.source = cabalRepo(name, newestIn)
	}
	return p, nil
}

// fetchVersions returns the version → status map, or nil when Hackage
// does not know the package.
func fetchVersions(c *http.Client, name string) (map[string]string, error) {
	body, status, err := get(c, BaseURL+"/package/"+url.PathEscape(name)+".json")
	if err != nil {
		return nil, fmt.Errorf("hackage unreachable: %w", err)
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("hackage rate limit hit; retry in a minute")
	default:
		return nil, fmt.Errorf("hackage answered %d for %s", status, name)
	}
	var vsn map[string]string
	if err := json.Unmarshal(body, &vsn); err != nil {
		return nil, fmt.Errorf("hackage metadata for %s: %w", name, err)
	}
	if len(vsn) == 0 {
		return nil, nil
	}
	return vsn, nil
}

// liveVersions re-fetches the version map with the uncached client;
// nil when the fetch fails (absence then goes unclaimed). Memoized for
// the run: one live fetch per package no matter how many versions or
// lockfiles ask.
var liveMemo sync.Map // name → map[string]string (nil stored as untyped nil check)

func liveVersions(name string) map[string]string {
	if v, ok := liveMemo.Load(name); ok {
		m, _ := v.(map[string]string)
		return m
	}
	var out map[string]string
	vsn, err := fetchVersions(liveClient, name)
	switch {
	case err != nil:
		out = nil
	case vsn == nil:
		out = map[string]string{} // Hackage confirms: not there
	default:
		out = vsn
	}
	liveMemo.Store(name, out)
	return out
}

// uploadTime returns the RFC3339 upload time of name-version, or "".
func uploadTime(name, version string) string {
	body, status, err := get(client, BaseURL+"/package/"+url.PathEscape(name)+"-"+url.PathEscape(version)+"/upload-time")
	if err != nil || status != http.StatusOK {
		return ""
	}
	ts := strings.TrimSpace(string(body))
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		return ""
	}
	return ts
}

// cabalRepo extracts the upstream repository from the release's .cabal
// file: source-repository location first, homepage/bug-reports fallback.
func cabalRepo(name, version string) string {
	body, status, err := get(client, BaseURL+"/package/"+url.PathEscape(name)+"-"+url.PathEscape(version)+"/"+url.PathEscape(name)+".cabal")
	if err != nil || status != http.StatusOK {
		return ""
	}
	var location, homepage, bugs string
	inRepo := false
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "source-repository"):
			inRepo = true
		case inRepo && strings.HasPrefix(lower, "location:"):
			if location == "" {
				location = strings.TrimSpace(trimmed[len("location:"):])
			}
			inRepo = false
		case strings.HasPrefix(lower, "homepage:"):
			homepage = strings.TrimSpace(trimmed[len("homepage:"):])
		case strings.HasPrefix(lower, "bug-reports:"):
			bugs = strings.TrimSpace(trimmed[len("bug-reports:"):])
		}
	}
	return repoURL(location, homepage, bugs)
}

// repoURL reduces candidate URLs (git://, https://, .git suffixes,
// /issues suffixes) to the bare forge repository the changelog layers
// can work with.
func repoURL(candidates ...string) string {
	for _, u := range candidates {
		u = strings.TrimSuffix(strings.TrimSpace(u), "/")
		u = strings.Replace(u, "git://", "https://", 1)
		for _, host := range []string{"https://github.com/", "https://gitlab.com/", "https://codeberg.org/", "https://bitbucket.org/"} {
			rest, ok := strings.CutPrefix(u, host)
			if !ok {
				continue
			}
			parts := strings.Split(rest, "/")
			if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
				continue
			}
			return host + parts[0] + "/" + strings.TrimSuffix(parts[1], ".git")
		}
	}
	return ""
}

// deprecatedPackages fetches Hackage's registry-wide deprecation list:
// package → suggested replacements (possibly empty, never nil for a
// deprecated package). Best-effort: nil on any failure.
func deprecatedPackages() map[string][]string {
	body, status, err := get(client, BaseURL+"/packages/deprecated.json")
	if err != nil || status != http.StatusOK {
		return nil
	}
	var list []struct {
		Package    string   `json:"deprecated-package"`
		InFavourOf []string `json:"in-favour-of"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		return nil
	}
	out := make(map[string][]string, len(list))
	for _, e := range list {
		if e.Package == "" {
			continue
		}
		if e.InFavourOf == nil {
			e.InFavourOf = []string{}
		}
		out[e.Package] = e.InFavourOf
	}
	return out
}

func get(c *http.Client, u string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json, text/plain")
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}
