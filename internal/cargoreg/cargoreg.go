// Package cargoreg asks crates.io what it knows about the versions a
// diff introduces:
//
//   - Trusted-publishing provenance: crates.io records which releases
//     were published through a trusted-publishing pipeline
//     (trustpub_data). A bump that silently DROPS that where every
//     previous release carried it is what publishing with a stolen API
//     token looks like — a token thief can publish, but cannot make the
//     project's CI pipeline do it. Same three gates as npm/PyPI:
//     outgoing pin attested, practice established right below the
//     incoming version, and the release is young (≤30 days) or too new
//     to be indexed.
//   - Yanks: an incoming version its maintainers yanked deserves a
//     look. deps.dev carries most of these already; this is the lag
//     fallback, and it never overwrites a reason deps.dev supplied.
//   - The version list re-verifies Unlisted flags set by the deps.dev
//     layer, which can lag crates.io by days: a version the registry
//     serves is not unlisted; a version crates.io itself lacks keeps
//     the flag — deleted malicious crates disappear from the index
//     entirely (yanked ones do not), so absence is exactly what a
//     pulled release looks like.
//
// The native build reads the sparse index (one anonymous GET per
// changed crate; the same static CDN cargo itself hammers, no rate
// limits) and only consults the crates.io API for the few
// provenance-candidate crates — young bumps — since trustpub data only
// lives there. The browser (wasm) build uses the API for everything:
// the sparse index sends no CORS headers, the API answers with
// Access-Control-Allow-Origin: *.
package cargoreg

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// IndexURL is the sparse-index base; a var so tests can fake it.
var IndexURL = "https://index.crates.io"

// APIURL is the crates.io API base; a var so tests can fake it.
var APIURL = "https://crates.io/api/v1"

// UseAPI switches the version-listing fetch from the sparse index to
// the API. The browser (wasm) build sets it: the sparse index has no
// CORS headers, the API does.
var UseAPI = false

// provenanceMaxAgeDays: incoming versions older than this never get the
// provenance-dropped flag (see the age gate in Annotate).
const provenanceMaxAgeDays = 30

// maxSingles caps per-crate single-version API lookups (old pins or
// practice-window versions beyond the first API page).
const maxSingles = 6

var client = &http.Client{Timeout: 20 * time.Second}

// Now is a var so tests can pin the clock.
var Now = time.Now

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

// verInfo is what lockvet keeps per crates.io version.
type verInfo struct {
	yanked  bool
	yankMsg string // API only; the index has no yank messages
	trust   *bool  // trusted-publishing provenance; nil = not known yet
	created string // RFC3339, API only
}

func attested(v *verInfo) bool { return v != nil && v.trust != nil && *v.trust }

type crate struct {
	versions map[string]*verInfo
	complete bool // full version set known (index path, or API total fit one page)
	apiDone  bool // API versions page already merged
	singles  int  // single-version lookups spent
}

// Annotate fills crates.io registry signals on the diffs; see the
// package comment for what it flags. Call it AFTER depsdev.Annotate (it
// re-verifies deps.dev-based Unlisted flags and never overwrites a
// deprecation reason deps.dev already supplied). Best-effort: network
// errors return an error but leave diffs usable.
func Annotate(diffs []diffx.FileDiff) error {
	type slot struct{ fd, ci int }
	byName := map[string][]slot{} // every crates.io change with an incoming side
	verify := map[string][]slot{} // unlisted-flagged changes per name
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "crates.io" {
				continue
			}
			if c.Unlisted {
				verify[c.Name] = append(verify[c.Name], slot{i, j})
			}
			if c.NonRegistry || len(c.New) == 0 {
				continue
			}
			byName[c.Name] = append(byName[c.Name], slot{i, j})
		}
	}
	if len(byName) == 0 && len(verify) == 0 {
		return nil
	}

	seen := map[string]bool{}
	var names []string
	for _, m := range []map[string][]slot{byName, verify} {
		for n := range m {
			if !seen[n] {
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	crates, err := fetchListings(names)
	if err != nil {
		return err
	}

	for name, slots := range byName {
		p, ok := crates[name]
		if !ok {
			continue // not on crates.io, or fetch failed
		}
		for _, s := range slots {
			c := &diffs[s.fd].Changes[s.ci]

			// Yanks → the deprecation surface, unless deps.dev already
			// carries an upstream reason.
			if !c.Deprecated {
				for _, v := range c.New {
					if info, ok := p.versions[v]; ok && info.yanked {
						c.Deprecated = true
						reason := "version " + v + " was yanked on crates.io"
						if info.yankMsg != "" {
							reason += ": " + firstLine(info.yankMsg)
						}
						c.DeprecatedReason = reason
						break
					}
				}
			}

			// Provenance: transitions only, so bumps only — and only
			// young ones. deps.dev ages are the cheap pre-filter; the
			// registry's own timestamps refine it below.
			if len(c.Old) == 0 || (c.PublishedAt != "" && c.AgeDays > provenanceMaxAgeDays) {
				continue
			}
			mergeAPI(name, p)
			oldSeen, oldAllAttested := true, true
			old := map[string]bool{}
			for _, v := range c.Old {
				old[v] = true
				info := ensureVersion(name, p, v)
				if info == nil || info.trust == nil {
					oldSeen = false
					break
				}
				oldAllAttested = oldAllAttested && *info.trust
			}
			if !oldSeen || !oldAllAttested {
				continue // old side unknown or not attested: no practice to drop
			}
			var unattested []string
			young := false
			for _, v := range c.New {
				if old[v] {
					continue
				}
				info := ensureVersion(name, p, v)
				if info == nil || info.trust == nil {
					continue // not on crates.io (unlisted handles that) or unknown
				}
				if !*info.trust && establishedTrustpub(name, p, v) {
					unattested = append(unattested, v)
					// Age gate, preferring crates.io's own publish time
					// over deps.dev (which can lag): a stolen token is
					// caught in days; an unattested release that has
					// survived a month is a maintainer's regular (if
					// untidy) practice. Unknown age means brand new,
					// so it stays flagged.
					if t, err := time.Parse(time.RFC3339, info.created); err == nil {
						young = young || Now().Sub(t) <= provenanceMaxAgeDays*24*time.Hour
					} else {
						young = young || c.PublishedAt == "" || c.AgeDays <= provenanceMaxAgeDays
					}
				}
			}
			if len(unattested) > 0 && young {
				c.ProvenanceDropped = true
				c.UnattestedVersions = unattested
			}
		}
	}

	// Unlisted verification: keep only versions crates.io itself lacks.
	// (A 404 for the whole crate keeps every flag — the crate is gone
	// from the registry, which is worse.)
	for name, slots := range verify {
		p, ok := crates[name]
		if !ok {
			continue
		}
		for _, s := range slots {
			c := &diffs[s.fd].Changes[s.ci]
			var still []string
			for _, v := range c.UnlistedVersions {
				if _, listed := p.versions[v]; listed {
					continue
				}
				if !p.complete && ensureVersion(name, p, v) != nil {
					continue // beyond the first API page, but real
				}
				still = append(still, v)
			}
			c.UnlistedVersions = still
			c.Unlisted = len(still) > 0
		}
	}
	return nil
}

// establishedTrustpub reports whether the crate's trusted-publishing
// practice was established right below the incoming version: the
// highest 3 stable (non-prerelease, non-yanked) versions strictly below
// it must ALL carry trustpub provenance, and at least 2 such versions
// must exist. One-off adopters stay quiet; crates that consistently
// publish via CI — the ones where a silent drop means something — stay
// covered.
func establishedTrustpub(name string, p *crate, incoming string) bool {
	var below []string
	for v, info := range p.versions {
		if info.yanked || isPrerelease(v) {
			continue
		}
		if vers.Compare(v, incoming) < 0 {
			below = append(below, v)
		}
	}
	sort.Slice(below, func(i, j int) bool { return vers.Compare(below[i], below[j]) > 0 })
	if len(below) > 3 {
		below = below[:3]
	}
	if len(below) < 2 {
		return false
	}
	for _, v := range below {
		info := ensureVersion(name, p, v)
		if info == nil || info.trust == nil || !*info.trust {
			return false
		}
	}
	return true
}

func isPrerelease(v string) bool {
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i] // build metadata is not a prerelease marker
	}
	return strings.Contains(v, "-")
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// fetchListings downloads each crate's version listing a few at a time:
// sparse-index documents natively, API version pages under wasm. 404s
// yield no entry; other HTTP failures abort with an error so callers
// can warn once.
func fetchListings(names []string) (map[string]*crate, error) {
	out := make(map[string]*crate, len(names))
	var mu sync.Mutex
	var firstErr error
	workers := 8
	if UseAPI {
		workers = 4
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			mu.Lock()
			stop := firstErr != nil
			mu.Unlock()
			if stop {
				return
			}
			var p *crate
			var err error
			if UseAPI {
				p, err = fetchAPIListing(name)
			} else {
				p, err = fetchIndexListing(name)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
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
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// indexPath maps a crate name to its sparse-index path (lowercased;
// 1/, 2/, 3/<c>/ prefixes for short names, aa/bb/ otherwise).
func indexPath(name string) string {
	n := strings.ToLower(name)
	switch len(n) {
	case 0:
		return ""
	case 1:
		return "/1/" + n
	case 2:
		return "/2/" + n
	case 3:
		return "/3/" + n[:1] + "/" + n
	default:
		return "/" + n[:2] + "/" + n[2:4] + "/" + n
	}
}

func fetchIndexListing(name string) (*crate, error) {
	path := indexPath(name)
	if path == "" {
		return nil, nil
	}
	resp, err := get(IndexURL + path)
	if err != nil {
		return nil, fmt.Errorf("crates.io index unreachable: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
	case 404, 410, 451:
		return nil, nil // not on crates.io (410/451: removed)
	default:
		return nil, fmt.Errorf("crates.io index returned HTTP %d", resp.StatusCode)
	}
	p := &crate{versions: map[string]*verInfo{}, complete: true}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 1<<16), 1<<22)
	for sc.Scan() {
		var line struct {
			Vers   string `json:"vers"`
			Yanked bool   `json:"yanked"`
		}
		if json.Unmarshal(sc.Bytes(), &line) != nil || line.Vers == "" {
			continue
		}
		p.versions[line.Vers] = &verInfo{yanked: line.Yanked}
	}
	if len(p.versions) == 0 {
		return nil, nil
	}
	return p, nil
}

// apiVersion is the slice of a crates.io API version object we use.
type apiVersion struct {
	Num       string          `json:"num"`
	Yanked    bool            `json:"yanked"`
	YankMsg   *string         `json:"yank_message"`
	Trustpub  json.RawMessage `json:"trustpub_data"`
	CreatedAt string          `json:"created_at"`
}

func (v apiVersion) info() *verInfo {
	t := len(v.Trustpub) > 0 && string(v.Trustpub) != "null"
	info := &verInfo{yanked: v.Yanked, trust: &t, created: v.CreatedAt}
	if v.YankMsg != nil {
		info.yankMsg = *v.YankMsg
	}
	return info
}

func fetchAPIListing(name string) (*crate, error) {
	resp, err := get(APIURL + "/crates/" + name + "/versions?per_page=100")
	if err != nil {
		return nil, fmt.Errorf("crates.io unreachable: %w", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
	case 404, 410, 451:
		return nil, nil
	default:
		return nil, fmt.Errorf("crates.io returned HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Versions []apiVersion `json:"versions"`
		Meta     struct {
			Total int `json:"total"`
		} `json:"meta"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil || len(doc.Versions) == 0 {
		return nil, nil
	}
	p := &crate{versions: make(map[string]*verInfo, len(doc.Versions)), apiDone: true}
	for _, v := range doc.Versions {
		if v.Num != "" {
			p.versions[v.Num] = v.info()
		}
	}
	p.complete = doc.Meta.Total <= len(doc.Versions)
	return p, nil
}

// mergeAPI overlays the crate's first API versions page (trustpub,
// created_at, yank messages) onto an index-fetched listing. Best-effort
// and idempotent; only called for provenance candidates.
func mergeAPI(name string, p *crate) {
	if p.apiDone {
		return
	}
	p.apiDone = true
	api, err := fetchAPIListing(name)
	if err != nil || api == nil {
		return
	}
	for v, info := range api.versions {
		p.versions[v] = info
	}
}

// ensureVersion returns what is known about one version, spending a
// single-version API lookup (capped per crate) when the version is
// absent from the listing or lacks trustpub data. nil means the version
// is not on crates.io or could not be resolved; a non-nil result with
// trust == nil means "exists, provenance unknown" — callers treat that
// conservatively.
func ensureVersion(name string, p *crate, ver string) *verInfo {
	info := p.versions[ver]
	if info != nil && info.trust != nil {
		return info
	}
	if p.singles >= maxSingles {
		return info
	}
	p.singles++
	resp, err := get(APIURL + "/crates/" + name + "/" + ver)
	if err != nil {
		return info
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		if resp.StatusCode == 404 || resp.StatusCode == 410 {
			return nil // definitively not on crates.io
		}
		return info
	}
	var doc struct {
		Version apiVersion `json:"version"`
	}
	if json.NewDecoder(resp.Body).Decode(&doc) != nil || doc.Version.Num == "" {
		return info
	}
	fresh := doc.Version.info()
	p.versions[doc.Version.Num] = fresh
	return fresh
}

func get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	return client.Do(req)
}
