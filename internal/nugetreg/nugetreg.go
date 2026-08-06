// Package nugetreg asks NuGet.org what it knows about the packages a
// diff touches, via the registration index — the same metadata endpoint
// `dotnet restore` itself reads:
//
//   - Unlisted detection, registry-verified. NuGet is the one registry
//     where "unlisted" is a native concept: authors can hide a version
//     (listed:false) while admins DELETE malicious ones outright. A bump
//     onto a stable version the registration index lacks entirely gets
//     the ▲ flag; one the author merely unlisted lands in the
//     deprecation lane (it is still restorable). Absent prereleases are
//     cleared instead — they are overwhelmingly CI-feed builds
//     (Roslyn dailies and friends) that packages.lock.json cannot
//     attribute to their real feed.
//   - Deprecation, with reasons and the suggested replacement package
//     (NuGet records both, e.g. WindowsAzure.Storage →
//     Azure.Storage.Common; deps.dev relays only the bare reason).
//   - License changes old → new from per-version licenseExpression, as
//     a fallback when deps.dev lacks either side.
//   - Release ages and the ⏱ cooldown flag from per-version published
//     times, when deps.dev lags. (NuGet resets published to 1900 on
//     unlisted versions; those timestamps are ignored.)
//
// One anonymous GET per changed package; packages with long histories
// page their registration index, and only pages whose version range
// covers a version the diff mentions are fetched (capped). The endpoint
// allows cross-origin requests, so the browser (wasm) build uses it
// identically.
package nugetreg

import (
	"encoding/json"
	"fmt"
	"github.com/matteo-sung/lockvet/internal/hcache"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// RegURL is the registration-index base; a var so tests can fake it.
var RegURL = "https://api.nuget.org/v3/registration5-gz-semver2"

// Now is a var so tests can pin the clock.
var Now = time.Now

var client = hcache.Client(20 * time.Second)

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const maxConcurrent = 8

// maxPageFetches caps non-inlined registration page downloads per
// package (each is one GET; only pages covering versions the diff
// mentions are candidates anyway).
const maxPageFetches = 4

// verInfo is what lockvet keeps per registered version.
type verInfo struct {
	listed    bool
	published string // RFC3339-ish
	license   string // SPDX expression, "" when unknown
	depReason string // non-empty = deprecated, human-ready reason
}

// pkg is what lockvet keeps per NuGet package. partial reports that at
// least one registration page relevant to the diff could not be
// fetched, in which case absence proves nothing and no version is
// flagged unlisted.
type pkg struct {
	versions map[string]verInfo // normalized lowercase version → info
	partial  bool
}

// Annotate fills NuGet registry signals on the diffs; see the package
// comment for what it covers. Call it AFTER depsdev.Annotate: it
// re-verifies deps.dev-based Unlisted flags (clearing ones NuGet itself
// disproves, adding listed:false ones deps.dev cannot see) and only
// backfills ages/licenses deps.dev lacks. freshDays mirrors the
// -fresh-days flag. Best-effort: per-package failures skip that
// package; only total failure returns an error.
func Annotate(diffs []diffx.FileDiff, freshDays int) error {
	type slot struct{ fd, ci int }
	byPkg := map[string][]slot{}
	wanted := map[string]map[string]bool{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "NuGet" || c.NonRegistry {
				continue
			}
			if len(c.New) == 0 && !c.Unlisted {
				continue // removals: nothing incoming to vet
			}
			key := strings.ToLower(c.Name)
			byPkg[key] = append(byPkg[key], slot{i, j})
			if wanted[key] == nil {
				wanted[key] = map[string]bool{}
			}
			for _, v := range append(append([]string{}, c.Old...), c.New...) {
				wanted[key][normalize(v)] = true
			}
		}
	}
	if len(byPkg) == 0 {
		return nil
	}

	names := make([]string, 0, len(byPkg))
	for n := range byPkg {
		names = append(names, n)
	}
	sort.Strings(names)
	pkgs, err := fetchAll(names, wanted)
	if err != nil {
		return err
	}

	for name, slots := range byPkg {
		p := pkgs[name]
		if p == nil {
			continue // not on NuGet at all, or fetch failed: flag nothing
		}
		for _, s := range slots {
			annotateChange(&diffs[s.fd].Changes[s.ci], p, freshDays)
		}
	}
	return nil
}

func annotateChange(c *diffx.Change, p *pkg, freshDays int) {
	// Unlisted: registry-verified, and split the way NuGet itself
	// splits it. A version the index carries with listed:false was
	// HIDDEN by its author — still restorable, so it lands in the
	// deprecation lane (deps.dev agrees: it relays those as reason
	// "Unlisted"). A version ABSENT from the registration index
	// altogether is what an admin-deleted (malicious) package looks
	// like and keeps the ▲ flag — but only for stable versions:
	// absent prereleases are overwhelmingly CI-feed builds (Roslyn
	// dailies etc.) that packages.lock.json cannot attribute to their
	// feed, so they are cleared rather than flagged. When relevant
	// pages could not be fetched, absence proves nothing: keep only
	// what deps.dev already claimed.
	was := map[string]bool{}
	for _, v := range c.UnlistedVersions {
		was[v] = true
	}
	hidden := false
	var missing []string
	for _, v := range c.New {
		vi, known := p.lookup(v)
		switch {
		case known && vi.listed:
			continue
		case known: // listed:false — author-unlisted, restorable
			hidden = true
		case isPrerelease(v):
			continue // likely a CI-feed build, not nuget.org's to know
		case !p.partial || was[v]:
			missing = append(missing, v)
		}
	}
	c.UnlistedVersions = missing
	c.Unlisted = len(missing) > 0
	if hidden {
		c.Deprecated = true
		if c.DeprecatedReason == "" {
			c.DeprecatedReason = "unlisted on the registry (hidden by its author)"
		}
	}

	if len(c.New) == 0 {
		return
	}

	// Release age backfill: deps.dev can lag NuGet; the index's
	// published time is authoritative. Keep the newest incoming time.
	// (Unlisted versions carry a 1900 sentinel — parseTime rejects it.)
	latest := c.PublishedAt
	for _, v := range c.New {
		if vi, ok := p.lookup(v); ok && vi.listed {
			if t, err := parseTime(vi.published); err == nil {
				if ts := t.UTC().Format(time.RFC3339); ts > latest {
					latest = ts
				}
			}
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

	// Deprecation: NuGet records reasons AND the suggested replacement
	// package. deps.dev relays the bare reason ("Legacy") but not the
	// replacement, so a richer reason from the registration index
	// upgrades whatever an earlier layer left; otherwise existing
	// reasons stand.
	for _, v := range c.New {
		vi, ok := p.lookup(v)
		if !ok || vi.depReason == "" {
			continue
		}
		c.Deprecated = true
		if c.DeprecatedReason == "" || strings.Contains(vi.depReason, "; use ") {
			c.DeprecatedReason = vi.depReason
		}
		break
	}

	// License change: fallback only — deps.dev covers NuGet licenses,
	// so claim nothing it already filled in.
	if c.OldLicense == "" && c.NewLicense == "" && len(c.Old) > 0 && len(c.New) > 0 {
		oldLic := newestLicense(p, c.Old)
		newLic := newestLicense(p, c.New)
		if oldLic != "" && newLic != "" {
			c.OldLicense, c.NewLicense = oldLic, newLic
			c.LicenseChanged = !strings.EqualFold(oldLic, newLic)
		}
	}
}

func (p *pkg) lookup(v string) (verInfo, bool) {
	vi, ok := p.versions[normalize(v)]
	return vi, ok
}

// newestLicense returns the license of the most recently published
// listed version among vs, or "".
func newestLicense(p *pkg, vs []string) string {
	best, bestTime := "", ""
	for _, v := range vs {
		vi, ok := p.lookup(v)
		if !ok || vi.license == "" {
			continue
		}
		if best == "" || vi.published > bestTime {
			best, bestTime = vi.license, vi.published
		}
	}
	return best
}

// normalize maps a version string onto NuGet's normalized form as far
// as matching needs: build metadata stripped, prerelease tags
// case-folded (NuGet compares them case-insensitively).
func normalize(v string) string {
	v, _, _ = strings.Cut(v, "+")
	return strings.ToLower(strings.TrimSpace(v))
}

// isPrerelease reports a SemVer prerelease (anything after a dash).
func isPrerelease(v string) bool { return strings.Contains(v, "-") }

// parseTime accepts the timestamps NuGet emits and rejects the
// 1900-01-01 sentinel it stores for unlisted versions.
func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return t, err
	}
	if t.Year() < 1980 {
		return t, fmt.Errorf("sentinel timestamp %s", s)
	}
	return t, nil
}

// ---- registration index fetching ----

type regIndex struct {
	Items []regPage `json:"items"`
}

type regPage struct {
	ID    string    `json:"@id"`
	Lower string    `json:"lower"`
	Upper string    `json:"upper"`
	Items []regLeaf `json:"items"` // inlined for short histories
}

type regLeaf struct {
	CatalogEntry struct {
		Version           string `json:"version"`
		Listed            *bool  `json:"listed"` // absent means listed
		Published         string `json:"published"`
		LicenseExpression string `json:"licenseExpression"`
		Deprecation       *struct {
			Message          string   `json:"message"`
			Reasons          []string `json:"reasons"`
			AlternatePackage *struct {
				ID string `json:"id"`
			} `json:"alternatePackage"`
		} `json:"deprecation"`
	} `json:"catalogEntry"`
}

func fetchAll(names []string, wanted map[string]map[string]bool) (map[string]*pkg, error) {
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
			p, err := fetchPkg(name, wanted[name])
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
		return nil, fmt.Errorf("NuGet registry unreachable: %w", firstErr)
	}
	return out, nil
}

// fetchPkg downloads one package's registration index and any
// non-inlined pages whose version range covers a version the diff
// mentions. nil, nil means the package is unknown to NuGet.
func fetchPkg(name string, want map[string]bool) (*pkg, error) {
	var idx regIndex
	status, err := getJSON(RegURL+"/"+strings.ToLower(name)+"/index.json", &idx)
	if err != nil {
		return nil, err
	}
	if status == 404 || len(idx.Items) == 0 {
		return nil, nil // unknown to NuGet: flag nothing
	}
	p := &pkg{versions: map[string]verInfo{}}
	budget := maxPageFetches
	for i := range idx.Items {
		page := &idx.Items[i]
		if page.Items == nil {
			if !pageWanted(page, want) {
				continue
			}
			if budget <= 0 || page.ID == "" {
				p.partial = true
				continue
			}
			budget--
			var full regPage
			if status, err := getJSON(page.ID, &full); err != nil || status != 200 {
				p.partial = true
				continue
			}
			page.Items = full.Items
		}
		for _, leaf := range page.Items {
			ce := leaf.CatalogEntry
			if ce.Version == "" {
				continue
			}
			p.versions[normalize(ce.Version)] = verInfo{
				listed:    ce.Listed == nil || *ce.Listed,
				published: ce.Published,
				license:   ce.LicenseExpression,
				depReason: depReason(ce.Deprecation),
			}
		}
	}
	return p, nil
}

// pageWanted reports whether any wanted version falls inside the page's
// [lower, upper] range. Pages with unparsable bounds are fetched when
// anything is wanted at all — better one spare GET than a wrong flag.
func pageWanted(page *regPage, want map[string]bool) bool {
	if len(want) == 0 {
		return false
	}
	if page.Lower == "" || page.Upper == "" {
		return true
	}
	lo, hi := normalize(page.Lower), normalize(page.Upper)
	for v := range want {
		if vers.Compare(v, lo) >= 0 && vers.Compare(v, hi) <= 0 {
			return true
		}
	}
	return false
}

func depReason(d *struct {
	Message          string   `json:"message"`
	Reasons          []string `json:"reasons"`
	AlternatePackage *struct {
		ID string `json:"id"`
	} `json:"alternatePackage"`
}) string {
	if d == nil {
		return ""
	}
	var bits []string
	for _, r := range d.Reasons {
		switch r {
		case "Legacy":
			bits = append(bits, "legacy")
		case "CriticalBugs":
			bits = append(bits, "has critical bugs")
		case "Other":
			// carries no information on its own
		default:
			bits = append(bits, r)
		}
	}
	reason := strings.Join(bits, ", ")
	if reason == "" {
		reason = "deprecated upstream"
	}
	if d.AlternatePackage != nil && d.AlternatePackage.ID != "" {
		reason += "; use " + d.AlternatePackage.ID + " instead"
	}
	return reason
}

func getJSON(url string, dst any) (int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
		return 200, json.NewDecoder(resp.Body).Decode(dst)
	case 404:
		return 404, nil
	default:
		return resp.StatusCode, fmt.Errorf("NuGet registry returned HTTP %d", resp.StatusCode)
	}
}
