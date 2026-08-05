// Package phpreg asks Packagist what it knows about the Composer
// packages a diff touches. deps.dev has no Composer/Packagist system at
// all, so for PHP this package IS the metadata layer, not a fallback:
//
//   - Release ages and the ⏱ cooldown flag, from the per-version `time`
//     Packagist records.
//   - Abandoned packages (Composer's deprecation mechanism) land in the
//     deprecation lane, with the suggested replacement when the
//     maintainer named one.
//   - License changes old → new, from the per-version license list.
//   - Unlisted detection: an incoming version missing from Packagist
//     while the package's other versions ARE listed is what an
//     unpublished/deleted release looks like. Packages Packagist does
//     not know at all (private registries, VCS pins) are never flagged,
//     and the composer.lock parser marks non-Packagist sources
//     NonRegistry besides.
//   - The upstream source repository, which the changelog layers turn
//     into verified compare links and release notes.
//
// One anonymous GET per changed package. The native build reads
// Composer's own p2 metadata endpoint (repo.packagist.org — the CDN
// `composer update` itself hammers, no auth, no limits); it sends no
// CORS headers, so the browser (wasm) build sets UseAPI and reads the
// CORS-open packagist.org/packages/{name}.json instead.
package phpreg

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// RepoURL is the p2 metadata base (native builds); a var so tests can
// fake it.
var RepoURL = "https://repo.packagist.org"

// APIURL is the packagist.org API base (wasm builds); a var so tests can
// fake it.
var APIURL = "https://packagist.org"

// UseAPI switches every lookup to the packagist.org API, which allows
// cross-origin requests. The browser (wasm) build sets it; the p2
// endpoint is preferred everywhere else per Packagist's own guidance.
var UseAPI = false

// Now is a var so tests can pin the clock.
var Now = time.Now

var client = &http.Client{Timeout: 20 * time.Second}

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const maxConcurrent = 8

// verInfo is what lockvet keeps per listed version.
type verInfo struct {
	time    string // RFC3339-ish as Packagist reports it
	license string // joined license list, "" when unknown
}

// pkg is what lockvet keeps per Packagist package.
type pkg struct {
	versions  map[string]verInfo // v-stripped version → info
	abandoned bool
	replacer  string // suggested replacement package, may be ""
	source    string // upstream repository URL, may be ""
}

// Annotate fills Packagist metadata on the diffs; see the package
// comment for what it covers. The returned bool reports whether at
// least one package was actually vetted against Packagist (callers use
// it to decide whether release metadata was checked at all, since
// deps.dev never covers PHP). freshDays mirrors -fresh-days.
// Best-effort: per-package failures skip that package; only total
// failure returns an error.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	type slot struct{ fd, ci int }
	byPkg := map[string][]slot{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "Packagist" || c.NonRegistry || !strings.Contains(c.Name, "/") {
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
	pkgs, err := fetchAll(names)
	if err != nil {
		return false, err
	}

	checked := false
	for name, slots := range byPkg {
		p := pkgs[name]
		if p == nil {
			continue // not on Packagist at all, or fetch failed: flag nothing
		}
		checked = true
		for _, s := range slots {
			annotateChange(&diffs[s.fd].Changes[s.ci], p, freshDays)
		}
	}
	return checked, nil
}

func annotateChange(c *diffx.Change, p *pkg, freshDays int) {
	// Release age: keep the most recently published incoming version,
	// exactly like the deps.dev layer does elsewhere.
	latest := c.PublishedAt
	for _, v := range c.New {
		if vi, ok := p.lookup(v); ok && vi.time != "" {
			if t, err := parseTime(vi.time); err == nil {
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

	// Abandoned = Composer's deprecation. Only changes that introduce a
	// version get the flag (removals are good news).
	if p.abandoned && len(c.New) > 0 {
		c.Deprecated = true
		if c.DeprecatedReason == "" {
			if p.replacer != "" {
				c.DeprecatedReason = "abandoned; use " + p.replacer + " instead"
			} else {
				c.DeprecatedReason = "abandoned by its maintainer"
			}
		}
	}

	// License change: only claimed when Packagist reports a license for
	// BOTH sides and they differ (case-only differences ignored).
	oldLic := newestLicense(p, c.Old)
	newLic := newestLicense(p, c.New)
	if oldLic != "" && newLic != "" && len(c.Old) > 0 && len(c.New) > 0 {
		c.OldLicense, c.NewLicense = oldLic, newLic
		c.LicenseChanged = !strings.EqualFold(oldLic, newLic)
	}

	// Unlisted: incoming release versions Packagist itself lacks, while
	// the package IS listed. Branch pins (dev-main, 1.x-dev) are not
	// releases and never flag.
	if len(p.versions) > 0 {
		var missing []string
		for _, v := range c.New {
			if isDevVersion(v) {
				continue
			}
			if _, ok := p.lookup(v); !ok {
				missing = append(missing, v)
			}
		}
		if len(missing) > 0 {
			c.Unlisted = true
			c.UnlistedVersions = missing
		}
	}

	// Upstream repository, for the changelog layers.
	if c.SourceRepo == "" && strings.HasPrefix(p.source, "https://") {
		c.SourceRepo = strings.TrimSuffix(p.source, ".git")
	}
}

// lookup finds a version tolerant of the leading-v difference between
// tags (v6.3.0 on Packagist) and composer.lock (the parser stores 6.3.0).
func (p *pkg) lookup(v string) (verInfo, bool) {
	vi, ok := p.versions[strings.TrimPrefix(v, "v")]
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
		if best == "" || vi.time > bestTime {
			best, bestTime = vi.license, vi.time
		}
	}
	return best
}

func isDevVersion(v string) bool {
	return strings.HasPrefix(v, "dev-") || strings.HasSuffix(v, "-dev")
}

// parseTime accepts the RFC3339-with-offset timestamps Packagist emits.
func parseTime(s string) (time.Time, error) { return time.Parse(time.RFC3339, s) }

func fetchAll(names []string) (map[string]*pkg, error) {
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
			p, err := fetchPkg(name)
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

// fetchPkg returns nil, nil when Packagist does not know the package.
func fetchPkg(name string) (*pkg, error) {
	if UseAPI {
		return fetchViaAPI(name)
	}
	return fetchViaP2(name)
}

func get(url string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("packagist unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}

// fetchViaP2 reads Composer's p2 metadata file, expanding Composer's
// "minified" format (each entry lists only the fields that changed from
// the previous one; "__unset" removes a field).
func fetchViaP2(name string) (*pkg, error) {
	body, status, err := get(RepoURL + "/p2/" + name + ".json")
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("packagist answered %d for %s", status, name)
	}
	var doc struct {
		Packages map[string][]map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("packagist metadata for %s: %w", name, err)
	}
	entries := doc.Packages[name]
	if entries == nil {
		return nil, nil
	}
	p := &pkg{versions: map[string]verInfo{}}
	cur := map[string]json.RawMessage{}
	for i, entry := range entries {
		for k, v := range entry {
			if string(v) == `"__unset"` {
				delete(cur, k)
			} else {
				cur[k] = v
			}
		}
		version := rawString(cur["version"])
		if version == "" {
			continue
		}
		p.versions[strings.TrimPrefix(version, "v")] = verInfo{
			time:    rawString(cur["time"]),
			license: joinLicense(cur["license"]),
		}
		if i == 0 { // newest entry: package-level state
			p.abandoned, p.replacer = parseAbandoned(cur["abandoned"])
			var src struct {
				URL string `json:"url"`
			}
			if cur["source"] != nil && json.Unmarshal(cur["source"], &src) == nil {
				p.source = src.URL
			}
		}
	}
	return p, nil
}

// fetchViaAPI reads the packagist.org package endpoint (not minified,
// CORS-open — the browser build's route).
func fetchViaAPI(name string) (*pkg, error) {
	body, status, err := get(APIURL + "/packages/" + name + ".json")
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("packagist answered %d for %s", status, name)
	}
	var doc struct {
		Package struct {
			Abandoned json.RawMessage `json:"abandoned"`
			Versions  map[string]struct {
				Version string          `json:"version"`
				Time    string          `json:"time"`
				License json.RawMessage `json:"license"`
				Source  struct {
					URL string `json:"url"`
				} `json:"source"`
			} `json:"versions"`
		} `json:"package"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("packagist metadata for %s: %w", name, err)
	}
	if doc.Package.Versions == nil {
		return nil, nil
	}
	p := &pkg{versions: map[string]verInfo{}}
	p.abandoned, p.replacer = parseAbandoned(doc.Package.Abandoned)
	newestTime := ""
	for key, v := range doc.Package.Versions {
		version := v.Version
		if version == "" {
			version = key
		}
		if isDevVersion(version) {
			continue
		}
		p.versions[strings.TrimPrefix(version, "v")] = verInfo{
			time:    v.Time,
			license: joinLicense(v.License),
		}
		if v.Source.URL != "" && (newestTime == "" || v.Time > newestTime) {
			newestTime, p.source = v.Time, v.Source.URL
		}
	}
	return p, nil
}

func rawString(raw json.RawMessage) string {
	var s string
	if raw != nil && json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// joinLicense renders Composer's license field (an array, very rarely a
// bare string) the way the registry pages do.
func joinLicense(raw json.RawMessage) string {
	if raw == nil {
		return ""
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return strings.Join(list, ", ")
	}
	return rawString(raw)
}

// parseAbandoned decodes Composer's abandoned field: absent/false, true
// (no replacement suggested), or the replacement package's name.
func parseAbandoned(raw json.RawMessage) (bool, string) {
	if raw == nil {
		return false, ""
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, ""
	}
	if s := rawString(raw); s != "" {
		return true, s
	}
	return false, ""
}
