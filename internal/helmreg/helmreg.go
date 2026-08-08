// Package helmreg asks the chart repository a Helm dependency resolves
// from what its own index.yaml says about it. Helm charts have no
// OSV.dev ecosystem and no deps.dev coverage, so — like Packagist,
// hex.pm, pub.dev, CRAN and the Bazel Central Registry before it — this
// package IS the metadata layer for Helm, not a fallback:
//
//   - Release ages and the ⏱ cooldown flag, from each version's
//     `created` timestamp in the repository index — the exact document
//     `helm dependency update` resolves against.
//   - Deprecated charts land in the deprecation lane: Helm's own
//     convention is `deprecated: true` on the chart's releases. A bump
//     onto a deprecated release flags directly; a chart whose LATEST
//     release is deprecated flags any bump, worded apart.
//   - Registry-verified unlisted detection, with a pruning guard: chart
//     repositories routinely PRUNE old releases from their index (the
//     bitnami index famously keeps only recent months), so absence
//     alone proves nothing. lockvet only flags an incoming version
//     that is missing while it sorts AT OR ABOVE the oldest release
//     the index still lists — a hole among the versions the repository
//     actively serves, which is what a pulled or never-published
//     release looks like. Absence is re-proven with an uncached fetch
//     before it is claimed; charts the index does not know at all are
//     never flagged.
//   - Source links: each release's `sources` (or `home`) names the
//     upstream repository, feeding verified compare links and
//     -changelogs exactly like the other registry layers.
//
// The repository URL comes from the lockfile itself (Chart.lock /
// Chart.yaml entries record it), so any HTTP(S) chart repository works
// — there is no central Helm registry to hardcode. oci:// references
// have no index.yaml and are honestly skipped; file:// subcharts are
// NonRegistry. Whether the browser (wasm) playground can query a given
// repository depends on that repository's CORS headers (GitHub
// Pages-hosted repos answer; others may not) — failures make no claims.
package helmreg

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/hcache"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// Enabled gates the whole layer.
var Enabled = true

// Now is a var so tests can pin the clock.
var Now = time.Now

var client = hcache.Client(30 * time.Second)

// uncachedClient re-proves absence evidence on every run, like every
// other unlisted path.
var uncachedClient = &http.Client{Timeout: 30 * time.Second}

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

// maxIndexBytes caps an index.yaml download; the largest public chart
// indexes are tens of MB.
const maxIndexBytes = 48 << 20

const maxConcurrent = 4

// entry is one release of one chart as the repository index lists it.
type entry struct {
	version    string
	created    string // RFC3339
	deprecated bool
	home       string
	sources    []string
}

// index is what lockvet keeps per chart repository: the listed releases
// of the charts the diff actually touches.
type index struct {
	charts map[string][]entry
	err    error
}

// Annotate fills Helm chart metadata on the diffs; see the package
// comment for what it covers. The returned bool reports whether at
// least one chart was actually vetted against its repository index.
// freshDays mirrors -fresh-days. Best-effort: per-repository failures
// make no claims; only total failure returns an error.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	if !Enabled {
		return false, nil
	}
	type slot struct{ fd, ci int }
	byRepo := map[string]map[string][]slot{} // repo URL → chart → slots
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "Helm" || c.NonRegistry || c.Channel == "" {
				continue
			}
			if !strings.HasPrefix(c.Channel, "http://") && !strings.HasPrefix(c.Channel, "https://") {
				continue
			}
			m := byRepo[c.Channel]
			if m == nil {
				m = map[string][]slot{}
				byRepo[c.Channel] = m
			}
			m[c.Name] = append(m[c.Name], slot{i, j})
		}
	}
	if len(byRepo) == 0 {
		return false, nil
	}

	repos := make([]string, 0, len(byRepo))
	for r := range byRepo {
		repos = append(repos, r)
	}
	sort.Strings(repos)

	idx := make(map[string]*index, len(repos))
	var mu sync.Mutex
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, r := range repos {
		wanted := map[string]bool{}
		for name := range byRepo[r] {
			wanted[name] = true
		}
		wg.Add(1)
		go func(r string, wanted map[string]bool) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ix := fetchIndex(client, r, wanted)
			mu.Lock()
			idx[r] = ix
			mu.Unlock()
		}(r, wanted)
	}
	wg.Wait()

	failures := 0
	var firstErr error
	for _, r := range repos {
		if idx[r].err != nil {
			failures++
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", hostOf(r), idx[r].err)
			}
		}
	}
	if failures == len(repos) && firstErr != nil {
		return false, firstErr
	}

	checked := false
	// reproven memoizes the uncached absence re-proof, one per repo.
	reproven := map[string]*index{}
	for _, r := range repos {
		ix := idx[r]
		if ix.err != nil {
			continue
		}
		for name, slots := range byRepo[r] {
			for _, s := range slots {
				c := &diffs[s.fd].Changes[s.ci]
				if annotateChange(c, r, ix.charts[name], freshDays, func() []entry {
					mu.Lock()
					defer mu.Unlock()
					re := reproven[r]
					if re == nil {
						re = fetchIndex(uncachedClient, r, map[string]bool{name: true})
						reproven[r] = re
					}
					if re.err != nil {
						return nil
					}
					return re.charts[name]
				}) {
					checked = true
				}
			}
		}
	}
	return checked, nil
}

// annotateChange fills one change from the repository index; reprove
// re-fetches the chart's listing uncached (nil = could not re-prove).
// Reports whether the index actually answered for this chart.
func annotateChange(c *diffx.Change, repo string, entries []entry, freshDays int, reprove func() []entry) bool {
	if len(entries) == 0 {
		// The index does not know this chart at all: no claims.
		return false
	}
	byVersion := func(entries []entry, v string) *entry {
		for i := range entries {
			if entries[i].version == v || strings.TrimPrefix(entries[i].version, "v") == strings.TrimPrefix(v, "v") {
				return &entries[i]
			}
		}
		return nil
	}

	// Release age: keep the most recently published incoming version,
	// exactly like the deps.dev layer does elsewhere.
	latest := c.PublishedAt
	for _, v := range c.New {
		if e := byVersion(entries, v); e != nil && e.created != "" && e.created > latest {
			latest = e.created
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

	// Deprecation lane. Incoming release marked deprecated flags
	// directly; a chart whose latest release is deprecated flags any
	// bump onto it.
	if c.DeprecatedReason == "" {
		for _, v := range c.New {
			if e := byVersion(entries, v); e != nil && e.deprecated {
				c.Deprecated = true
				c.DeprecatedReason = fmt.Sprintf("marked deprecated in the %s chart index", hostOf(repo))
				break
			}
		}
	}
	if c.DeprecatedReason == "" && len(c.New) > 0 {
		if newest := newestEntry(entries); newest != nil && newest.deprecated {
			c.Deprecated = true
			c.DeprecatedReason = fmt.Sprintf("the chart's latest release (%s) is marked deprecated in the %s chart index", newest.version, hostOf(repo))
		}
	}

	// Source repository → verified compare links and -changelogs.
	if c.SourceRepo == "" {
		for _, v := range c.New {
			if e := byVersion(entries, v); e != nil {
				if r := pickRepo(e.sources, e.home); r != "" {
					c.SourceRepo = r
					break
				}
			}
		}
	}

	// Registry-verified unlisted, with the pruning guard: only flag a
	// missing incoming version that sorts at or above the OLDEST
	// release the index still lists (repositories prune old releases;
	// below the window absence proves nothing).
	oldest := oldestEntry(entries)
	var missing []string
	for _, v := range c.New {
		if byVersion(entries, v) != nil {
			continue
		}
		if oldest == nil || vers.Compare(v, oldest.version) < 0 {
			continue
		}
		missing = append(missing, v)
	}
	if len(missing) > 0 && !c.Unlisted {
		// Absence is evidence: re-prove it with an uncached fetch.
		re := reprove()
		if re != nil {
			still := missing[:0]
			for _, v := range missing {
				if byVersion(re, v) == nil {
					still = append(still, v)
				}
			}
			if len(still) > 0 {
				c.Unlisted = true
				c.UnlistedVersions = append(c.UnlistedVersions, still...)
			}
		}
	}
	return true
}

// newestEntry returns the highest-versioned listed release (stable
// preferred; falls back to prereleases when nothing stable is listed).
func newestEntry(entries []entry) *entry {
	var best *entry
	bestStable := false
	for i := range entries {
		e := &entries[i]
		stable := !strings.ContainsAny(e.version, "-")
		switch {
		case best == nil,
			stable && !bestStable,
			stable == bestStable && vers.Compare(e.version, best.version) > 0:
			best, bestStable = e, stable
		}
	}
	return best
}

// oldestEntry returns the lowest-versioned listed release.
func oldestEntry(entries []entry) *entry {
	var low *entry
	for i := range entries {
		if low == nil || vers.Compare(entries[i].version, low.version) < 0 {
			low = &entries[i]
		}
	}
	return low
}

// pickRepo chooses an upstream source-repository URL worth probing for
// tags: a forge-looking https URL from sources (monorepo /tree/…
// suffixes stripped, pub.dev precedent), falling back to home.
func pickRepo(sources []string, home string) string {
	for _, s := range append(append([]string{}, sources...), home) {
		if r := forgeRepo(s); r != "" {
			return r
		}
	}
	return ""
}

func forgeRepo(u string) string {
	if !strings.HasPrefix(u, "https://") {
		return ""
	}
	rest := strings.TrimPrefix(u, "https://")
	host, path, ok := strings.Cut(rest, "/")
	if !ok || path == "" {
		return ""
	}
	h := strings.ToLower(host)
	if h != "github.com" && h != "gitlab.com" && h != "bitbucket.org" &&
		h != "codeberg.org" && !strings.HasPrefix(h, "git.") {
		return ""
	}
	segs := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(segs) < 2 {
		return ""
	}
	// Monorepo deep links (…/tree/main/bitnami/postgresql) → repo root.
	repo := "https://" + host + "/" + segs[0] + "/" + strings.TrimSuffix(segs[1], ".git")
	return repo
}

func hostOf(repo string) string {
	rest := strings.TrimPrefix(strings.TrimPrefix(repo, "https://"), "http://")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// Latest resolves the newest listed release of a chart against its
// repository's index: the highest stable, non-deprecated version
// (prereleases and deprecated releases only win when nothing else is
// listed). Used by `lockvet pkg helm:<repo>/<chart>`.
func Latest(repo, chart string) (string, error) {
	ix := fetchIndex(client, repo, map[string]bool{chart: true})
	if ix.err != nil {
		return "", fmt.Errorf("%s: %w", hostOf(repo), ix.err)
	}
	entries := ix.charts[chart]
	if len(entries) == 0 {
		return "", fmt.Errorf("chart %q is not in the %s index — is the repository URL right?", chart, hostOf(repo))
	}
	best := ""
	bestRank := -1
	for _, e := range entries {
		rank := 0
		if !strings.Contains(e.version, "-") {
			rank += 2 // stable
		}
		if !e.deprecated {
			rank++
		}
		if rank > bestRank || (rank == bestRank && vers.Compare(e.version, best) > 0) {
			best, bestRank = e.version, rank
		}
	}
	return best, nil
}

// fetchIndex downloads and parses <repo>/index.yaml, keeping only the
// charts in wanted.
func fetchIndex(cl *http.Client, repo string, wanted map[string]bool) *index {
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(repo, "/")+"/index.yaml", nil)
	if err != nil {
		return &index{err: err}
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return &index{err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return &index{err: fmt.Errorf("index.yaml: HTTP %d", resp.StatusCode)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIndexBytes+1))
	if err != nil {
		return &index{err: err}
	}
	if len(body) > maxIndexBytes {
		return &index{err: fmt.Errorf("index.yaml exceeds %d MiB", maxIndexBytes>>20)}
	}
	return &index{charts: parseIndex(body, wanted)}
}

// parseIndex reads the machine-generated `helm repo index` document
// line by line (indent-aware; no YAML library needed for this shape),
// keeping only the charts in wanted.
func parseIndex(data []byte, wanted map[string]bool) map[string][]entry {
	charts := map[string][]entry{}
	inEntries := false
	chartIndent := -1
	var chart string
	var cur *entry
	fieldIndent := -1
	listKey := ""
	flush := func() {
		if cur != nil && chart != "" && wanted[chart] && cur.version != "" {
			charts[chart] = append(charts[chart], *cur)
		}
		cur = nil
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			flush()
			inEntries = trimmed == "entries:"
			chart = ""
			continue
		}
		if !inEntries {
			continue
		}
		if chartIndent < 0 {
			chartIndent = indent
		}
		switch {
		case indent == chartIndent && strings.HasPrefix(trimmed, "- "):
			// New release item under the current chart.
			flush()
			cur = &entry{}
			fieldIndent = chartIndent + 2
			listKey = ""
			itemField(cur, strings.TrimSpace(trimmed[2:]), &listKey)
		case indent == chartIndent && strings.HasSuffix(trimmed, ":"):
			flush()
			chart = strings.Trim(strings.TrimSuffix(trimmed, ":"), `"'`)
		case cur != nil && indent == fieldIndent && strings.HasPrefix(trimmed, "- "):
			// List item at field level (sigs.k8s.io/yaml style):
			// sources/urls entries.
			if listKey == "sources" {
				cur.sources = append(cur.sources, strings.Trim(strings.TrimSpace(trimmed[2:]), `"'`))
			}
		case cur != nil && indent == fieldIndent:
			itemField(cur, trimmed, &listKey)
			// Deeper indents are nested maps (annotations, maintainers
			// members) — skipped.
		}
	}
	flush()
	return charts
}

// itemField applies one "key: value" line at release-field level.
func itemField(e *entry, kv string, listKey *string) {
	key, val, ok := strings.Cut(kv, ":")
	if !ok {
		return
	}
	key = strings.TrimSpace(key)
	val = strings.Trim(strings.TrimSpace(val), `"'`)
	if val == "" {
		// A nested block (annotations:, sources:, urls:, …) starts.
		*listKey = key
		return
	}
	*listKey = ""
	switch key {
	case "version":
		e.version = val
	case "created":
		e.created = val
	case "deprecated":
		e.deprecated = val == "true"
	case "home":
		e.home = val
	}
}
