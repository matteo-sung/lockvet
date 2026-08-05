// Package hexreg asks hex.pm what it knows about the Hex packages a
// diff touches (Elixir mix.lock and Gleam manifest.toml both resolve
// against Hex). deps.dev has no Hex system at all, so for the BEAM
// world this package IS the metadata layer, not a fallback:
//
//   - Release ages and the ⏱ cooldown flag, from each release's
//     inserted_at timestamp.
//   - Retired releases (Hex's per-version deprecation mechanism) land
//     in the deprecation lane with the maintainer's reason and message
//     ("Not really maintained, please check out Tesla").
//   - Unlisted detection: hex.pm lets publishers fully delete a release
//     (and admins remove malicious ones), and deleted releases vanish
//     from the API — an incoming version missing while the package's
//     other versions ARE listed is what that looks like. Packages Hex
//     does not know at all are never flagged, and the parsers mark
//     git/path installs NonRegistry besides.
//   - The upstream source repository from the package links, which the
//     changelog layers turn into verified compare links and release
//     notes.
//
// Hex has no per-release license history, so license-change detection
// is honestly left out for this ecosystem.
//
// One anonymous GET per changed package against the CORS-open
// hex.pm/api/packages endpoint — the same route works native and in the
// browser (wasm) build. Anonymous quota is 100 requests/minute; setting
// HEX_API_KEY (a hex.pm API key, same variable mix itself understands)
// raises it.
package hexreg

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// BaseURL is the hex.pm API base; a var so tests can fake it.
var BaseURL = "https://hex.pm"

// Now is a var so tests can pin the clock.
var Now = time.Now

var client = &http.Client{Timeout: 20 * time.Second}

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const maxConcurrent = 8

type retirement struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// pkg is what lockvet keeps per Hex package.
type pkg struct {
	inserted map[string]string     // version → RFC3339 inserted_at
	retired  map[string]retirement // version → retirement
	source   string                // upstream repository URL, may be ""
}

// Annotate fills hex.pm metadata on the diffs; see the package comment
// for what it covers. The returned bool reports whether at least one
// package was actually vetted against hex.pm (callers use it to decide
// whether release metadata was checked at all, since deps.dev never
// covers Hex). freshDays mirrors -fresh-days. Best-effort: per-package
// failures skip that package; only total failure returns an error.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	type slot struct{ fd, ci int }
	byPkg := map[string][]slot{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "Hex" || c.NonRegistry {
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
			continue // not on hex.pm at all, or fetch failed: flag nothing
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
		if ts, ok := p.inserted[v]; ok && ts != "" {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				if s := t.UTC().Format(time.RFC3339); s > latest {
					latest = s
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

	// Retired releases are Hex's deprecation. Only changes that
	// introduce a retired version get the flag (removals are good news).
	for _, v := range c.New {
		if r, ok := p.retired[v]; ok {
			c.Deprecated = true
			if c.DeprecatedReason == "" {
				c.DeprecatedReason = retirementReason(r)
			}
			break
		}
	}

	// Unlisted: incoming release versions hex.pm itself lacks, while
	// the package IS listed.
	if len(p.inserted) > 0 {
		var missing []string
		for _, v := range c.New {
			if _, ok := p.inserted[v]; !ok {
				missing = append(missing, v)
			}
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

// retirementReason renders a Hex retirement the way `mix hex.outdated`
// style tooling would: the machine reason, then the maintainer's
// message when present.
func retirementReason(r retirement) string {
	reason := strings.TrimSpace(r.Reason)
	switch reason {
	case "", "other":
		reason = "retired"
	case "invalid":
		reason = "retired: release is broken"
	case "security":
		reason = "retired: security issue"
	case "deprecated":
		reason = "retired: deprecated"
	case "renamed":
		reason = "retired: renamed"
	default:
		reason = "retired: " + reason
	}
	if msg := strings.TrimSpace(r.Message); msg != "" {
		reason += " — " + msg
	}
	return reason
}

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

// fetchPkg returns nil, nil when hex.pm does not know the package.
func fetchPkg(name string) (*pkg, error) {
	req, err := http.NewRequest(http.MethodGet, BaseURL+"/api/packages/"+name, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	if key := os.Getenv("HEX_API_KEY"); key != "" {
		req.Header.Set("Authorization", key)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hex.pm unreachable: %w", err)
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
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("hex.pm rate limit hit (100 requests/minute anonymous; set HEX_API_KEY to raise it)")
	default:
		return nil, fmt.Errorf("hex.pm answered %d for %s", resp.StatusCode, name)
	}
	var doc struct {
		Releases []struct {
			Version    string `json:"version"`
			InsertedAt string `json:"inserted_at"`
		} `json:"releases"`
		Retirements map[string]retirement `json:"retirements"`
		Meta        struct {
			Links map[string]string `json:"links"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("hex.pm metadata for %s: %w", name, err)
	}
	if len(doc.Releases) == 0 {
		return nil, nil
	}
	p := &pkg{inserted: map[string]string{}, retired: doc.Retirements}
	for _, r := range doc.Releases {
		p.inserted[r.Version] = r.InsertedAt
	}
	if p.retired == nil {
		p.retired = map[string]retirement{}
	}
	p.source = sourceFromLinks(doc.Meta.Links)
	return p, nil
}

// sourceFromLinks picks the upstream repository out of a Hex package's
// links map. Keys are free-form ("GitHub", "github", "Repository",
// "Source"...), so match on the URL host instead.
func sourceFromLinks(links map[string]string) string {
	keys := make([]string, 0, len(links))
	for k := range links {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic pick
	best := ""
	for _, k := range keys {
		u := strings.TrimSuffix(strings.TrimSpace(links[k]), "/")
		if !strings.HasPrefix(u, "https://") {
			continue
		}
		for _, host := range []string{"https://github.com/", "https://gitlab.com/", "https://codeberg.org/", "https://bitbucket.org/"} {
			if strings.HasPrefix(u, host) && strings.Count(strings.TrimPrefix(u, host), "/") == 1 {
				u = strings.TrimSuffix(u, ".git")
				lk := strings.ToLower(k)
				if strings.Contains(lk, "github") || strings.Contains(lk, "repo") || strings.Contains(lk, "source") {
					return u // an explicitly repo-flavoured key wins outright
				}
				if best == "" {
					best = u
				}
			}
		}
	}
	return best
}
