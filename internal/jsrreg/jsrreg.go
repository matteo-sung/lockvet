// Package jsrreg asks jsr.io what it knows about the JSR packages a
// deno.lock diff touches. Neither OSV.dev nor deps.dev has a JSR
// ecosystem, so for jsr: packages this package IS the metadata layer,
// not a fallback:
//
//   - Release ages and the ⏱ cooldown flag, from each version's
//     createdAt in the package's meta.json — the exact document Deno
//     itself resolves against.
//   - Yanked versions land in the deprecation lane (JSR keeps yanked
//     versions listed in meta.json, so a yank is visible, not a hole).
//   - Archived packages (jsr.io's package-level retirement) land in the
//     deprecation lane too.
//   - Unlisted detection: JSR does not let publishers delete versions —
//     yanking keeps them listed — so an incoming version missing from
//     meta.json while the package's other versions ARE listed is a
//     strong signal that something was scrubbed. Packages jsr.io does
//     not know at all are never flagged.
//   - The upstream GitHub repository the package links on jsr.io, which
//     the changelog layers turn into verified compare links and release
//     notes.
//
// JSR publishes are sigstore-signed across the board (there is no
// unattested baseline to fall from), so provenance-drop detection does
// not apply. JSR has no per-release license history either, so
// license-change detection is honestly left out.
//
// Two anonymous GETs per changed package (meta.json + the package API
// for archived/repository), both against CORS-open endpoints — the same
// route works native and in the browser (wasm) build.
package jsrreg

import (
	"encoding/json"
	"fmt"
	"github.com/matteo-sung/lockvet/internal/hcache"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// BaseURL serves /@scope/name/meta.json; a var so tests can fake it.
var BaseURL = "https://jsr.io"

// APIBaseURL serves /api/scopes/{scope}/packages/{name}; a var so tests
// can fake it (defaults to BaseURL's host in fetch when empty).
var APIBaseURL = "https://jsr.io"

// Now is a var so tests can pin the clock.
var Now = time.Now

var client = hcache.Client(20 * time.Second)

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const maxConcurrent = 8

// Prefix marks JSR packages inside npm-ecosystem lockfiles (deno.lock
// keeps npm and jsr dependencies side by side; the parser prefixes the
// latter since OSV has no JSR ecosystem to put them in).
const Prefix = "jsr:"

// pkg is what lockvet keeps per jsr.io package.
type pkg struct {
	created  map[string]string // version → RFC3339 createdAt
	yanked   map[string]bool   // version → yanked
	archived bool
	source   string // upstream repository URL, may be ""
}

// Annotate fills jsr.io metadata on the diffs; see the package comment
// for what it covers. The returned bool reports whether at least one
// package was actually vetted against jsr.io. freshDays mirrors
// -fresh-days. Best-effort: per-package failures skip that package;
// only total failure returns an error.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	type slot struct{ fd, ci int }
	byPkg := map[string][]slot{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "npm" || c.NonRegistry || !strings.HasPrefix(c.Name, Prefix) {
				continue
			}
			if scope, name, ok := splitName(c.Name); !ok || scope == "" || name == "" {
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
			continue // not on jsr.io at all, or fetch failed: flag nothing
		}
		checked = true
		for _, s := range slots {
			annotateChange(&diffs[s.fd].Changes[s.ci], p, freshDays)
		}
	}
	return checked, nil
}

func annotateChange(c *diffx.Change, p *pkg, freshDays int) {
	// Release age: keep the most recently published incoming version.
	latest := c.PublishedAt
	for _, v := range c.New {
		if ts, ok := p.created[v]; ok && ts != "" {
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

	// Deprecation lane: an archived package taints every version; a
	// yanked incoming version taints just that bump. Only changes that
	// introduce something get the flag (removals are good news).
	if len(c.New) > 0 {
		if p.archived && c.DeprecatedReason == "" {
			c.Deprecated = true
			c.DeprecatedReason = "package archived on jsr.io"
		}
		if !c.Deprecated {
			for _, v := range c.New {
				if p.yanked[v] {
					c.Deprecated = true
					c.DeprecatedReason = "version yanked on jsr.io"
					break
				}
			}
		}
	}

	// Unlisted: incoming versions jsr.io itself lacks, while the
	// package IS listed (yanks stay listed, so absence is real signal).
	if len(p.created) > 0 {
		var missing []string
		for _, v := range c.New {
			if _, ok := p.created[v]; !ok {
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

// splitName turns "jsr:@std/path" into ("std", "path", true).
func splitName(prefixed string) (scope, name string, ok bool) {
	rest, found := strings.CutPrefix(prefixed, Prefix)
	if !found {
		return "", "", false
	}
	rest, found = strings.CutPrefix(rest, "@")
	if !found {
		return "", "", false
	}
	scope, name, found = strings.Cut(rest, "/")
	if !found || strings.Contains(name, "/") {
		return "", "", false
	}
	return scope, name, true
}

// fetchPkg returns nil, nil when jsr.io does not know the package.
func fetchPkg(prefixed string) (*pkg, error) {
	scope, name, ok := splitName(prefixed)
	if !ok {
		return nil, nil
	}

	body, status, err := get(BaseURL + "/@" + scope + "/" + name + "/meta.json")
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusGone:
		return nil, nil
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("jsr.io rate limit hit; retry in a minute")
	default:
		return nil, fmt.Errorf("jsr.io answered %d for @%s/%s", status, scope, name)
	}
	var meta struct {
		Versions map[string]struct {
			Yanked    bool   `json:"yanked"`
			CreatedAt string `json:"createdAt"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, fmt.Errorf("jsr.io metadata for @%s/%s: %w", scope, name, err)
	}
	if len(meta.Versions) == 0 {
		return nil, nil
	}
	p := &pkg{
		created: make(map[string]string, len(meta.Versions)),
		yanked:  map[string]bool{},
	}
	for v, info := range meta.Versions {
		p.created[v] = info.CreatedAt
		if info.Yanked {
			p.yanked[v] = true
		}
	}

	// Package-level details (archived flag, linked repository). Best
	// effort: failure here loses the extras, not the version data.
	if body, status, err := get(APIBaseURL + "/api/scopes/" + scope + "/packages/" + name); err == nil && status == http.StatusOK {
		var doc struct {
			IsArchived       bool `json:"isArchived"`
			GithubRepository *struct {
				Owner string `json:"owner"`
				Name  string `json:"name"`
			} `json:"githubRepository"`
		}
		if json.Unmarshal(body, &doc) == nil {
			p.archived = doc.IsArchived
			if gh := doc.GithubRepository; gh != nil && gh.Owner != "" && gh.Name != "" {
				p.source = "https://github.com/" + gh.Owner + "/" + gh.Name
			}
		}
	}
	return p, nil
}

func get(url string) (body []byte, status int, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("jsr.io unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}
