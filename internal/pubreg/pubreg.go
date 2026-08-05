// Package pubreg asks pub.dev what it knows about the Dart/Flutter
// packages a diff touches (pubspec.lock resolves against pub.dev).
// deps.dev has no Pub system at all, so for the Dart world this package
// IS the metadata layer, not a fallback:
//
//   - Release ages and the ⏱ cooldown flag, from each version's
//     published timestamp.
//   - Discontinued packages (pub.dev's package-level deprecation) land
//     in the deprecation lane, with the replacement package when the
//     publisher named one ("discontinued; replaced by lints").
//   - Retracted versions (pub.dev's per-version recall, `dart pub`
//     refuses to newly resolve them) land in the deprecation lane too.
//   - Unlisted detection: pub.dev never deletes versions except through
//     moderation of malicious/legal takedowns — retraction keeps the
//     version listed — so an incoming version missing while the
//     package's other versions ARE listed is a strong signal. Packages
//     pub.dev does not know at all are never flagged, and the parser
//     marks git/path/sdk/private-host installs NonRegistry besides.
//   - The upstream source repository from the package's pubspec
//     (monorepo /tree/... paths reduced to the repo), which the
//     changelog layers turn into verified compare links and release
//     notes.
//
// pub.dev has no per-release license history, so license-change
// detection is honestly left out for this ecosystem.
//
// One anonymous GET per changed package against the CORS-open
// pub.dev/api/packages endpoint — the same route works native and in
// the browser (wasm) build.
package pubreg

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

// BaseURL is the pub.dev API base; a var so tests can fake it.
var BaseURL = "https://pub.dev"

// Now is a var so tests can pin the clock.
var Now = time.Now

var client = &http.Client{Timeout: 20 * time.Second}

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const maxConcurrent = 8

// pkg is what lockvet keeps per pub.dev package.
type pkg struct {
	published    map[string]string // version → RFC3339 published
	retracted    map[string]bool   // version → retracted
	discontinued bool
	replacedBy   string
	source       string // upstream repository URL, may be ""
}

// Annotate fills pub.dev metadata on the diffs; see the package comment
// for what it covers. The returned bool reports whether at least one
// package was actually vetted against pub.dev (callers use it to decide
// whether release metadata was checked at all, since deps.dev never
// covers Pub). freshDays mirrors -fresh-days. Best-effort: per-package
// failures skip that package; only total failure returns an error.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	type slot struct{ fd, ci int }
	byPkg := map[string][]slot{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "Pub" || c.NonRegistry {
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
			continue // not on pub.dev at all, or fetch failed: flag nothing
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
		if ts, ok := p.published[v]; ok && ts != "" {
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

	// Deprecation lane: a discontinued package taints every version;
	// a retracted incoming version taints just that bump. Only changes
	// that introduce something get the flag (removals are good news).
	if len(c.New) > 0 {
		if p.discontinued && c.DeprecatedReason == "" {
			c.Deprecated = true
			reason := "discontinued on pub.dev"
			if p.replacedBy != "" {
				reason += "; replaced by " + p.replacedBy
			}
			c.DeprecatedReason = reason
		}
		if !c.Deprecated {
			for _, v := range c.New {
				if p.retracted[v] {
					c.Deprecated = true
					c.DeprecatedReason = "version retracted by the publisher"
					break
				}
			}
		}
	}

	// Unlisted: incoming release versions pub.dev itself lacks, while
	// the package IS listed.
	if len(p.published) > 0 {
		var missing []string
		for _, v := range c.New {
			if _, ok := p.published[v]; !ok {
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

// fetchPkg returns nil, nil when pub.dev does not know the package.
func fetchPkg(name string) (*pkg, error) {
	req, err := http.NewRequest(http.MethodGet, BaseURL+"/api/packages/"+name, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pub.dev unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("pub.dev rate limit hit; retry in a minute")
	default:
		return nil, fmt.Errorf("pub.dev answered %d for %s", resp.StatusCode, name)
	}
	var doc struct {
		Latest struct {
			Pubspec struct {
				Repository string `json:"repository"`
				Homepage   string `json:"homepage"`
			} `json:"pubspec"`
		} `json:"latest"`
		Versions []struct {
			Version   string `json:"version"`
			Published string `json:"published"`
			Retracted bool   `json:"retracted"`
		} `json:"versions"`
		IsDiscontinued bool   `json:"isDiscontinued"`
		ReplacedBy     string `json:"replacedBy"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("pub.dev metadata for %s: %w", name, err)
	}
	if len(doc.Versions) == 0 {
		return nil, nil
	}
	p := &pkg{
		published:    make(map[string]string, len(doc.Versions)),
		retracted:    map[string]bool{},
		discontinued: doc.IsDiscontinued,
		replacedBy:   doc.ReplacedBy,
	}
	for _, v := range doc.Versions {
		p.published[v.Version] = v.Published
		if v.Retracted {
			p.retracted[v.Version] = true
		}
	}
	p.source = repoURL(doc.Latest.Pubspec.Repository, doc.Latest.Pubspec.Homepage)
	return p, nil
}

// repoURL reduces a pubspec repository (or, failing that, homepage) URL
// to the bare repository the changelog layers can work with. Dart
// monorepos routinely point at subdirectories
// (github.com/dart-lang/http/tree/master/pkgs/http), so anything past
// owner/repo on the known forges is dropped.
func repoURL(candidates ...string) string {
	for _, u := range candidates {
		u = strings.TrimSuffix(strings.TrimSpace(u), "/")
		if !strings.HasPrefix(u, "https://") {
			continue
		}
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
