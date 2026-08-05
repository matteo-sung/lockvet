// Package conanreg asks ConanCenter what it knows about the packages a
// conan.lock diff touches. deps.dev has no Conan system and OSV's
// ConanCenter ecosystem is still near-empty, so for C/C++ lockfiles this
// package IS the registry-metadata layer:
//
//   - Release ages and the ⏱ cooldown flag. A Conan version's
//     publication time is the time of its OLDEST recipe revision on
//     ConanCenter: recipes get re-exported (new revisions of old
//     versions) all the time, and using the latest revision would make
//     five-year-old releases look fresh.
//
// No unlisted claims, deliberately: a conan.lock reference does not
// record WHICH remote it came from, and real projects layer private
// remotes over ConanCenter for the same package names (XRPLF/rippled
// pins benchmark/1.9.5 from its own remote while ConanCenter stops at
// 1.9.0). Absence from ConanCenter therefore proves nothing, so
// versions the registry does not know simply carry no age. References
// pinned WITH a user/channel never reach this package at all (the
// parser marks them NonRegistry).
//
// Endpoints are ConanCenter's own Conan-protocol REST API (anonymous):
// one version-list GET per changed package plus one revisions GET per
// incoming listed version, capped. center2.conan.io sends no CORS
// headers, so the browser (wasm) playground skips this layer entirely
// and conan.lock diffs there carry no registry claims.
package conanreg

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
)

// BaseURL is the ConanCenter remote API base; a var so tests can point
// it at an httptest server. center2.conan.io is the live Conan 2 remote
// (center.conan.io is the frozen legacy remote and stopped receiving
// new versions in 2024 — asking it would misdate everything recent).
var BaseURL = "https://center2.conan.io"

// Enabled gates the whole layer; the browser (wasm) build sets it to
// false because center.conan.io sends no CORS headers.
var Enabled = true

// Now is a var so tests can pin the clock.
var Now = time.Now

var client = &http.Client{Timeout: 20 * time.Second}

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const (
	maxConcurrent = 6
	// maxRevisionLookups caps the per-version revisions requests across
	// the whole diff (version lists are one request per package and are
	// not capped).
	maxRevisionLookups = 48
)

type pkgInfo struct {
	listed    map[string]bool   // versions ConanCenter's list endpoint knows
	published map[string]string // version → RFC3339 oldest-revision time
}

// Annotate fills ConanCenter metadata on the diffs; see the package
// comment for what it covers. The returned bool reports whether at
// least one package was actually vetted against the registry.
// Best-effort: per-package failures skip that package; only total
// failure returns an error.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	if !Enabled {
		return false, nil
	}
	type slot struct{ fd, ci int }
	byName := map[string][]slot{}
	incoming := map[string][]string{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "ConanCenter" || c.NonRegistry || !validName(c.Name) {
				continue
			}
			byName[c.Name] = append(byName[c.Name], slot{i, j})
			incoming[c.Name] = append(incoming[c.Name], c.New...)
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

	infos := make(map[string]*pkgInfo, len(names))
	var mu sync.Mutex
	var firstErr error
	failures := 0
	budget := maxRevisionLookups
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			listed, err := fetchVersions(name)
			if err != nil {
				mu.Lock()
				failures++
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			info := &pkgInfo{listed: listed, published: map[string]string{}}
			for _, v := range dedupe(incoming[name]) {
				if !listed[v] {
					continue
				}
				mu.Lock()
				ok := budget > 0
				if ok {
					budget--
				}
				mu.Unlock()
				if !ok {
					break
				}
				if ts, err := fetchOldestRevisionTime(name, v); err == nil && ts != "" {
					info.published[v] = ts
				}
			}
			mu.Lock()
			infos[name] = info
			mu.Unlock()
		}(name)
	}
	wg.Wait()
	if failures == len(names) && firstErr != nil {
		return false, firstErr
	}

	checked := false
	for name, slots := range byName {
		info := infos[name]
		if info == nil || len(info.listed) == 0 {
			continue // ConanCenter does not know the package: flag nothing
		}
		checked = true
		for _, s := range slots {
			annotateChange(&diffs[s.fd].Changes[s.ci], info, freshDays)
		}
	}
	return checked, nil
}

func annotateChange(c *diffx.Change, info *pkgInfo, freshDays int) {
	// Release age: most recently published incoming version, exactly
	// like the deps.dev layer elsewhere.
	latest := c.PublishedAt
	for _, v := range c.New {
		if ts := info.published[v]; ts != "" && ts > latest {
			latest = ts
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

}

func validName(name string) bool {
	return name != "" && !strings.ContainsAny(name, "/@#% \t")
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func get(u string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

// fetchVersions returns the set of versions ConanCenter lists for a
// package, via the same search endpoint the conan client uses. An empty
// set means the registry does not know the package at all.
func fetchVersions(name string) (map[string]bool, error) {
	status, body, err := get(BaseURL + "/v1/conans/search?q=" + url.QueryEscape(name))
	if err != nil {
		return nil, fmt.Errorf("center.conan.io unreachable: %w", err)
	}
	if status == http.StatusNotFound {
		return map[string]bool{}, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("center.conan.io search: HTTP %d", status)
	}
	var res struct {
		Results []string `json:"results"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	listed := map[string]bool{}
	for _, ref := range res.Results {
		if i := strings.IndexByte(ref, '@'); i >= 0 {
			ref = ref[:i]
		}
		n, v, ok := strings.Cut(ref, "/")
		if ok && n == name && v != "" {
			listed[v] = true
		}
	}
	return listed, nil
}

// fetchOldestRevisionTime returns the RFC3339 time of the version's
// oldest recipe revision — its first publication on ConanCenter.
func fetchOldestRevisionTime(name, version string) (string, error) {
	status, body, err := get(BaseURL + "/v2/conans/" + url.PathEscape(name) + "/" + url.PathEscape(version) + "/_/_/revisions")
	if err != nil || status != http.StatusOK {
		return "", err
	}
	var res struct {
		Revisions []struct {
			Time string `json:"time"`
		} `json:"revisions"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return "", err
	}
	oldest := ""
	for _, r := range res.Revisions {
		t, err := time.Parse("2006-01-02T15:04:05-0700", r.Time)
		if err != nil {
			if t, err = time.Parse(time.RFC3339, r.Time); err != nil {
				continue
			}
		}
		s := t.UTC().Format(time.RFC3339)
		if oldest == "" || s < oldest {
			oldest = s
		}
	}
	return oldest, nil
}
