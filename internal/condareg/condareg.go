// Package condareg asks anaconda.org what it knows about the conda
// packages a diff touches (pixi.lock and conda-lock.yml resolve from
// conda channels). Conda has no OSV ecosystem and no deps.dev coverage,
// so — like Packagist, hex.pm, pub.dev and CRAN before it — this package
// IS the metadata layer for conda, not a fallback:
//
//   - Release ages and the ⏱ cooldown flag, from the per-release upload
//     times on api.anaconda.org (the API behind anaconda.org, which
//     conda.anaconda.org channels serve from).
//   - Broken releases land in the deprecation lane: conda-forge pulls a
//     bad or malicious build by giving its artifacts the `broken` label
//     (and patching it out of repodata), so a bump onto a broken release
//     is worth a look. All-builds-broken and some-builds-broken are
//     worded apart.
//   - Per-release license fields (from the artifacts' recipe metadata)
//     power license-change detection, exactly like the other registry
//     layers (both sides must be known; case-only differences ignored).
//   - Registry-verified unlisted detection: anaconda.org answers 404 for
//     a release it has never seen. Absence is only claimed after the
//     package itself is confirmed to exist (another release answered, or
//     a HEAD on the package document succeeds — re-proven every run,
//     never cached); packages the API does not know at all are never
//     flagged. Channels pull malicious uploads outright, so a lockfile
//     still pinning one is a red flag.
//
// The channel comes from the artifact URLs the lockfile itself records
// (conda.anaconda.org/<channel>/…), so bioconda and every other
// anaconda.org channel work exactly like conda-forge. Artifacts served
// from elsewhere (repo.anaconda.com's defaults channels, private
// mirrors) carry no channel lockvet can ask about and are skipped —
// lockvet makes no claims it cannot back. PyPI wheels inside pixi locks
// already get the full PyPI treatment and never reach this layer.
//
// api.anaconda.org sends no CORS headers, so the browser (wasm)
// playground skips this layer; the native CLI is unaffected.
package condareg

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
)

// BaseURL is the anaconda.org API base; a var so tests can fake it.
var BaseURL = "https://api.anaconda.org"

// Enabled gates the whole layer; the wasm playground sets it false
// (no CORS on api.anaconda.org).
var Enabled = true

// Now is a var so tests can pin the clock.
var Now = time.Now

var client = hcache.Client(20 * time.Second)

// headClient is deliberately uncached: absence evidence is re-proven on
// every run, like every other unlisted path.
var headClient = &http.Client{Timeout: 20 * time.Second}

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const maxConcurrent = 8

// release is what lockvet keeps per (channel, package, version).
type release struct {
	published  string // RFC3339 UTC of the earliest artifact upload
	license    string
	total      int // artifacts in the release
	broken     int // artifacts carrying the `broken` label
	notFound   bool
	fetchError bool
}

// Annotate fills conda metadata on the diffs; see the package comment
// for what it covers. The returned bool reports whether at least one
// package was actually vetted against its channel (neither OSV nor
// deps.dev cover conda, so this decides whether release metadata was
// checked at all). freshDays mirrors -fresh-days. Best-effort:
// per-release failures make no claims; only total failure returns an
// error.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	if !Enabled {
		return false, nil
	}
	type slot struct{ fd, ci int }
	type key struct{ channel, name string }
	byPkg := map[key][]slot{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "conda" || c.NonRegistry || c.Channel == "" {
				continue
			}
			k := key{c.Channel, c.Name}
			byPkg[k] = append(byPkg[k], slot{i, j})
		}
	}
	if len(byPkg) == 0 {
		return false, nil
	}

	// One fetch per (channel, name, version) across the whole diff.
	type rkey struct{ channel, name, version string }
	want := map[rkey]bool{}
	for k, slots := range byPkg {
		for _, s := range slots {
			c := &diffs[s.fd].Changes[s.ci]
			for _, v := range append(append([]string{}, c.Old...), c.New...) {
				want[rkey{k.channel, k.name, v}] = true
			}
		}
	}
	keys := make([]rkey, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		return a.channel+"/"+a.name+"/"+a.version < b.channel+"/"+b.name+"/"+b.version
	})

	rels := make(map[rkey]*release, len(keys))
	var mu sync.Mutex
	var firstErr error
	failures := 0
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, k := range keys {
		wg.Add(1)
		go func(k rkey) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r, err := fetchRelease(k.channel, k.name, k.version)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
				if firstErr == nil {
					firstErr = err
				}
				rels[k] = &release{fetchError: true}
				return
			}
			rels[k] = r
		}(k)
	}
	wg.Wait()
	if failures == len(keys) && firstErr != nil {
		return false, firstErr // total failure: report it
	}

	checked := false
	for k, slots := range byPkg {
		relOf := func(v string) *release {
			if r := rels[rkey{k.channel, k.name, v}]; r != nil {
				return r
			}
			return &release{fetchError: true}
		}
		anyKnown := false
		for _, s := range slots {
			c := &diffs[s.fd].Changes[s.ci]
			for _, v := range append(append([]string{}, c.Old...), c.New...) {
				if r := relOf(v); !r.notFound && !r.fetchError {
					anyKnown = true
				}
			}
		}
		exists := anyKnown // another release answering proves the package
		for _, s := range slots {
			c := &diffs[s.fd].Changes[s.ci]
			if annotateChange(c, k.channel, k.name, relOf, &exists, freshDays) {
				checked = true
			}
		}
	}
	return checked, nil
}

// annotateChange fills one change from the fetched releases; reports
// whether any registry answer was actually used.
func annotateChange(c *diffx.Change, channel, name string, relOf func(string) *release, exists *bool, freshDays int) bool {
	used := false

	// Release age: keep the most recently published incoming version,
	// exactly like the deps.dev layer does elsewhere.
	latest := c.PublishedAt
	for _, v := range c.New {
		r := relOf(v)
		if r.published != "" && r.published > latest {
			latest = r.published
		}
	}
	if latest != "" && latest != c.PublishedAt {
		if t, err := time.Parse(time.RFC3339, latest); err == nil {
			c.PublishedAt = latest
			used = true
			if age := int(Now().Sub(t).Hours() / 24); age >= 0 {
				c.AgeDays = age
				c.Fresh = freshDays > 0 && Now().Sub(t) < time.Duration(freshDays)*24*time.Hour
			}
		}
	}

	// Deprecation lane: an incoming release whose artifacts carry the
	// `broken` label was pulled by the channel (removals stay quiet).
	for _, v := range c.New {
		r := relOf(v)
		if r.total == 0 || r.broken == 0 {
			continue
		}
		used = true
		c.Deprecated = true
		if c.DeprecatedReason == "" {
			if r.broken == r.total {
				c.DeprecatedReason = fmt.Sprintf("marked broken on %s (artifacts moved to the broken label)", channel)
			} else {
				c.DeprecatedReason = fmt.Sprintf("some builds marked broken on %s (broken label)", channel)
			}
		}
		break
	}

	// License change: only claimed when the channel reports a license
	// for BOTH sides and they differ (case-only differences ignored).
	oldLic := newestLicense(relOf, c.Old)
	newLic := newestLicense(relOf, c.New)
	if oldLic != "" && newLic != "" && len(c.Old) > 0 && len(c.New) > 0 && c.OldLicense == "" {
		c.OldLicense, c.NewLicense = oldLic, newLic
		c.LicenseChanged = !strings.EqualFold(oldLic, newLic)
		used = true
	}

	// Unlisted: incoming versions the channel answers 404 for, while the
	// package itself is confirmed to exist. Absence evidence is
	// re-proven on every run (404s are never cached; the existence HEAD
	// is uncached besides).
	var missing []string
	for _, v := range c.New {
		r := relOf(v)
		if !r.notFound {
			continue
		}
		if !*exists {
			if !packageExists(channel, name) {
				continue // package unknown entirely, or can't prove: no claim
			}
			*exists = true
		}
		missing = append(missing, v)
	}
	if len(missing) > 0 {
		c.Unlisted = true
		c.UnlistedVersions = missing
		used = true
	}
	return used
}

// newestLicense returns the license of the most recently published
// version in vs that the channel knows.
func newestLicense(relOf func(string) *release, vs []string) string {
	best, bestTS := "", ""
	for _, v := range vs {
		r := relOf(v)
		if r.license == "" {
			continue
		}
		if best == "" || r.published > bestTS {
			best, bestTS = r.license, r.published
		}
	}
	return best
}

// fetchRelease returns the channel's answer for one release; notFound is
// set on 404 (the way anaconda.org reports a version it has never seen).
func fetchRelease(channel, name, version string) (*release, error) {
	u := BaseURL + "/release/" + url.PathEscape(channel) + "/" + url.PathEscape(name) + "/" + url.PathEscape(version)
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api.anaconda.org unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return &release{notFound: true}, nil
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("api.anaconda.org rate limit hit; retry in a minute")
	default:
		return nil, fmt.Errorf("api.anaconda.org answered %d for %s/%s %s", resp.StatusCode, channel, name, version)
	}
	var doc struct {
		Distributions []struct {
			UploadTime string   `json:"upload_time"`
			Labels     []string `json:"labels"`
			Attrs      struct {
				License string `json:"license"`
			} `json:"attrs"`
		} `json:"distributions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("anaconda.org metadata for %s/%s: %w", channel, name, err)
	}
	r := &release{total: len(doc.Distributions)}
	for _, d := range doc.Distributions {
		if ts := parseUploadTime(d.UploadTime); ts != "" && (r.published == "" || ts < r.published) {
			r.published = ts
		}
		for _, l := range d.Labels {
			if l == "broken" {
				r.broken++
				break
			}
		}
		if r.license == "" && d.Attrs.License != "" {
			r.license = d.Attrs.License
		}
	}
	return r, nil
}

// parseUploadTime turns anaconda.org's "2026-07-04 23:11:22.279000+00:00"
// into RFC3339 UTC; "" when it can't.
func parseUploadTime(s string) string {
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999-07:00",
		"2006-01-02 15:04:05-07:00",
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return ""
}

// packageExists HEADs the package document — cheap (the 200 carries no
// body on HEAD) and uncached, so absence claims rest on live evidence.
func packageExists(channel, name string) bool {
	req, err := http.NewRequest(http.MethodHead, BaseURL+"/package/"+url.PathEscape(channel)+"/"+url.PathEscape(name), nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := headClient.Do(req)
	if err != nil {
		return false // can't prove the package exists: make no claim
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// Latest returns the channel's idea of the package's latest release, for
// `lockvet pkg conda:[channel/]name`. Note this is anaconda.org's own
// latest_version — if that release was later marked broken, the report
// will say so.
func Latest(channel, name string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, BaseURL+"/package/"+url.PathEscape(channel)+"/"+url.PathEscape(name), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("api.anaconda.org unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return "", err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", fmt.Errorf("conda: package %s not found on %s", name, channel)
	default:
		return "", fmt.Errorf("api.anaconda.org answered %d for %s/%s", resp.StatusCode, channel, name)
	}
	var doc struct {
		Latest string `json:"latest_version"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("anaconda.org metadata for %s/%s: %w", channel, name, err)
	}
	if doc.Latest == "" {
		return "", fmt.Errorf("conda: %s/%s lists no releases", channel, name)
	}
	return doc.Latest, nil
}
