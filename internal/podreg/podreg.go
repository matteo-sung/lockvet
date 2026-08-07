// Package podreg asks the CocoaPods registry what it knows about the
// pods a diff touches (Podfile.lock resolves against the trunk registry
// via the CDN). Neither OSV nor deps.dev has a CocoaPods system, so for
// the iOS/macOS world this package IS the metadata layer, not a
// fallback:
//
//   - The version listing comes from the same sharded CDN index that
//     `pod install` itself resolves against (all_pods_versions_*.txt),
//     so unlisted detection is registry-verified: an incoming version
//     missing from the index while the pod's other versions ARE listed
//     is what a deleted or moderated (malicious) release looks like.
//     Pods the index does not know at all are never flagged, and the
//     parser marks git/path pins and private-specs-repo pods
//     NonRegistry besides.
//   - Release ages and the ⏱ cooldown flag, from the trunk API's
//     per-version publish timestamps (native builds only: trunk sends
//     no CORS headers, so the browser build goes without ages here).
//   - Deprecated pods land in the deprecation lane with the podspec's
//     own replacement ("deprecated on CocoaPods; in favor of X") —
//     `pod trunk deprecate` rewrites every version's podspec, so the
//     incoming version's spec carries the verdict.
//   - License changes old → new, from the two versions' podspecs.
//   - The upstream source repository from the podspec's source.git,
//     which the changelog layers turn into verified compare links and
//     release notes.
//
// Requests are small and anonymous: one CDN index GET per shard, one
// trunk GET per pod (native), and up to two podspec GETs per bumped
// pod, 8-way concurrent. The browser (wasm) build reads the CDN index
// directly (it is CORS-open), podspecs through the CORS-open jsDelivr
// mirror (the CDN redirects those without CORS headers), and skips
// trunk.
package podreg

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/matteo-sung/lockvet/internal/hcache"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// CDNURL is the CocoaPods CDN base (shard index files); tests point it
// at an httptest server. Its index answers are CORS-open, so the wasm
// build uses it too.
var CDNURL = "https://cdn.cocoapods.org"

// SpecsURL overrides where podspec.json files are read from. Empty means
// CDNURL. The CDN 301-redirects /Specs/ paths to jsDelivr *without* CORS
// headers — browsers refuse to follow that — so the wasm build sets the
// CORS-open mirror (https://cdn.jsdelivr.net/cocoa) here directly.
var SpecsURL = ""

// TrunkURL is the trunk registry API base; a var so tests can fake it.
var TrunkURL = "https://trunk.cocoapods.org"

// UseTrunk gates the trunk API (publish timestamps). The wasm build
// disables it: trunk answers without CORS headers.
var UseTrunk = true

// Now is a var so tests can pin the clock.
var Now = time.Now

var client = hcache.Client(20 * time.Second)

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const maxConcurrent = 8

// pkg is what lockvet keeps per pod.
type pkg struct {
	listed  map[string]bool   // version set from the CDN index
	created map[string]string // version → RFC3339 publish time (trunk)
	specs   map[string]*spec  // version → podspec details
}

type spec struct {
	deprecated bool
	inFavorOf  string
	license    string
	source     string
}

// Annotate fills CocoaPods registry metadata on the diffs; see the
// package comment for what it covers. The returned bool reports whether
// at least one pod was actually vetted against the registry (callers
// use it to decide whether release metadata was checked at all, since
// deps.dev never covers CocoaPods). freshDays mirrors -fresh-days.
// Best-effort: per-pod failures skip that pod; only total failure
// returns an error.
type slot struct{ fd, ci int }

func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	byPod := map[string][]slot{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "CocoaPods" || c.NonRegistry {
				continue
			}
			byPod[c.Name] = append(byPod[c.Name], slot{i, j})
		}
	}
	if len(byPod) == 0 {
		return false, nil
	}

	names := make([]string, 0, len(byPod))
	for n := range byPod {
		names = append(names, n)
	}
	sort.Strings(names)

	pkgs, err := fetchListings(names)
	if err != nil {
		return false, err
	}
	if UseTrunk {
		fetchDates(pkgs)
	}
	fetchSpecs(pkgs, diffs, byPod)

	checked := false
	for name, slots := range byPod {
		p := pkgs[name]
		if p == nil {
			continue // not in the registry index at all: flag nothing
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
		if ts, ok := p.created[v]; ok && ts > latest {
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

	newV := newestVersion(p, c.New)
	oldV := newestVersion(p, c.Old)

	// Deprecation lane: never overwrite a richer reason.
	if len(c.New) > 0 && c.DeprecatedReason == "" {
		if s := p.specs[newV]; s != nil && s.deprecated {
			c.Deprecated = true
			reason := "deprecated on CocoaPods"
			if s.inFavorOf != "" {
				reason += "; in favor of " + s.inFavorOf
			}
			c.DeprecatedReason = reason
		}
	}

	// License change: only claimed when both sides' podspecs name one.
	if s, o := p.specs[newV], p.specs[oldV]; s != nil && o != nil &&
		s.license != "" && o.license != "" && c.OldLicense == "" {
		c.OldLicense, c.NewLicense = o.license, s.license
		c.LicenseChanged = !strings.EqualFold(o.license, s.license)
	}

	// Unlisted: incoming versions the registry index itself lacks,
	// while the pod IS indexed.
	if len(p.listed) > 0 {
		var missing []string
		for _, v := range c.New {
			if !p.listed[v] {
				missing = append(missing, v)
			}
		}
		if len(missing) > 0 {
			c.Unlisted = true
			c.UnlistedVersions = missing
		}
	}

	// Upstream repository, for the changelog layers.
	if c.SourceRepo == "" {
		if s := p.specs[newV]; s != nil && s.source != "" {
			c.SourceRepo = s.source
		}
	}
}

// newestVersion picks the version to read podspec details from: the
// most recently published when trunk dates are known, otherwise the
// last listed one in the change's own order.
func newestVersion(p *pkg, vs []string) string {
	best, bestTS := "", ""
	for _, v := range vs {
		if !p.listed[v] {
			continue
		}
		ts := p.created[v]
		if best == "" || ts > bestTS {
			best, bestTS = v, ts
		}
	}
	return best
}

// shard returns CocoaPods' CDN shard for a pod name: the first three
// hex chars of its MD5, as path segments ("Alamofire" → "d/a/2").
func shard(name string) [3]string {
	sum := md5.Sum([]byte(name))
	h := hex.EncodeToString(sum[:])
	return [3]string{h[0:1], h[1:2], h[2:3]}
}

// fetchListings reads the sharded CDN index files covering the pods and
// returns a pkg (with the version set) for every pod the index knows.
func fetchListings(names []string) (map[string]*pkg, error) {
	byShard := map[[3]string][]string{}
	for _, n := range names {
		s := shard(n)
		byShard[s] = append(byShard[s], n)
	}
	out := map[string]*pkg{}
	var mu sync.Mutex
	var firstErr error
	failures := 0
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for s, pods := range byShard {
		wg.Add(1)
		go func(s [3]string, pods []string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			listing, err := fetchShard(s)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			for _, n := range pods {
				if vs, ok := listing[n]; ok {
					out[n] = &pkg{listed: vs, created: map[string]string{}, specs: map[string]*spec{}}
				}
			}
		}(s, pods)
	}
	wg.Wait()
	if failures == len(byShard) && firstErr != nil {
		return nil, firstErr // total failure: report it
	}
	return out, nil
}

// ShardVersions returns every version the CDN index lists for one pod
// (the file `pod install` resolves against). Used by the latest-version
// lookup for `lockvet pkg pod:<name>`; an unknown pod returns an empty
// slice with status 200.
func ShardVersions(name string) ([]string, int, error) {
	pods, err := fetchShard(shard(name))
	if err != nil {
		return nil, 0, err
	}
	var out []string
	for v := range pods[name] {
		out = append(out, v)
	}
	return out, http.StatusOK, nil
}

// fetchShard downloads one all_pods_versions_a_b_c.txt index file and
// returns pod → version set. Lines look like "Alamofire/5.9.0/5.9.1".
func fetchShard(s [3]string) (map[string]map[string]bool, error) {
	u := fmt.Sprintf("%s/all_pods_versions_%s_%s_%s.txt", CDNURL, s[0], s[1], s[2])
	body, status, err := get(u)
	if err != nil {
		return nil, fmt.Errorf("CocoaPods CDN unreachable: %w", err)
	}
	if status == http.StatusNotFound {
		return map[string]map[string]bool{}, nil // empty shard
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("CocoaPods CDN answered %d for shard %s/%s/%s", status, s[0], s[1], s[2])
	}
	out := map[string]map[string]bool{}
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Split(strings.TrimSpace(line), "/")
		if len(parts) < 2 || parts[0] == "" {
			continue
		}
		vs := make(map[string]bool, len(parts)-1)
		for _, v := range parts[1:] {
			if v != "" {
				vs[v] = true
			}
		}
		out[parts[0]] = vs
	}
	return out, nil
}

// fetchDates asks trunk for each pod's per-version publish timestamps.
// Best-effort: trunk predates nothing — pods pushed before trunk exist
// only in the index, and 404s here simply mean no ages.
func fetchDates(pkgs map[string]*pkg) {
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for name, p := range pkgs {
		wg.Add(1)
		go func(name string, p *pkg) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			body, status, err := get(TrunkURL + "/api/v1/pods/" + url.PathEscape(name))
			if err != nil || status != http.StatusOK {
				return
			}
			var doc struct {
				Versions []struct {
					Name      string `json:"name"`
					CreatedAt string `json:"created_at"`
				} `json:"versions"`
			}
			if json.Unmarshal(body, &doc) != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, v := range doc.Versions {
				if t, err := time.Parse("2006-01-02 15:04:05 MST", v.CreatedAt); err == nil {
					p.created[v.Name] = t.UTC().Format(time.RFC3339)
				}
			}
		}(name, p)
	}
	wg.Wait()
}

// fetchSpecs downloads the podspecs the annotation step will read: the
// newest listed incoming version of every bump (deprecation, license,
// source repo) and the newest listed outgoing version (license compare).
func fetchSpecs(pkgs map[string]*pkg, diffs []diffx.FileDiff, byPod map[string][]slot) {
	type key struct{ name, version string }
	want := map[key]bool{}
	for name, slots := range byPod {
		p := pkgs[name]
		if p == nil {
			continue
		}
		for _, s := range slots {
			c := diffs[s.fd].Changes[s.ci]
			if len(c.New) == 0 {
				continue // removals need no podspec
			}
			if v := newestVersion(p, c.New); v != "" {
				want[key{name, v}] = true
			}
			if v := newestVersion(p, c.Old); v != "" {
				want[key{name, v}] = true
			}
		}
	}
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for k := range want {
		wg.Add(1)
		go func(k key) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			s := fetchSpec(k.name, k.version)
			if s == nil {
				return
			}
			mu.Lock()
			pkgs[k.name].specs[k.version] = s
			mu.Unlock()
		}(k)
	}
	wg.Wait()
}

func fetchSpec(name, version string) *spec {
	base := SpecsURL
	if base == "" {
		base = CDNURL
	}
	sh := shard(name)
	u := fmt.Sprintf("%s/Specs/%s/%s/%s/%s/%s/%s.podspec.json",
		base, sh[0], sh[1], sh[2],
		url.PathEscape(name), url.PathEscape(version), url.PathEscape(name))
	body, status, err := get(u)
	if err != nil || status != http.StatusOK {
		return nil
	}
	var doc struct {
		Deprecated        json.RawMessage `json:"deprecated"`
		DeprecatedInFavor string          `json:"deprecated_in_favor_of"`
		License           json.RawMessage `json:"license"`
		Source            struct {
			Git string `json:"git"`
		} `json:"source"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil
	}
	s := &spec{
		inFavorOf: doc.DeprecatedInFavor,
		license:   licenseString(doc.License),
		source:    repoURL(doc.Source.Git),
	}
	var b bool
	if json.Unmarshal(doc.Deprecated, &b) == nil {
		s.deprecated = b
	}
	if s.inFavorOf != "" {
		s.deprecated = true
	}
	return s
}

// licenseString accepts podspec license shapes: "MIT" or
// {"type":"MIT","file":"LICENSE"}.
func licenseString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var obj struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		return strings.TrimSpace(obj.Type)
	}
	return ""
}

// repoURL reduces a podspec source.git URL to the bare https repository
// the changelog layers can work with.
func repoURL(git string) string {
	git = strings.TrimSpace(git)
	if !strings.HasPrefix(git, "https://") {
		return ""
	}
	return strings.TrimSuffix(strings.TrimSuffix(git, "/"), ".git")
}

func get(u string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}
