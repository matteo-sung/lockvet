// Package orbreg asks the CircleCI orb registry what it knows about
// the orbs a .circleci/config.yml diff pins. There is no OSV.dev
// ecosystem and no deps.dev system for orbs, so — like Packagist,
// hex.pm, pub.dev, CRAN, Hackage, the Bazel Central Registry, Helm
// chart repositories and Ansible Galaxy before it — this package IS
// the metadata layer, not a fallback:
//
//   - Release ages and the ⏱ cooldown flag, from each orb version's
//     createdAt in the registry's own GraphQL API (the endpoint the
//     CircleCI CLI's `orb info` resolves against, queried anonymously
//     for public orbs).
//   - Floating pins resolve to the release they fetch today:
//     `volatile` → the newest published version, `5` / `5.1` → the
//     newest matching version, rendered like an Actions floating major
//     ("5 (=5.3.2)").
//   - Registry-verified unlisted detection: published orb versions are
//     immutable — deleting one is a CircleCI-support action reserved
//     for security problems — so an exact version the full version
//     list omits, while the orb itself IS listed, is what a pulled
//     release looks like. Absence is re-proven with an uncached fetch
//     before it is claimed.
//   - The upstream source repository from the orb's display metadata
//     (display.source_url in the published orb source), feeding
//     verified compare links and -changelogs.
//
// An orb the registry answers null for makes NO claims: unlisted orbs,
// private Server-install namespaces and typos all look the same from
// outside, and silence is the honest read.
//
// circleci.com sends no CORS wildcard, so the browser (wasm)
// playground disables this layer; the CLI covers it fully.
package orbreg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/hcache"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// Enabled gates the whole layer (the wasm playground turns it off:
// circleci.com sends no CORS wildcard).
var Enabled = true

// BaseURL is the registry GraphQL endpoint; a var so tests can fake it.
var BaseURL = "https://circleci.com/graphql-unstable"

// Now is a var so tests can pin the clock.
var Now = time.Now

var client = hcache.Client(20 * time.Second)

// uncachedClient re-proves absence evidence on every run, like every
// other unlisted path.
var uncachedClient = &http.Client{Timeout: 20 * time.Second}

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const maxConcurrent = 8

var nameOK = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
var exactVer = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
var floatVer = regexp.MustCompile(`^\d+(\.\d+)?$`)

// orbInfo is what lockvet keeps per changed orb.
type orbInfo struct {
	known    bool
	versions []string          // full published list, registry order
	created  map[string]string // version → RFC3339 createdAt
}

// Annotate fills orb-registry metadata on the diffs; see the package
// comment for what it covers. The returned bool reports whether at
// least one orb was actually vetted against the registry. freshDays
// mirrors -fresh-days. Best-effort: per-orb failures skip that orb;
// only total failure returns an error.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	if !Enabled {
		return false, nil
	}
	type slot struct{ fd, ci int }
	orbs := map[string][]slot{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.NonRegistry || c.Ecosystem != "CircleCI" || !nameOK.MatchString(c.Name) {
				continue
			}
			orbs[c.Name] = append(orbs[c.Name], slot{i, j})
		}
	}
	if len(orbs) == 0 {
		return false, nil
	}

	var mu sync.Mutex
	got := map[string]*orbInfo{}
	var firstErr error
	failures, total := 0, 0
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for name := range orbs {
		total++
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			info, err := fetchOrb(client, name)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			got[name] = info
		}(name)
	}
	wg.Wait()
	if failures == total && firstErr != nil {
		return false, firstErr
	}

	checked := false
	for name, slots := range orbs {
		info := got[name]
		if info == nil || !info.known {
			continue // not on the registry (or fetch failed): no claims
		}
		checked = true
		for _, s := range slots {
			annotateOrb(&diffs[s.fd].Changes[s.ci], name, info, freshDays)
		}
	}
	return checked, nil
}

func annotateOrb(c *diffx.Change, name string, info *orbInfo, freshDays int) {
	// Resolve floating pins first: ages and source lookups use the
	// version the pin fetches today.
	effective := make([]string, 0, len(c.New))
	var missing []string
	for _, v := range c.New {
		switch {
		case exactVer.MatchString(v):
			if _, ok := info.created[v]; ok {
				effective = append(effective, v)
			} else {
				missing = append(missing, v)
			}
		case v == "volatile" || floatVer.MatchString(v):
			if r := resolve(info.versions, v); r != "" {
				if c.ResolvedRefs == nil {
					c.ResolvedRefs = map[string]string{}
				}
				c.ResolvedRefs[v] = r
				effective = append(effective, r)
			}
		}
	}

	// Ages from the resolved versions' createdAt.
	latest := c.PublishedAt
	for _, v := range effective {
		if ts := info.created[v]; ts != "" {
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

	// Source repository from the orb's display metadata, for verified
	// compare links and -changelogs.
	if c.SourceRepo == "" {
		for _, v := range effective {
			if r := fetchSourceRepo(name, v); r != "" {
				c.SourceRepo = r
				break
			}
		}
	}

	// Registry-verified unlisted: the orb is listed, the exact incoming
	// version is absent from the full version list, and an uncached
	// re-fetch agrees.
	if len(missing) > 0 && len(info.versions) > 0 && !c.Unlisted {
		var still []string
		if fresh, err := fetchOrb(uncachedClient, name); err == nil && fresh.known {
			for _, v := range missing {
				if _, ok := fresh.created[v]; !ok {
					still = append(still, v)
				}
			}
		}
		if len(still) > 0 {
			c.Unlisted = true
			c.UnlistedVersions = append(c.UnlistedVersions, still...)
		}
	}
}

// resolve maps a floating pin to the newest matching published version.
func resolve(versions []string, ref string) string {
	prefix := ""
	if ref != "volatile" {
		prefix = ref + "."
	}
	best := ""
	for _, v := range versions {
		if !exactVer.MatchString(v) {
			continue
		}
		if prefix != "" && !strings.HasPrefix(v, prefix) {
			continue
		}
		if best == "" || vers.Compare(best, v) < 0 {
			best = v
		}
	}
	return best
}

// graphql performs one registry query.
func graphql(cl *http.Client, query string, out any) error {
	body, err := json.Marshal(map[string]string{"query": query})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, BaseURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return fmt.Errorf("circleci.com unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("circleci.com answered %d", resp.StatusCode)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("circleci.com metadata: %w", err)
	}
	return nil
}

func fetchOrb(cl *http.Client, name string) (*orbInfo, error) {
	if !nameOK.MatchString(name) {
		return &orbInfo{}, nil
	}
	var doc struct {
		Data struct {
			Orb *struct {
				Versions []struct {
					Version   string `json:"version"`
					CreatedAt string `json:"createdAt"`
				} `json:"versions"`
			} `json:"orb"`
		} `json:"data"`
	}
	q := fmt.Sprintf(`query{orb(name:%q){versions(count:1000){version createdAt}}}`, name)
	if err := graphql(cl, q, &doc); err != nil {
		return nil, err
	}
	if doc.Data.Orb == nil {
		return &orbInfo{}, nil
	}
	info := &orbInfo{known: true, created: map[string]string{}}
	for _, v := range doc.Data.Orb.Versions {
		info.versions = append(info.versions, v.Version)
		info.created[v.Version] = v.CreatedAt
	}
	return info, nil
}

var sourceURLRe = regexp.MustCompile(`(?m)^\s*source_url:\s*("?)(https?://\S+?)("?)\s*$`)

// srcMemo caches per-process source-repo lookups (the orb source is the
// only place display metadata lives, and it can run to ~100KB).
var srcMemo sync.Map // "name@version" → string

// fetchSourceRepo extracts display.source_url from the published orb
// source at the given version. Best-effort: "" on any failure.
func fetchSourceRepo(name, version string) string {
	key := name + "@" + version
	if v, ok := srcMemo.Load(key); ok {
		return v.(string)
	}
	repo := ""
	defer func() { srcMemo.Store(key, repo) }()
	var doc struct {
		Data struct {
			OrbVersion *struct {
				Source string `json:"source"`
			} `json:"orbVersion"`
		} `json:"data"`
	}
	q := fmt.Sprintf(`query{orbVersion(orbVersionRef:%q){source}}`, key)
	if err := graphql(client, q, &doc); err != nil || doc.Data.OrbVersion == nil {
		return repo
	}
	src := doc.Data.OrbVersion.Source
	if len(src) > 16<<10 {
		src = src[:16<<10] // display: sits at the top of the document
	}
	if m := sourceURLRe.FindStringSubmatch(src); m != nil {
		repo = strings.TrimSuffix(m[2], "/")
	}
	return repo
}

// Latest resolves the newest published version of an orb — what
// `volatile` would fetch (there are no pre-release orb versions;
// every published version is x.y.z).
func Latest(name string) (string, error) {
	info, err := fetchOrb(client, name)
	if err != nil {
		return "", err
	}
	if !info.known {
		return "", fmt.Errorf("orb %q is not in the CircleCI orb registry (private, unlisted, or a typo)", name)
	}
	if v := resolve(info.versions, "volatile"); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("orb %q has no published versions", name)
}
