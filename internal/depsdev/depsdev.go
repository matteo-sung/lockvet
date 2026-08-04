// Package depsdev queries deps.dev for registry metadata: when a version
// was published (fresh-release detection) and whether it is deprecated.
package depsdev

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/taglink"
)

// BatchURL is a var so tests can point it at a fake server.
var BatchURL = "https://api.deps.dev/v3alpha/versionbatch"

// SingleURL is the base for per-version GET lookups (see SingleRequests).
var SingleURL = "https://api.deps.dev/v3alpha"

// SingleRequests switches Annotate from the versionbatch endpoint to one
// GET per version. The browser (wasm) build sets it: versionbatch does not
// answer CORS preflight requests, but the GET endpoints are CORS-simple.
var SingleRequests = false

var client = &http.Client{Timeout: 20 * time.Second}

// Now is a var so tests can pin the clock.
var Now = time.Now

const chunkSize = 500

// system maps lockvet ecosystems to deps.dev systems. Ecosystems deps.dev
// doesn't cover (Packagist, Hex, Pub, SwiftURL) are skipped gracefully.
func system(eco string) string {
	switch eco {
	case "npm":
		return "NPM"
	case "crates.io":
		return "CARGO"
	case "PyPI":
		return "PYPI"
	case "Go":
		return "GO"
	case "Maven":
		return "MAVEN"
	case "NuGet":
		return "NUGET"
	case "RubyGems":
		return "RUBYGEMS"
	}
	return ""
}

// Covers reports whether deps.dev has data for the ecosystem.
func Covers(eco string) bool { return system(eco) != "" }

type versionKey struct {
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type request struct {
	VersionKey versionKey `json:"versionKey"`
}

type versionInfo struct {
	PublishedAt      string   `json:"publishedAt"`
	IsDeprecated     bool     `json:"isDeprecated"`
	DeprecatedReason string   `json:"deprecatedReason"`
	Licenses         []string `json:"licenses"`
	Links            []struct {
		Label string `json:"label"`
		URL   string `json:"url"`
	} `json:"links"`
}

// licenseOf joins the registry's license strings for display ("" = unknown).
func licenseOf(info *versionInfo) string {
	ls := append([]string(nil), info.Licenses...)
	sort.Strings(ls)
	return strings.Join(ls, ", ")
}

// sourceRepo picks the SOURCE_REPO link, canonicalised, or "".
func sourceRepo(info *versionInfo) string {
	for _, l := range info.Links {
		if l.Label == "SOURCE_REPO" {
			return taglink.NormalizeRepoURL(l.URL)
		}
	}
	return ""
}

// Annotate fills PublishedAt / AgeDays / Fresh / Deprecated on every change
// that introduces a version, in place. A version counts as fresh when it was
// published fewer than freshDays days before now. Best-effort: network
// errors return an error but leave diffs usable.
func Annotate(diffs []diffx.FileDiff, freshDays int) error {
	type slot struct {
		fd, ci  int
		oldSide bool
	}
	var reqs []request
	var slots []slot

	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			sys := system(c.Ecosystem)
			if sys == "" {
				continue
			}
			if strings.HasPrefix(c.Name, "jsr:") {
				continue // deno.lock JSR entries: not an npm package
			}
			old := map[string]bool{}
			for _, v := range c.Old {
				old[v] = true
			}
			nu := map[string]bool{}
			for _, v := range c.New {
				nu[v] = true
			}
			queryVersion := func(v string) string {
				if sys == "GO" && !strings.HasPrefix(v, "v") {
					return "v" + v // lockvet stores Go versions without the prefix
				}
				return v
			}
			for _, v := range c.New {
				if old[v] {
					continue // only versions this change introduces
				}
				reqs = append(reqs, request{versionKey{sys, c.Name, queryVersion(v)}})
				slots = append(slots, slot{i, j, false})
			}
			if len(c.New) > 0 {
				// Departing versions too, so we can spot license changes.
				for _, v := range c.Old {
					if nu[v] {
						continue
					}
					reqs = append(reqs, request{versionKey{sys, c.Name, queryVersion(v)}})
					slots = append(slots, slot{i, j, true})
				}
			}
		}
	}
	if len(reqs) == 0 {
		return nil
	}

	// Per change and side, the license of the most recently published
	// version we saw (mirrors the age logic below).
	type sideKey struct {
		fd, ci  int
		oldSide bool
	}
	type sideLic struct {
		published string
		license   string
	}
	lics := map[sideKey]sideLic{}

	now := Now()
	for start := 0; start < len(reqs); start += chunkSize {
		end := min(start+chunkSize, len(reqs))
		fetchChunk := runBatch
		if SingleRequests {
			fetchChunk = runSingles
		}
		infos, err := fetchChunk(reqs[start:end])
		if err != nil {
			return err
		}
		for k, info := range infos {
			if info == nil {
				continue // unknown to deps.dev
			}
			s := slots[start+k]
			c := &diffs[s.fd].Changes[s.ci]
			if lic := licenseOf(info); lic != "" {
				key := sideKey{s.fd, s.ci, s.oldSide}
				if cur, ok := lics[key]; !ok || info.PublishedAt > cur.published {
					lics[key] = sideLic{info.PublishedAt, lic}
				}
			}
			if s.oldSide {
				continue // departing version: license only
			}
			if c.SourceRepo == "" {
				c.SourceRepo = sourceRepo(info)
			}
			if info.IsDeprecated {
				c.Deprecated = true
				if c.DeprecatedReason == "" {
					c.DeprecatedReason = firstLine(info.DeprecatedReason)
				}
			}
			t, err := time.Parse(time.RFC3339, info.PublishedAt)
			if err != nil {
				continue
			}
			// Keep the most recently published of the introduced versions.
			if c.PublishedAt == "" || t.Format(time.RFC3339) > c.PublishedAt {
				c.PublishedAt = t.UTC().Format(time.RFC3339)
				age := int(now.Sub(t).Hours() / 24)
				if age < 0 {
					age = 0
				}
				c.AgeDays = age
				c.Fresh = freshDays > 0 && now.Sub(t) < time.Duration(freshDays)*24*time.Hour
			}
		}
	}

	// A license change is only claimed when the registry reports a
	// license for BOTH sides and they differ.
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			oldL, okOld := lics[sideKey{i, j, true}]
			newL, okNew := lics[sideKey{i, j, false}]
			if !okOld || !okNew {
				continue
			}
			c.OldLicense, c.NewLicense = oldL.license, newL.license
			c.LicenseChanged = !strings.EqualFold(oldL.license, newL.license)
		}
	}
	return nil
}

// runBatch posts one chunk and returns one entry per request (nil when
// deps.dev has no data for that version), following pagination if needed.
func runBatch(reqs []request) ([]*versionInfo, error) {
	out := make([]*versionInfo, len(reqs))
	pos := 0
	pageToken := ""
	for {
		payload := map[string]any{"requests": reqs}
		if pageToken != "" {
			payload["pageToken"] = pageToken
		}
		body, _ := json.Marshal(payload)
		resp, err := client.Post(BatchURL, "application/json", bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("deps.dev unreachable: %w", err)
		}
		var doc struct {
			Responses []struct {
				Version *versionInfo `json:"version"`
			} `json:"responses"`
			NextPageToken string `json:"nextPageToken"`
		}
		err = json.NewDecoder(resp.Body).Decode(&doc)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("deps.dev returned HTTP %d", resp.StatusCode)
		}
		if err != nil {
			return nil, err
		}
		for _, r := range doc.Responses {
			if pos >= len(out) {
				return nil, fmt.Errorf("deps.dev returned more results than queries")
			}
			out[pos] = r.Version
			pos++
		}
		if doc.NextPageToken == "" {
			break
		}
		pageToken = doc.NextPageToken
	}
	if pos != len(out) {
		return nil, fmt.Errorf("deps.dev returned %d results for %d queries", pos, len(out))
	}
	return out, nil
}

// runSingles resolves one chunk with one GET per version key, a few at a
// time. 404 means deps.dev has no data for that version (nil entry), like
// an empty batch response.
func runSingles(reqs []request) ([]*versionInfo, error) {
	out := make([]*versionInfo, len(reqs))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	for i, r := range reqs {
		wg.Add(1)
		go func(i int, vk versionKey) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			mu.Lock()
			stop := firstErr != nil
			mu.Unlock()
			if stop {
				return
			}
			u := SingleURL + "/systems/" + neturl.PathEscape(vk.System) +
				"/packages/" + neturl.PathEscape(vk.Name) +
				"/versions/" + neturl.PathEscape(vk.Version)
			resp, err := client.Get(u)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("deps.dev unreachable: %w", err)
				}
				mu.Unlock()
				return
			}
			defer resp.Body.Close()
			switch resp.StatusCode {
			case 200:
				var info versionInfo
				if err := json.NewDecoder(resp.Body).Decode(&info); err == nil {
					out[i] = &info
				}
			case 404:
				// unknown version: leave nil
			default:
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("deps.dev returned HTTP %d", resp.StatusCode)
				}
				mu.Unlock()
			}
		}(i, r.VersionKey)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			s = s[:i]
			break
		}
	}
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
