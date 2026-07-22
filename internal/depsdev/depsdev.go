// Package depsdev queries deps.dev for registry metadata: when a version
// was published (fresh-release detection) and whether it is deprecated.
package depsdev

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// BatchURL is a var so tests can point it at a fake server.
var BatchURL = "https://api.deps.dev/v3alpha/versionbatch"

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
	PublishedAt      string `json:"publishedAt"`
	IsDeprecated     bool   `json:"isDeprecated"`
	DeprecatedReason string `json:"deprecatedReason"`
}

// Annotate fills PublishedAt / AgeDays / Fresh / Deprecated on every change
// that introduces a version, in place. A version counts as fresh when it was
// published fewer than freshDays days before now. Best-effort: network
// errors return an error but leave diffs usable.
func Annotate(diffs []diffx.FileDiff, freshDays int) error {
	type slot struct{ fd, ci int }
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
			for _, v := range c.New {
				if old[v] {
					continue // only versions this change introduces
				}
				qv := v
				if sys == "GO" && !strings.HasPrefix(qv, "v") {
					qv = "v" + qv // lockvet stores Go versions without the prefix
				}
				reqs = append(reqs, request{versionKey{sys, c.Name, qv}})
				slots = append(slots, slot{i, j})
			}
		}
	}
	if len(reqs) == 0 {
		return nil
	}

	now := Now()
	for start := 0; start < len(reqs); start += chunkSize {
		end := min(start+chunkSize, len(reqs))
		infos, err := runBatch(reqs[start:end])
		if err != nil {
			return err
		}
		for k, info := range infos {
			if info == nil {
				continue // unknown to deps.dev
			}
			s := slots[start+k]
			c := &diffs[s.fd].Changes[s.ci]
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
