// Package osv queries the OSV.dev vulnerability database.
package osv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/matteo-sung/lockvet/internal/lock"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

const (
	batchURL   = "https://api.osv.dev/v1/querybatch"
	vulnURL    = "https://api.osv.dev/v1/vulns/"
	maxDetails = 150 // cap detail lookups per run
)

var client = &http.Client{Timeout: 20 * time.Second}

type query struct {
	Version string `json:"version"`
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
}

// Annotate fills IntroducedVulns / FixedVulns on every change, in place.
// It is best-effort: network errors return an error but leave diffs usable.
func Annotate(diffs []diffx.FileDiff) error {
	type slot struct {
		fd, ci int
		side   string // "old" or "new"
	}
	var queries []query
	var slots []slot

	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if !lock.Ecosystem(c.Ecosystem).HasOSV() {
				continue // e.g. Nix: no OSV.dev ecosystem
			}
			for _, v := range c.Old {
				queries = append(queries, mkQuery(c.Name, c.Ecosystem, v))
				slots = append(slots, slot{i, j, "old"})
			}
			for _, v := range c.New {
				queries = append(queries, mkQuery(c.Name, c.Ecosystem, v))
				slots = append(slots, slot{i, j, "new"})
			}
		}
	}
	if len(queries) == 0 {
		return nil
	}

	// vuln IDs affecting old/new versions, per change
	oldIDs := map[[2]int]map[string]bool{}
	newIDs := map[[2]int]map[string]bool{}

	for start := 0; start < len(queries); start += 1000 {
		end := min(start+1000, len(queries))
		results, err := runBatch(queries[start:end])
		if err != nil {
			return err
		}
		for k, res := range results {
			s := slots[start+k]
			key := [2]int{s.fd, s.ci}
			m := newIDs
			if s.side == "old" {
				m = oldIDs
			}
			if m[key] == nil {
				m[key] = map[string]bool{}
			}
			for _, v := range res.Vulns {
				m[key][v.ID] = true
			}
		}
	}

	// Partition IDs per change, then fetch details by priority:
	// introduced first, then fixed, then existing.
	type part struct{ intro, fixed, exist map[string]bool }
	parts := map[[2]int]part{}
	var pri1, pri2, pri3 []string
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			key := [2]int{i, j}
			pt := part{map[string]bool{}, map[string]bool{}, map[string]bool{}}
			for id := range newIDs[key] {
				if oldIDs[key][id] {
					pt.exist[id] = true
					pri3 = append(pri3, id)
				} else {
					pt.intro[id] = true
					pri1 = append(pri1, id)
				}
			}
			for id := range oldIDs[key] {
				if !newIDs[key][id] && len(c.New) > 0 {
					pt.fixed[id] = true
					pri2 = append(pri2, id)
				}
			}
			parts[key] = pt
		}
	}
	details := fetchDetails(append(append(pri1, pri2...), pri3...))

	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			pt := parts[[2]int{i, j}]
			c.IntroducedVulns = dedupe(pt.intro, details)
			c.FixedVulns = dedupe(pt.fixed, details)
			c.ExistingVulns = dedupe(pt.exist, details)
		}
	}
	return nil
}

// dedupe collapses advisories that are aliases of each other (e.g. a PYSEC
// and a GHSA entry for the same CVE), preferring GHSA > CVE > other IDs,
// and sorts by severity then ID.
func dedupe(ids map[string]bool, details map[string]vulnDetail) []diffx.Vuln {
	if len(ids) == 0 {
		return nil
	}
	// Union-find over alias groups.
	group := map[string]string{} // alias -> representative id seen first
	var reps []string
	for id := range ids {
		rep := ""
		aliases := append([]string{id}, details[id].aliases...)
		for _, a := range aliases {
			if g, ok := group[a]; ok {
				rep = g
				break
			}
		}
		if rep == "" {
			rep = id
			reps = append(reps, rep)
		}
		for _, a := range aliases {
			group[a] = rep
		}
	}
	// Pick the best-named member of each group.
	best := map[string]string{}
	for id := range ids {
		rep := group[id]
		if cur, ok := best[rep]; !ok || idRank(id) < idRank(cur) {
			best[rep] = id
		}
	}
	var out []diffx.Vuln
	for _, rep := range reps {
		id := best[rep]
		d := details[id]
		out = append(out, diffx.Vuln{
			ID: id, Summary: d.summary, Severity: d.severity,
			URL: "https://osv.dev/vulnerability/" + id,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if r1, r2 := sevRank(a.Severity), sevRank(b.Severity); r1 != r2 {
			return r1 < r2
		}
		return a.ID < b.ID
	})
	return out
}

func idRank(id string) int {
	switch {
	case strings.HasPrefix(id, "GHSA-"):
		return 0
	case strings.HasPrefix(id, "CVE-"):
		return 1
	case strings.HasPrefix(id, "RUSTSEC-"):
		return 2
	}
	return 3
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	case "moderate", "medium":
		return 2
	case "low":
		return 3
	}
	return 4
}

func mkQuery(name, eco, version string) query {
	var q query
	q.Package.Name = name
	q.Package.Ecosystem = eco
	q.Version = version
	return q
}

type batchResult struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
}

func runBatch(qs []query) ([]batchResult, error) {
	body, _ := json.Marshal(map[string]any{"queries": qs})
	resp, err := client.Post(batchURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv.dev unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("osv.dev returned HTTP %d", resp.StatusCode)
	}
	var out struct {
		Results []batchResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Results) != len(qs) {
		return nil, fmt.Errorf("osv.dev returned %d results for %d queries", len(out.Results), len(qs))
	}
	return out.Results, nil
}

type vulnDetail struct {
	summary, severity string
	aliases           []string
}

// fetchDetails fetches vulnerability details for ids (in priority order),
// up to the cap.
func fetchDetails(ids []string) map[string]vulnDetail {
	out := map[string]vulnDetail{}
	seen := map[string]bool{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	n := 0
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		if n++; n > maxDetails {
			break
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if v, err := fetchVuln(id); err == nil {
				mu.Lock()
				out[id] = v
				mu.Unlock()
			}
		}(id)
	}
	wg.Wait()
	return out
}

func fetchVuln(id string) (vulnDetail, error) {
	var v vulnDetail
	resp, err := client.Get(vulnURL + id)
	if err != nil {
		return v, err
	}
	defer resp.Body.Close()
	var doc struct {
		Summary          string   `json:"summary"`
		Details          string   `json:"details"`
		Aliases          []string `json:"aliases"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return v, err
	}
	v.summary = doc.Summary
	if v.summary == "" {
		v.summary = firstLine(doc.Details)
	}
	v.severity = strings.ToLower(doc.DatabaseSpecific.Severity)
	v.aliases = doc.Aliases
	return v, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return strings.TrimSpace(s)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
