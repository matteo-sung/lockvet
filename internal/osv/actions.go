package osv

// Client-side range evaluation for the "GitHub Actions" ecosystem: OSV's
// API can't match versions against ECOSYSTEM ranges there (every version
// query returns empty even when advisories exist), so lockvet queries the
// package, fetches the advisories' affected ranges, and evaluates them
// itself — against the release each pin resolves to (internal/actreg
// settles SHA pins and floating major tags first).

import (
	"fmt"
	"strings"

	"github.com/matteo-sung/lockvet/internal/actreg"
	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// evalActions fills oldIDs/newIDs for workflow pin changes, keyed like the
// standard batch path so partitioning downstream is identical.
func evalActions(diffs []diffx.FileDiff, actionChanges map[string][][2]int, oldIDs, newIDs map[[2]int]map[string]bool) error {
	if len(actionChanges) == 0 {
		return nil
	}
	var names []string
	var queries []query
	for name := range actionChanges {
		names = append(names, name)
		queries = append(queries, mkQuery(name, "GitHub Actions", ""))
	}
	results, err := db.batch(queries)
	if err != nil {
		return err
	}

	var allIDs []string
	idsByName := map[string][]string{}
	for k, res := range results {
		for _, v := range res.Vulns {
			idsByName[names[k]] = append(idsByName[names[k]], v.ID)
			allIDs = append(allIDs, v.ID)
		}
	}
	if len(allIDs) == 0 {
		return nil
	}
	details := db.details(allIDs)

	for name, keys := range actionChanges {
		for _, key := range keys {
			c := &diffs[key[0]].Changes[key[1]]
			// If no incoming pin can be evaluated (orphan SHA, branch),
			// skip the outgoing side too: recording only old-side hits
			// would surface as "fixes GHSA-…", and moving onto an
			// unknowable commit fixes nothing.
			if len(c.New) > 0 {
				evaluable := false
				for _, v := range c.New {
					if actreg.VersionLike(actreg.Effective(c, v)) {
						evaluable = true
						break
					}
				}
				if !evaluable {
					continue
				}
			}
			for _, id := range idsByName[name] {
				det, ok := details[id]
				if !ok {
					continue
				}
				record := func(m map[[2]int]map[string]bool, versions []string) {
					for _, raw := range versions {
						if !actionAffected(det, name, c, raw) {
							continue
						}
						if m[key] == nil {
							m[key] = map[string]bool{}
						}
						m[key][id] = true
					}
				}
				record(oldIDs, c.Old)
				record(newIDs, c.New)
			}
		}
	}
	return nil
}

// actionAffected reports whether the pin raw (resolved via the change's
// ResolvedRefs where possible) falls in the advisory's affected set.
func actionAffected(det vulnDetail, name string, c *diffx.Change, raw string) bool {
	eff := actreg.Effective(c, raw)
	if !actreg.VersionLike(eff) {
		return false // unresolved SHA or branch ref: nothing to evaluate
	}
	ver := strings.TrimPrefix(eff, "v")

	// A floating major tag that actreg could not resolve (offline, fetch
	// failed) covers a whole line of releases: claim affected only when
	// both ends of that major are inside the range, so an advisory fixed
	// within the major (which the floating tag likely points past)
	// doesn't false-positive.
	floating := eff == raw && !strings.Contains(ver, ".")

	// GHSA records actions advisories per major line (">= 2.26.11,
	// < 3.0.0"), but the OSV export sometimes drops the upper bound of a
	// never-patched line, leaving an open-ended range that would flag
	// every later major forever. When ANOTHER range of the same advisory
	// carries a fix, cap such open ranges at the next major of their
	// introduced version — the line they actually describe.
	hasFix := false
	for _, a := range det.affected {
		if !strings.EqualFold(a.Package.Name, name) {
			continue
		}
		for _, r := range a.Ranges {
			for _, ev := range r.Events {
				if _, ok := ev["fixed"]; ok {
					hasFix = true
				}
			}
		}
	}

	for _, a := range det.affected {
		if !strings.EqualFold(a.Package.Name, name) || a.Package.Ecosystem != "GitHub Actions" {
			continue
		}
		for _, v := range a.Versions {
			if strings.TrimPrefix(v, "v") == ver {
				return true
			}
		}
		for _, r := range a.Ranges {
			if r.Type != "ECOSYSTEM" && r.Type != "SEMVER" {
				continue
			}
			events := r.Events
			if hasFix {
				events = capOpenRange(events)
			}
			if floating {
				if inEvents(events, ver) && inEvents(events, ver+".999999999.999999999") {
					return true
				}
			} else if inEvents(events, ver) {
				return true
			}
		}
	}
	return false
}

// capOpenRange appends a synthetic "fixed: <next major>" to a range that
// has an introduced version (> 0) but no upper bound at all.
func capOpenRange(events []map[string]string) []map[string]string {
	intro := ""
	for _, ev := range events {
		if _, ok := ev["fixed"]; ok {
			return events
		}
		if _, ok := ev["last_affected"]; ok {
			return events
		}
		if v, ok := ev["introduced"]; ok {
			intro = v
		}
	}
	if intro == "" || intro == "0" {
		return events
	}
	maj := strings.TrimPrefix(intro, "v")
	if i := strings.IndexAny(maj, ".-+"); i >= 0 {
		maj = maj[:i]
	}
	n := 0
	for i := 0; i < len(maj); i++ {
		if maj[i] < '0' || maj[i] > '9' {
			return events
		}
		n = n*10 + int(maj[i]-'0')
	}
	out := make([]map[string]string, len(events), len(events)+1)
	copy(out, events)
	return append(out, map[string]string{"fixed": fmt.Sprintf("%d.0.0", n+1)})
}

// inEvents evaluates OSV range events (introduced / fixed / last_affected)
// against a version.
func inEvents(events []map[string]string, ver string) bool {
	affected := false
	for _, ev := range events {
		if v, ok := ev["introduced"]; ok {
			if v == "0" || vers.Compare(strings.TrimPrefix(v, "v"), ver) <= 0 {
				affected = true
			}
		}
		if v, ok := ev["fixed"]; ok && affected {
			if vers.Compare(strings.TrimPrefix(v, "v"), ver) <= 0 {
				affected = false
			}
		}
		if v, ok := ev["last_affected"]; ok && affected {
			if vers.Compare(strings.TrimPrefix(v, "v"), ver) < 0 {
				affected = false
			}
		}
	}
	return affected
}
