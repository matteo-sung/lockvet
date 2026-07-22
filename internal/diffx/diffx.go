// Package diffx computes the semantic difference between two lockfiles.
package diffx

import (
	"sort"
	"strings"

	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// Kind of change for a single package.
type Kind string

const (
	Added      Kind = "added"
	Removed    Kind = "removed"
	Upgraded   Kind = "upgraded"
	Downgraded Kind = "downgraded"
	Changed    Kind = "changed" // multi-version set changed
)

// Change describes what happened to one package.
type Change struct {
	Name        string     `json:"name"`
	Ecosystem   string     `json:"ecosystem"`
	Kind        Kind       `json:"kind"`
	Old         []string   `json:"old,omitempty"`
	New         []string   `json:"new,omitempty"`
	Level       vers.Level `json:"-"`
	LevelString string     `json:"level,omitempty"`

	// Filled in by the OSV layer.
	IntroducedVulns []Vuln `json:"introduced_vulns,omitempty"` // affect new, not old
	FixedVulns      []Vuln `json:"fixed_vulns,omitempty"`      // affected old, not new
	ExistingVulns   []Vuln `json:"existing_vulns,omitempty"`   // affect both
}

// Vuln is a known vulnerability reference.
type Vuln struct {
	ID       string `json:"id"`
	Summary  string `json:"summary,omitempty"`
	Severity string `json:"severity,omitempty"`
	URL      string `json:"url,omitempty"`
}

// FileDiff is the set of changes within one lockfile.
type FileDiff struct {
	Path      string   `json:"path"`
	Kind      string   `json:"lockfile"`
	Ecosystem string   `json:"ecosystem"`
	Changes   []Change `json:"changes"`
}

// Diff compares two parsed lockfiles (either may be nil for created/deleted).
func Diff(oldF, newF *lock.File) FileDiff {
	ref := newF
	if ref == nil {
		ref = oldF
	}
	fd := FileDiff{Path: ref.Path, Kind: ref.Kind, Ecosystem: string(ref.Ecosystem)}

	names := map[string]bool{}
	oldPkgs, newPkgs := map[string][]string{}, map[string][]string{}
	if oldF != nil {
		oldPkgs = oldF.Packages
	}
	if newF != nil {
		newPkgs = newF.Packages
	}
	for n := range oldPkgs {
		names[n] = true
	}
	for n := range newPkgs {
		names[n] = true
	}

	for name := range names {
		o, n := oldPkgs[name], newPkgs[name]
		if equal(o, n) {
			continue
		}
		c := Change{Name: name, Ecosystem: fd.Ecosystem, Old: o, New: n}
		switch {
		case len(o) == 0:
			c.Kind = Added
		case len(n) == 0:
			c.Kind = Removed
		case len(o) == 1 && len(n) == 1:
			if vers.Compare(o[0], n[0]) < 0 {
				c.Kind = Upgraded
			} else {
				c.Kind = Downgraded
			}
			c.Level = vers.Delta(o[0], n[0])
			c.LevelString = c.Level.String()
		default:
			c.Kind = Changed
			c.Level = maxDelta(o, n)
			c.LevelString = c.Level.String()
		}
		fd.Changes = append(fd.Changes, c)
	}

	sort.Slice(fd.Changes, func(i, j int) bool {
		a, b := fd.Changes[i], fd.Changes[j]
		if a.Level != b.Level {
			return a.Level > b.Level // major first
		}
		if a.Kind != b.Kind {
			return kindRank(a.Kind) < kindRank(b.Kind)
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return fd
}

func kindRank(k Kind) int {
	switch k {
	case Downgraded:
		return 0
	case Upgraded:
		return 1
	case Changed:
		return 2
	case Added:
		return 3
	case Removed:
		return 4
	}
	return 5
}

func maxDelta(o, n []string) vers.Level {
	max := vers.None
	for _, ov := range o {
		for _, nv := range n {
			if d := vers.Delta(ov, nv); d != vers.Unknown && d > max {
				max = d
			}
		}
	}
	return max
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Summary aggregates counts across file diffs.
type Summary struct {
	Total, Major, Minor, Patch, Added, Removed, Downgraded int
	VulnsIntroduced, VulnsFixed, VulnsExisting             int
}

// Summarize computes totals for a set of file diffs.
func Summarize(diffs []FileDiff) Summary {
	var s Summary
	for _, fd := range diffs {
		for _, c := range fd.Changes {
			s.Total++
			switch c.Kind {
			case Added:
				s.Added++
			case Removed:
				s.Removed++
			case Downgraded:
				s.Downgraded++
			}
			if c.Kind == Upgraded || c.Kind == Downgraded || c.Kind == Changed {
				switch c.Level {
				case vers.Major:
					s.Major++
				case vers.Minor:
					s.Minor++
				case vers.Patch:
					s.Patch++
				}
			}
			s.VulnsIntroduced += len(c.IntroducedVulns)
			s.VulnsFixed += len(c.FixedVulns)
			s.VulnsExisting += len(c.ExistingVulns)
		}
	}
	return s
}
