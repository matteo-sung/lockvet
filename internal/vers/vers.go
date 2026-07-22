// Package vers implements lenient version parsing and comparison that
// tolerates semver, Python versions (1.2.3.post1), Go pseudo-versions,
// and other real-world strings found in lockfiles.
package vers

import (
	"strconv"
	"strings"
)

// Level classifies the significance of a version change.
type Level int

const (
	None Level = iota
	Patch
	Minor
	Major
	Unknown // versions not comparable numerically
)

func (l Level) String() string {
	switch l {
	case Major:
		return "major"
	case Minor:
		return "minor"
	case Patch:
		return "patch"
	case Unknown:
		return "?"
	}
	return ""
}

type parsed struct {
	nums []int  // numeric release components
	pre  string // pre-release / suffix, "" if none
	ok   bool
}

func parse(v string) parsed {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" {
		return parsed{}
	}
	if i := strings.IndexByte(v, '+'); i >= 0 { // build metadata
		v = v[:i]
	}
	rest := ""
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v, rest = v[:i], v[i+1:]
	}
	parts := strings.Split(v, ".")
	var nums []int
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			// tolerate suffixes glued to the last numeric part, e.g. "3a1"
			rest = strings.Join(parts[i:], ".") + dash(rest)
			break
		}
		nums = append(nums, n)
	}
	if len(nums) == 0 {
		return parsed{}
	}
	return parsed{nums: nums, pre: rest, ok: true}
}

func dash(s string) string {
	if s == "" {
		return ""
	}
	return "-" + s
}

// Compare returns -1, 0, or 1. Non-parseable versions compare as strings.
func Compare(a, b string) int {
	pa, pb := parse(a), parse(b)
	if !pa.ok || !pb.ok {
		return strings.Compare(a, b)
	}
	for i := 0; i < len(pa.nums) || i < len(pb.nums); i++ {
		x, y := 0, 0
		if i < len(pa.nums) {
			x = pa.nums[i]
		}
		if i < len(pb.nums) {
			y = pb.nums[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	// equal release: version with a pre-release sorts lower (semver rule),
	// except common post-release markers which sort higher.
	return comparePre(pa.pre, pb.pre)
}

func comparePre(a, b string) int {
	if a == b {
		return 0
	}
	ra, rb := preRank(a), preRank(b)
	if ra != rb {
		if ra < rb {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

// preRank: pre-release < release < post-release.
func preRank(pre string) int {
	switch {
	case pre == "":
		return 1
	case strings.HasPrefix(pre, "post"), strings.HasPrefix(pre, "p"):
		return 2
	default:
		return 0
	}
}

// Delta classifies the jump from old to new.
func Delta(oldV, newV string) Level {
	if oldV == newV {
		return None
	}
	a, b := parse(oldV), parse(newV)
	if !a.ok || !b.ok {
		return Unknown
	}
	get := func(p parsed, i int) int {
		if i < len(p.nums) {
			return p.nums[i]
		}
		return 0
	}
	if get(a, 0) != get(b, 0) {
		return Major
	}
	// 0.x.y: treat minor bumps as major-ish per semver convention? No —
	// report the literal component that changed; the renderer flags 0.x.
	if get(a, 1) != get(b, 1) {
		return Minor
	}
	if get(a, 2) != get(b, 2) {
		return Patch
	}
	if len(a.nums) > 3 || len(b.nums) > 3 || a.pre != b.pre {
		return Patch
	}
	return None
}
