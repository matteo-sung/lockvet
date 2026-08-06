// Package squat flags newly-added dependencies whose names are one edit
// away from a popular package on the same registry — the shape of a
// typosquatting attack (npm, PyPI, crates.io, RubyGems, Packagist).
//
// The check is entirely local: the popular-package name lists are embedded
// at build time, so it runs offline and in the browser playground alike.
//
// Noise control, in the spirit of every other lockvet signal:
//
//   - only packages ENTERING the tree are checked (an existing dependency
//     being bumped cannot change its name);
//   - the incoming release must be young (≤ 30 days) or of unknown age —
//     a name that has coexisted with its popular neighbour for years is
//     an unfortunate name, not an attack;
//   - the added package must not itself be on the popular list;
//   - name pairs a registry treats as the SAME package never flag
//     (PyPI: '-', '_' and '.' are interchangeable per PEP 503;
//     crates.io: '-'/'_' collisions are blocked at publish time);
//   - names shorter than 4 characters are skipped (too collision-prone).
//
// Popular-package data sources (regenerate with gen.sh):
//
//   - npm: the npm-high-impact list by Titus Wormer (MIT),
//     https://github.com/wooorm/npm-high-impact
//   - PyPI: Top PyPI Packages by Hugo van Kemenade,
//     https://github.com/hugovk/top-pypi-packages
//     (DOI 10.5281/zenodo.2586599), top 8 000
//   - crates.io: the crates.io API, sorted by all-time downloads, top 2 500
//   - RubyGems: the ecosyste.ms packages API (data CC BY-SA 4.0),
//     rubygems.org sorted by all-time downloads, top 5 000
//   - Packagist: packagist.org's official explore/popular API, top 4 000
package squat

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"strings"
	"sync"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/lock"
)

//go:embed data/npm.txt.gz
var npmData []byte

//go:embed data/pypi.txt.gz
var pypiData []byte

//go:embed data/crates.txt.gz
var cratesData []byte

//go:embed data/gems.txt.gz
var gemsData []byte

//go:embed data/php.txt.gz
var phpData []byte

// MaxAgeDays is the young-release gate: additions older than this never
// flag, however confusable their name is.
const MaxAgeDays = 30

type index struct {
	exact    map[string]string   // fold(name) -> original popular spelling
	variants map[string][]string // delete-1 variant of fold(name) -> popular spellings
}

var (
	once    sync.Once
	indexes map[lock.Ecosystem]*index
)

// fold is the matching key: lowercase with '-', '_' and '.' collapsed to
// '-', so separator confusion is one shared representation away.
func fold(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}

// canon returns the identity under which the registry itself considers two
// names the same package. Names with equal canon must never flag.
func canon(eco lock.Ecosystem, name string) string {
	switch eco {
	case lock.PyPI:
		// PEP 503: runs of '-', '_', '.' compare equal.
		return fold(strings.ToLower(name))
	case lock.CratesIO:
		// crates.io blocks publishing foo_bar next to foo-bar.
		return strings.ReplaceAll(strings.ToLower(name), "_", "-")
	default:
		// npm, RubyGems, Packagist: separator swaps are distinct names
		// (lodash.merge vs lodash-merge, rack-cache vs rack_cache).
		return strings.ToLower(name)
	}
}

func deletions(s string) []string {
	out := make([]string, 0, len(s))
	for i := range s {
		out = append(out, s[:i]+s[i+1:])
	}
	return out
}

func load(data []byte) *index {
	idx := &index{exact: map[string]string{}, variants: map[string][]string{}}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return idx
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		name := strings.TrimSpace(sc.Text())
		if name == "" {
			continue
		}
		f := fold(name)
		if _, dup := idx.exact[f]; !dup {
			idx.exact[f] = name
		}
		for _, v := range deletions(f) {
			idx.variants[v] = append(idx.variants[v], name)
		}
	}
	return idx
}

func ensure() {
	once.Do(func() {
		indexes = map[lock.Ecosystem]*index{
			lock.NPM:       load(npmData),
			lock.PyPI:      load(pypiData),
			lock.CratesIO:  load(cratesData),
			lock.RubyGems:  load(gemsData),
			lock.Packagist: load(phpData),
		}
	})
}

// osa1 reports whether the optimal-string-alignment distance between a and
// b is exactly 1 (single insertion, deletion, substitution or adjacent
// transposition).
func osa1(a, b string) bool {
	la, lb := len(a), len(b)
	if la > lb {
		a, b, la, lb = b, a, lb, la
	}
	switch lb - la {
	case 0:
		// substitution or adjacent transposition
		diff := -1
		for i := 0; i < la; i++ {
			if a[i] != b[i] {
				diff = i
				break
			}
		}
		if diff == -1 {
			return false // equal
		}
		if a[diff+1:] == b[diff+1:] {
			return true // one substitution
		}
		// adjacent transposition
		return diff+1 < la && a[diff] == b[diff+1] && a[diff+1] == b[diff] &&
			a[diff+2:] == b[diff+2:]
	case 1:
		// one insertion into a
		for i := 0; i < la; i++ {
			if a[i] != b[i] {
				return a[i:] == b[i+1:]
			}
		}
		return true // insertion at the end
	default:
		return false
	}
}

// Match returns the popular package name (in its original spelling) that
// `name` is at most one edit away from on the ecosystem's registry, or ""
// when there is none — or when the pair could never be a squat (same
// canonical package, name itself popular, name too short).
func Match(eco lock.Ecosystem, name string) string {
	ensure()
	idx, ok := indexes[eco]
	if !ok {
		return ""
	}
	f := fold(name)
	if len(f) < 4 {
		return ""
	}
	if _, popular := idx.exact[f]; popular {
		// The folded name IS on the list. Where the registry keeps
		// separator spellings distinct (npm, RubyGems, Packagist), a
		// different raw spelling of a popular folded name (lodash.merge
		// vs lodash-merge, rack-cache vs rack_cache) is a real squat;
		// for PyPI/crates the registry treats them as one package and
		// canon comes out equal.
		orig := idx.exact[f]
		if canon(eco, orig) != canon(eco, name) {
			return orig
		}
		return ""
	}
	seen := map[string]bool{}
	candidates := []string{}
	add := func(list []string) {
		for _, c := range list {
			if !seen[c] {
				seen[c] = true
				candidates = append(candidates, c)
			}
		}
	}
	// popular names one insertion away (f is one of their delete-1
	// variants), one deletion away (a delete-1 of f is popular), and
	// substitution/transposition neighbours (shared delete-1 variant).
	add(idx.variants[f])
	for _, v := range deletions(f) {
		if orig, ok := idx.exact[v]; ok {
			add([]string{orig})
		}
		add(idx.variants[v])
	}
	best := ""
	for _, cand := range candidates {
		cf := fold(cand)
		if osa1(cf, f) {
			if canon(eco, cand) == canon(eco, name) {
				continue // same package as far as the registry cares
			}
			if best == "" || cand < best {
				best = cand
			}
		}
	}
	return best
}

// Annotate flags added packages whose names are confusable with a popular
// package. Runs after the metadata layers so the young-release gate can
// use PublishedAt/AgeDays.
func Annotate(diffs []diffx.FileDiff) {
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Kind != diffx.Added || c.NonRegistry {
				continue
			}
			if c.PublishedAt != "" && c.AgeDays > MaxAgeDays {
				continue
			}
			eco := lock.Ecosystem(c.Ecosystem)
			if m := Match(eco, c.Name); m != "" {
				c.TyposquatOf = m
			}
		}
	}
}
