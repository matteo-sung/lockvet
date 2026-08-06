package squat

import (
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/lock"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		eco  lock.Ecosystem
		name string
		want string
	}{
		// classic single-edit squats
		{lock.NPM, "lodahs", "lodash"},               // transposition
		{lock.NPM, "lodashs", "lodash"},              // insertion
		{lock.NPM, "expres", "express"},              // deletion
		{lock.NPM, "chalk", ""},                      // the real thing
		{lock.PyPI, "requestss", "requests"},         // insertion
		{lock.PyPI, "reqeusts", "requests"},          // transposition
		{lock.CratesIO, "serde-json", ""},            // same package as serde_json on crates.io
		{lock.CratesIO, "serde-jsonn", "serde_json"}, // 1 edit past the canon guard
		{lock.PyPI, "typing-extensions", ""},         // popular itself
		{lock.PyPI, "typing_extensions", ""},         // PEP 503 same package
		{lock.NPM, "ms", ""},                         // too short
		{lock.NPM, "some-very-unique-name", ""},      // nowhere near anything
		// RubyGems: '-' and '_' are DISTINCT gem names
		{lock.RubyGems, "nokogiri", ""},                    // popular itself
		{lock.RubyGems, "nokogirl", "nokogiri"},            // substitution
		{lock.RubyGems, "active-support", "activesupport"}, // separator insertion
		{lock.RubyGems, "rack_cache", "rack-cache"},        // separator swap of a popular gem
		{lock.RubyGems, "devsie", "devise"},                // transposition
		// rspec-mokcs is the example ReversingLabs' writeup of the Feb 2020
		// RubyGems typosquat campaign (760+ malicious gems) leads with.
		{lock.RubyGems, "rspec-mokcs", "rspec-mocks"},
		// Packagist: vendor/package names, separators distinct
		{lock.Packagist, "monolog/monolog", ""},                 // popular itself
		{lock.Packagist, "monolog/monolg", "monolog/monolog"},   // deletion
		{lock.Packagist, "symfonny/console", "symfony/console"}, // vendor squat
		{lock.Packagist, "guzzlehttp/guzle", "guzzlehttp/guzzle"},
		{lock.Packagist, "laravel/framewrok", "laravel/framework"},
	}
	for _, c := range cases {
		got := Match(c.eco, c.name)
		if got != c.want {
			t.Errorf("Match(%s, %q) = %q, want %q", c.eco, c.name, got, c.want)
		}
	}
}

func TestOSA1(t *testing.T) {
	yes := [][2]string{{"lodash", "lodahs"}, {"lodash", "lodas"}, {"lodash", "lodashx"}, {"lodash", "lodesh"}}
	no := [][2]string{{"lodash", "lodash"}, {"lodash", "loadhs"}, {"lodash", "lod"}, {"cat", "dog"}}
	for _, p := range yes {
		if !osa1(p[0], p[1]) {
			t.Errorf("osa1(%q,%q) = false, want true", p[0], p[1])
		}
	}
	for _, p := range no {
		if osa1(p[0], p[1]) {
			t.Errorf("osa1(%q,%q) = true, want false", p[0], p[1])
		}
	}
}

func TestAnnotateGates(t *testing.T) {
	mk := func(kind diffx.Kind, age int, pub string, nonReg bool) diffx.Change {
		return diffx.Change{Name: "lodahs", Ecosystem: "npm", Kind: kind,
			New: []string{"1.0.0"}, AgeDays: age, PublishedAt: pub, NonRegistry: nonReg}
	}
	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		mk(diffx.Added, 3, "2026-08-01T00:00:00Z", false),    // flags
		mk(diffx.Added, 400, "2025-01-01T00:00:00Z", false),  // old: no flag
		mk(diffx.Added, 0, "", false),                        // unknown age: flags
		mk(diffx.Upgraded, 3, "2026-08-01T00:00:00Z", false), // not an addition
		mk(diffx.Added, 3, "2026-08-01T00:00:00Z", true),     // non-registry
	}}}
	Annotate(diffs)
	got := []bool{}
	for _, c := range diffs[0].Changes {
		got = append(got, c.TyposquatOf != "")
	}
	want := []bool{true, false, true, false, false}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("change %d: flagged=%v, want %v", i, got[i], want[i])
		}
	}
}
