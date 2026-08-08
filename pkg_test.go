package main

import (
	"testing"

	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/pkgspec"
)

func TestParsePkgSpec(t *testing.T) {
	cases := []struct {
		in      string
		eco     lock.Ecosystem
		name    string
		version string
	}{
		{"npm:left-pad", lock.NPM, "left-pad", ""},
		{"npm:chalk@5.6.1", lock.NPM, "chalk", "5.6.1"},
		{"npm:@types/node", lock.NPM, "@types/node", ""},
		{"npm:@types/node@24.0.0", lock.NPM, "@types/node", "24.0.0"},
		{"jsr:@std/http@1.0.0", lock.NPM, "jsr:@std/http", "1.0.0"},
		{"pypi:requests@2.32.0", lock.PyPI, "requests", "2.32.0"},
		{"pip:requests", lock.PyPI, "requests", ""},
		{"cargo:serde", lock.CratesIO, "serde", ""},
		{"rust:serde@1.0.0", lock.CratesIO, "serde", "1.0.0"},
		{"gem:rails", lock.RubyGems, "rails", ""},
		{"composer:Monolog/Monolog@3.0.0", lock.Packagist, "monolog/monolog", "3.0.0"},
		{"go:github.com/gin-gonic/gin@1.9.0", lock.Go, "github.com/gin-gonic/gin", "v1.9.0"},
		{"go:github.com/BurntSushi/toml", lock.Go, "github.com/BurntSushi/toml", ""},
		{"maven:com.google.guava:guava@33.0.0-jre", lock.Maven, "com.google.guava:guava", "33.0.0-jre"},
		{"nuget:Newtonsoft.Json", lock.NuGet, "newtonsoft.json", ""},
		{"pod:Alamofire@5.9.0", lock.CocoaPods, "Alamofire", "5.9.0"},
		{"terraform:hashicorp/aws", lock.Terraform, "hashicorp/aws", ""},
		{"conan:openssl@3.3.2", lock.Conan, "openssl", "3.3.2"},
		{"cran:dplyr@1.1.4", lock.CRAN, "dplyr", "1.1.4"},
		{"conda:numpy", lock.Conda, "numpy", ""},
		{"conda:numpy@2.5.1", lock.Conda, "numpy", "2.5.1"},
		{"conda:bioconda/samtools@1.20", lock.Conda, "samtools", "1.20"},
		{"hex:phoenix", lock.Hex, "phoenix", ""},
		{"pub:dio@5.0.0", lock.Pub, "dio", "5.0.0"},
	}
	for _, c := range cases {
		spec, err := pkgspec.Parse(c.in)
		if err != nil {
			t.Errorf("pkgspec.Parse(%q): %v", c.in, err)
			continue
		}
		if spec.Eco != c.eco || spec.Name != c.name || spec.Version != c.version {
			t.Errorf("pkgspec.Parse(%q) = {%s %q %q}, want {%s %q %q}",
				c.in, spec.Eco, spec.Name, spec.Version, c.eco, c.name, c.version)
		}
	}
}

func TestParsePkgSpecErrors(t *testing.T) {
	for _, in := range []string{
		"",              // empty
		"left-pad",      // no ecosystem
		"npm:",          // no name
		":left-pad",     // empty ecosystem
		"zzz:something", // unknown ecosystem
		"jsr:std/http",  // JSR names need @scope
	} {
		if _, err := pkgspec.Parse(in); err == nil {
			t.Errorf("pkgspec.Parse(%q): want error, got none", in)
		}
	}
}
