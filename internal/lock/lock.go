// Package lock parses dependency lockfiles into a common representation.
package lock

import (
	"path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Ecosystem is an OSV.dev ecosystem identifier.
type Ecosystem string

const (
	NPM       Ecosystem = "npm"
	CratesIO  Ecosystem = "crates.io"
	PyPI      Ecosystem = "PyPI"
	Go        Ecosystem = "Go"
	Packagist Ecosystem = "Packagist"
	RubyGems  Ecosystem = "RubyGems"
	Hex       Ecosystem = "Hex"
	Pub       Ecosystem = "Pub"
	Maven     Ecosystem = "Maven"
	NuGet     Ecosystem = "NuGet"
	SwiftURL  Ecosystem = "SwiftURL"
	CocoaPods Ecosystem = "CocoaPods"

	// Nix has no OSV.dev ecosystem and no semver: flake inputs pin git
	// revisions. lockvet still explains what moved and by how much time.
	Nix Ecosystem = "Nix"
)

// HasOSV reports whether the ecosystem can be queried on OSV.dev.
// CocoaPods and Nix have no OSV.dev ecosystem (verified live: OSV returns
// "invalid ecosystem"), so lockvet explains those diffs without vuln data.
func (e Ecosystem) HasOSV() bool { return e != Nix && e != CocoaPods }

// HasSemver reports whether version-jump levels (major/minor/patch) are
// meaningful for the ecosystem.
func (e Ecosystem) HasSemver() bool { return e != Nix }

// File is a parsed lockfile: package name -> set of pinned versions.
// A lockfile may legitimately contain multiple versions of one package
// (npm nesting, cargo duplicate majors), hence the set.
type File struct {
	Path      string
	Kind      string // e.g. "package-lock.json"
	Ecosystem Ecosystem
	Packages  map[string][]string

	// Dependency-graph info, filled in only when the lockfile format
	// records it. Deps maps package name -> names it depends on.
	// Roots are the project's *direct* dependencies when the lockfile
	// itself says so (npm root entry, pnpm importers, Gemfile.lock
	// DEPENDENCIES, go.mod without "// indirect", ...).
	// RootsKnown distinguishes "no roots recorded" from "empty roots".
	Deps       map[string][]string
	Roots      []string
	RootsKnown bool
}

func newFile(p, kind string, eco Ecosystem) *File {
	return &File{Path: p, Kind: kind, Ecosystem: eco, Packages: map[string][]string{}}
}

// addEdge records "from depends on to". Self-edges and empty names are dropped.
func (f *File) addEdge(from, to string) {
	from, to = Sanitize(from), Sanitize(to)
	if from == "" || to == "" || from == to {
		return
	}
	if f.Deps == nil {
		f.Deps = map[string][]string{}
	}
	for _, d := range f.Deps[from] {
		if d == to {
			return
		}
	}
	f.Deps[from] = append(f.Deps[from], to)
}

// addRoot records a known direct dependency.
func (f *File) addRoot(name string) {
	f.RootsKnown = true
	name = Sanitize(name)
	if name == "" {
		return
	}
	for _, r := range f.Roots {
		if r == name {
			return
		}
	}
	f.Roots = append(f.Roots, name)
}

// Sanitize makes untrusted strings (lockfile- or registry-derived) safe to
// render: it enforces valid UTF-8 and strips control characters (so hostile
// input cannot smuggle ANSI escape sequences into terminal output).
func Sanitize(s string) string {
	if s == "" {
		return s
	}
	clean := true
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) {
			b.WriteRune('\uFFFD')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (f *File) add(name, version string) {
	name, version = Sanitize(name), Sanitize(version)
	if name == "" || version == "" {
		return
	}
	for _, v := range f.Packages[name] {
		if v == version {
			return
		}
	}
	f.Packages[name] = append(f.Packages[name], version)
	sort.Strings(f.Packages[name])
}

// Parser turns lockfile bytes into a File.
type Parser struct {
	Kind      string
	Ecosystem Ecosystem
	Parse     func(p string, data []byte) (*File, error)
}

// ByBasename returns the parser responsible for a given file path, or nil.
func ByBasename(p string) *Parser {
	switch path.Base(p) {
	case "package-lock.json", "npm-shrinkwrap.json":
		return &Parser{"package-lock.json", NPM, parseNPMLock}
	case "pnpm-lock.yaml":
		return &Parser{"pnpm-lock.yaml", NPM, parsePnpmLock}
	case "yarn.lock":
		return &Parser{"yarn.lock", NPM, parseYarnLock}
	case "bun.lock":
		return &Parser{"bun.lock", NPM, parseBunLock}
	case "Cargo.lock":
		return &Parser{"Cargo.lock", CratesIO, parseTOMLPackages("Cargo.lock", CratesIO)}
	case "uv.lock":
		return &Parser{"uv.lock", PyPI, parseTOMLPackages("uv.lock", PyPI)}
	case "poetry.lock":
		return &Parser{"poetry.lock", PyPI, parseTOMLPackages("poetry.lock", PyPI)}
	case "requirements.txt":
		return &Parser{"requirements.txt", PyPI, parseRequirementsTxt}
	case "go.mod":
		return &Parser{"go.mod", Go, parseGoMod}
	case "composer.lock":
		return &Parser{"composer.lock", Packagist, parseComposerLock}
	case "Gemfile.lock":
		return &Parser{"Gemfile.lock", RubyGems, parseGemfileLock}
	case "Pipfile.lock":
		return &Parser{"Pipfile.lock", PyPI, parsePipfileLock}
	case "mix.lock":
		return &Parser{"mix.lock", Hex, parseMixLock}
	case "pubspec.lock":
		return &Parser{"pubspec.lock", Pub, parsePubspecLock}
	case "gradle.lockfile":
		return &Parser{"gradle.lockfile", Maven, parseGradleLockfile}
	case "packages.lock.json":
		return &Parser{"packages.lock.json", NuGet, parseNuGetLock}
	case "Package.resolved":
		return &Parser{"Package.resolved", SwiftURL, parseSwiftResolved}
	case "Podfile.lock":
		return &Parser{"Podfile.lock", CocoaPods, parsePodfileLock}
	case "deno.lock":
		return &Parser{"deno.lock", NPM, parseDenoLock}
	case "flake.lock":
		return &Parser{"flake.lock", Nix, parseFlakeLock}
	}
	return nil
}

// KnownBasenames lists every lockfile filename lockvet understands.
func KnownBasenames() []string {
	return []string{
		"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
		"bun.lock", "Cargo.lock", "uv.lock", "poetry.lock", "requirements.txt",
		"go.mod", "composer.lock", "Gemfile.lock", "Pipfile.lock", "mix.lock",
		"pubspec.lock", "gradle.lockfile", "packages.lock.json", "Package.resolved",
		"Podfile.lock", "deno.lock", "flake.lock",
	}
}
