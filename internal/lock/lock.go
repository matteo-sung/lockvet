// Package lock parses dependency lockfiles into a common representation.
package lock

import (
	"path"
	"sort"
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
)

// File is a parsed lockfile: package name -> set of pinned versions.
// A lockfile may legitimately contain multiple versions of one package
// (npm nesting, cargo duplicate majors), hence the set.
type File struct {
	Path      string
	Kind      string // e.g. "package-lock.json"
	Ecosystem Ecosystem
	Packages  map[string][]string
}

func newFile(p, kind string, eco Ecosystem) *File {
	return &File{Path: p, Kind: kind, Ecosystem: eco, Packages: map[string][]string{}}
}

func (f *File) add(name, version string) {
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
	}
	return nil
}

// KnownBasenames lists every lockfile filename lockvet understands.
func KnownBasenames() []string {
	return []string{
		"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
		"bun.lock", "Cargo.lock", "uv.lock", "poetry.lock", "requirements.txt",
		"go.mod", "composer.lock", "Gemfile.lock",
	}
}
