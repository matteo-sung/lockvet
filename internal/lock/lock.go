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

	// GitHubActions covers pkg:github purls in SBOMs (OSV ecosystem
	// "GitHub Actions").
	GitHubActions Ecosystem = "GitHub Actions"

	// SBOMEco is the file-level ecosystem of an SBOM: a single CycloneDX
	// or SPDX document mixes ecosystems, so each package carries its own
	// (File.PkgEco) and this value is only a label / fallback.
	SBOMEco Ecosystem = "SBOM"
)

// HasOSV reports whether the ecosystem can be queried on OSV.dev.
// This is a whitelist: SBOMs introduce open-ended ecosystem strings
// (Linux distro packages, unknown purl types) and OSV rejects a whole
// batch when one query names an invalid ecosystem.
func (e Ecosystem) HasOSV() bool {
	switch e {
	case NPM, CratesIO, PyPI, Go, Packagist, RubyGems, Hex, Pub, Maven,
		NuGet, SwiftURL, GitHubActions:
		return true
	}
	// Release-qualified distro ecosystems derived from SBOM purl
	// qualifiers, e.g. "Alpine:v3.18", "Debian:12".
	s := string(e)
	return strings.HasPrefix(s, "Alpine:v") || strings.HasPrefix(s, "Debian:") || s == "Wolfi"
}

// HasSemver reports whether version-jump levels (major/minor/patch) are
// meaningful for the ecosystem. Nix pins git revisions; Debian/Ubuntu/RPM
// version strings carry epochs and distro revisions where semver labels
// would be noise.
func (e Ecosystem) HasSemver() bool {
	if e == Nix {
		return false
	}
	s := string(e)
	return !strings.HasPrefix(s, "Debian") && !strings.HasPrefix(s, "Ubuntu") && !strings.HasPrefix(s, "RPM")
}

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

	// PkgEco overrides the file-level Ecosystem per package. Only SBOMs
	// use it: one CycloneDX/SPDX document mixes npm, PyPI, distro
	// packages and more. nil for ordinary lockfiles.
	PkgEco map[string]Ecosystem
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
	if isSBOMName(path.Base(p)) {
		return &Parser{"sbom", SBOMEco, parseSBOM}
	}
	return nil
}

// isSBOMName reports whether a basename looks like a JSON SBOM. The parser
// sniffs the actual format (CycloneDX vs SPDX) from the content.
func isSBOMName(base string) bool {
	b := strings.ToLower(base)
	switch b {
	case "bom.json", "sbom.json", "cyclonedx.json", "spdx.json":
		return true
	}
	return strings.HasSuffix(b, ".cdx.json") ||
		strings.HasSuffix(b, ".spdx.json") ||
		strings.HasSuffix(b, ".cyclonedx.json")
}

// KnownBasenames lists every lockfile filename lockvet understands.
func KnownBasenames() []string {
	return []string{
		"package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
		"bun.lock", "Cargo.lock", "uv.lock", "poetry.lock", "requirements.txt",
		"go.mod", "composer.lock", "Gemfile.lock", "Pipfile.lock", "mix.lock",
		"pubspec.lock", "gradle.lockfile", "packages.lock.json", "Package.resolved",
		"Podfile.lock", "deno.lock", "flake.lock", "bom.json", "sbom.json",
	}
}
