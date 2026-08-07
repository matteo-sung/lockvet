// Package lock parses dependency lockfiles into a common representation.
package lock

import (
	"net/url"
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

	// CRAN and Bioconductor cover R packages from renv.lock. A single
	// renv.lock mixes both; Bioconductor packages are marked per-package
	// via File.PkgEco.
	CRAN         Ecosystem = "CRAN"
	Bioconductor Ecosystem = "Bioconductor"

	// Nix has no OSV.dev ecosystem and no semver: flake inputs pin git
	// revisions. lockvet still explains what moved and by how much time.
	Nix Ecosystem = "Nix"

	// Conda covers pixi.lock and conda-lock.yml. Conda channels have no
	// OSV.dev ecosystem or deps.dev coverage, so conda packages get diff,
	// graph and version-jump treatment only; pip/pypi packages inside the
	// same lockfile are marked PyPI per-package (File.PkgEco) and get
	// full vulnerability, age and deprecation data.
	Conda Ecosystem = "conda"

	// Terraform providers (.terraform.lock.hcl, Terraform & OpenTofu)
	// and Helm charts (Chart.lock) have no OSV.dev ecosystem or deps.dev
	// coverage: changes are diffed, classified and explained without
	// vulnerability or age claims.
	Terraform Ecosystem = "Terraform"
	Helm      Ecosystem = "Helm"

	// Julia covers Manifest.toml (General registry packages and stdlibs;
	// OSV ecosystem "Julia"). Hackage covers stack.yaml.lock and
	// cabal.project.freeze/cabal.config (OSV ecosystem "Hackage").
	Julia   Ecosystem = "Julia"
	Hackage Ecosystem = "Hackage"

	// GitHubActions covers pkg:github purls in SBOMs (OSV ecosystem
	// "GitHub Actions").
	GitHubActions Ecosystem = "GitHub Actions"

	// Conan covers conan.lock (C/C++). "ConanCenter" is a valid OSV
	// ecosystem (currently near-empty — advisories will surface here
	// automatically if it fills in); deps.dev has no Conan system, so
	// internal/conanreg is the metadata layer for these lockfiles.
	Conan Ecosystem = "ConanCenter"

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
		NuGet, SwiftURL, GitHubActions, CRAN, Bioconductor, Julia, Hackage,
		Conan:
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

	// NonRegistry marks packages the lockfile itself says do NOT come
	// from the format's public registry: workspace members, path and
	// git dependencies, alternate indexes. Registry-metadata checks
	// (like the unlisted-version flag) skip them.
	NonRegistry map[string]bool

	// Pins records what the lockfile itself pins for a (package, version)
	// beyond the version string: the content hash it expects and the
	// registry host it resolves from. Filled only by formats that write
	// integrity hashes or resolution URLs (npm, pnpm, yarn, Cargo, uv,
	// poetry, Pipfile, requirements --hash, Gemfile.lock remotes).
	// name → version → meta.
	Pins map[string]map[string]PinMeta
}

// PinMeta is the integrity/resolution metadata a lockfile records for one
// pinned (package, version).
type PinMeta struct {
	// Integrity is a space-joined set of content hashes in whatever
	// notation the format uses ("sha512-…", "sha256:…", bare hex,
	// yarn-berry "10c0/…"). A set because Python lockfiles record one
	// hash per artifact (sdist + wheels) for the same version.
	Integrity string
	// Host is the registry/CDN host the package resolves from, e.g.
	// "registry.npmjs.org". Empty when the format doesn't record it.
	Host string
}

func newFile(p, kind string, eco Ecosystem) *File {
	return &File{Path: p, Kind: kind, Ecosystem: eco, Packages: map[string][]string{}}
}

// markNonRegistry records that a package does not come from the public
// registry (workspace member, path or git dependency, alternate index).
func (f *File) markNonRegistry(name string) {
	name = Sanitize(name)
	if name == "" {
		return
	}
	if f.NonRegistry == nil {
		f.NonRegistry = map[string]bool{}
	}
	f.NonRegistry[name] = true
}

// setPin records integrity/host metadata for a pinned (package, version).
// Integrity strings accumulate as a set (npm nesting can pin the same
// version at several paths; Python lockfiles hash every artifact); the
// first non-empty host wins.
func (f *File) setPin(name, version, integrity, host string) {
	name, version = Sanitize(name), Sanitize(version)
	integrity, host = Sanitize(integrity), Sanitize(host)
	if name == "" || version == "" || (integrity == "" && host == "") {
		return
	}
	if f.Pins == nil {
		f.Pins = map[string]map[string]PinMeta{}
	}
	m := f.Pins[name]
	if m == nil {
		m = map[string]PinMeta{}
		f.Pins[name] = m
	}
	pm := m[version]
	if integrity != "" {
		pm.Integrity = joinHashSet(pm.Integrity, integrity)
	}
	if host != "" && pm.Host == "" {
		pm.Host = host
	}
	m[version] = pm
}

// Pin returns the recorded integrity/host metadata for (name, version),
// or a zero PinMeta when the format records none.
func (f *File) Pin(name, version string) PinMeta {
	if f == nil || f.Pins == nil {
		return PinMeta{}
	}
	return f.Pins[name][version]
}

// joinHashSet appends hashes from add (space-separated fields) to set,
// skipping duplicates. Capped so a hostile file can't grow it unbounded.
func joinHashSet(set, add string) string {
	const maxHashes = 128
	have := strings.Fields(set)
	for _, h := range strings.Fields(add) {
		if len(have) >= maxHashes {
			break
		}
		dup := false
		for _, x := range have {
			if x == h {
				dup = true
				break
			}
		}
		if !dup {
			have = append(have, h)
		}
	}
	return strings.Join(have, " ")
}

// HostOf extracts the lowercase host from a URL string; "" when it can't.
func HostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// PublicRegistryHost reports whether the host is the ecosystem's canonical
// public registry (or its official CDN). Used to tell "resolution moved to
// the public registry" — the dependency-confusion direction — apart from
// ordinary mirror hops.
func (e Ecosystem) PublicRegistryHost(h string) bool {
	switch e {
	case NPM:
		return h == "registry.npmjs.org" || h == "registry.yarnpkg.com"
	case PyPI:
		return h == "pypi.org" || h == "files.pythonhosted.org" || h == "pypi.python.org"
	case CratesIO:
		return h == "crates.io" || h == "index.crates.io" || h == "static.crates.io"
	case RubyGems:
		return h == "rubygems.org" || h == "index.rubygems.org"
	case Pub:
		return h == "pub.dev" || h == "pub.dartlang.org"
	case Conda:
		return h == "conda.anaconda.org" || h == "repo.anaconda.com"
	}
	return false
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
// Both forward and backward slashes separate: forge and git paths always
// use "/", but file mode (`lockvet diff`, MCP vet_files) gets OS paths,
// and no supported lockfile basename contains a backslash.
func ByBasename(p string) *Parser {
	if i := strings.LastIndexByte(p, '\\'); i >= 0 {
		p = p[i+1:]
	}
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
	case "renv.lock":
		return &Parser{"renv.lock", CRAN, parseRenvLock}
	case "pixi.lock":
		return &Parser{"pixi.lock", Conda, parsePixiLock}
	case "conda-lock.yml", "conda-lock.yaml":
		return &Parser{"conda-lock.yml", Conda, parseCondaLock}
	case ".terraform.lock.hcl":
		return &Parser{".terraform.lock.hcl", Terraform, parseTerraformLock}
	case "Chart.lock":
		return &Parser{"Chart.lock", Helm, parseChartLock}
	case "requirements.lock":
		// Helm v2 chart lock, or pip-frozen requirements — sniffed.
		return &Parser{"requirements.lock", Helm, parseRequirementsLock}
	case "Manifest.toml":
		return &Parser{"Manifest.toml", Julia, sniffManifestTOML(true)}
	case "manifest.toml":
		// Gleam's lockfile; content-sniffed in case a Julia manifest was
		// lowercased somewhere along the way.
		return &Parser{"manifest.toml", Hex, sniffManifestTOML(false)}
	case "stack.yaml.lock":
		return &Parser{"stack.yaml.lock", Hackage, parseStackYamlLock}
	case "cabal.project.freeze", "cabal.config":
		return &Parser{"cabal.project.freeze", Hackage, parseCabalFreeze}
	case "conan.lock":
		return &Parser{"conan.lock", Conan, parseConanLock}
	}
	base := path.Base(p)
	// conda-lock supports named unified lockfiles (chipyard keeps
	// conda-reqs.conda-lock.yml, torchlens audio.pixi.lock, …).
	if strings.HasSuffix(base, ".pixi.lock") {
		return &Parser{"pixi.lock", Conda, parsePixiLock}
	}
	if strings.HasSuffix(base, ".conda-lock.yml") || strings.HasSuffix(base, ".conda-lock.yaml") {
		return &Parser{"conda-lock.yml", Conda, parseCondaLock}
	}
	// Suffix-named terraform locks exist too (cloudposse/atmos keeps
	// .plat-uw2-dev-kms-key.terraform.lock.hcl and friends).
	if strings.HasSuffix(base, ".terraform.lock.hcl") {
		return &Parser{".terraform.lock.hcl", Terraform, parseTerraformLock}
	}
	// Julia 1.10.8+ writes version-specific manifests (Manifest-v1.11.toml).
	if strings.HasPrefix(base, "Manifest-v") && strings.HasSuffix(base, ".toml") {
		return &Parser{"Manifest.toml", Julia, sniffManifestTOML(true)}
	}
	if isSBOMName(base) {
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
		"Podfile.lock", "deno.lock", "flake.lock", "renv.lock", "pixi.lock",
		"conda-lock.yml", ".terraform.lock.hcl", "Chart.lock",
		"requirements.lock", "Manifest.toml", "manifest.toml",
		"stack.yaml.lock", "cabal.project.freeze", "cabal.config",
		"conan.lock", "bom.json", "sbom.json",
	}
}
