package lock

import (
	"regexp"
	"strings"
)

// ---- Manifest.toml (Julia) ----
//
// Julia's package manager pins the full environment in Manifest.toml.
// Format 2.0 (Julia >= 1.7) keeps one array-of-tables entry per package:
//
//	[[deps.CodecZlib]]
//	deps = ["TranscodingStreams", "Zlib_jll"]
//	git-tree-sha1 = "..."
//	uuid = "944b1d66-..."
//	version = "0.7.8"
//
// with optional weakdeps/extensions sub-tables ([deps.X.extensions]).
// Format 1.0 (Julia <= 1.6) uses top-level [[CodecZlib]] entries with the
// same keys. Julia 1.10.8+ also writes version-suffixed manifests
// (Manifest-v1.11.toml). Standard-library entries carry versions too and
// are kept; entries without a version (old-format stdlibs) are dropped.
// The deps arrays give a real dependency graph -> via-chains; the roots
// live in Project.toml, which is not a lockfile, so RootsKnown is false.

var juliaHeadRe = regexp.MustCompile(`^\[\[(?:deps\.)?"?([A-Za-z0-9_]+)"?\]\]$`)
var juliaTreeRe = regexp.MustCompile(`^git-tree-sha1\s*=\s*"([^"]+)"\s*$`)

func parseJuliaManifest(p string, data []byte) (*File, error) {
	f := newFile(p, "Manifest.toml", Julia)
	type entry struct {
		name    string
		version string
		treeSHA string
		repoURL bool // tracked from a git repo, not the registry
		deps    []string
	}
	var entries []entry
	var cur *entry
	inDeps := false // inside a multi-line deps = [ ... ] array
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if inDeps {
			if line == "]" {
				inDeps = false
				continue
			}
			if cur != nil {
				if d := tomlDepItem(line); d != "" {
					cur.deps = append(cur.deps, d)
				}
			}
			continue
		}
		if m := juliaHeadRe.FindStringSubmatch(line); m != nil {
			entries = append(entries, entry{name: m[1]})
			cur = &entries[len(entries)-1]
			continue
		}
		if strings.HasPrefix(line, "[") {
			// [deps.X.extensions] / [X.weakdeps] sub-tables: keys below
			// belong to the sub-table, not the package.
			cur = nil
			continue
		}
		if cur == nil {
			continue
		}
		if m := tomlKVRe.FindStringSubmatch(line); m != nil && m[1] == "version" {
			cur.version = m[2]
			continue
		}
		if m := juliaTreeRe.FindStringSubmatch(line); m != nil {
			cur.treeSHA = strings.ToLower(m[1])
			continue
		}
		if strings.HasPrefix(line, "repo-url ") || strings.HasPrefix(line, "repo-url=") {
			cur.repoURL = true
			continue
		}
		if rest, ok := strings.CutPrefix(line, "deps = ["); ok {
			rest = strings.TrimSpace(rest)
			if rest == "" {
				inDeps = true
				continue
			}
			rest = strings.TrimSuffix(rest, "]")
			for _, item := range strings.Split(rest, ",") {
				if d := tomlDepItem(item); d != "" {
					cur.deps = append(cur.deps, d)
				}
			}
		}
	}
	locked := map[string]bool{}
	for _, e := range entries {
		if e.version == "" {
			continue
		}
		f.add(e.name, e.version)
		locked[e.name] = true
		// git-tree-sha1 identifies the exact source tree the registry
		// maps to this version; registered versions are immutable. Pins
		// tracking a git repo (repo-url) legitimately move — skipped,
		// and marked non-registry so a registry→git switch at the same
		// version reads as the routine fork-pin flow it is (matching
		// pubspec.lock) rather than an integrity-removed alarm.
		if e.repoURL {
			f.markNonRegistry(e.name)
		}
		if e.treeSHA != "" && !e.repoURL {
			f.setPin(e.name, e.version, "tree:"+e.treeSHA, "")
		}
	}
	for _, e := range entries {
		if !locked[e.name] {
			continue
		}
		for _, d := range e.deps {
			if locked[d] {
				f.addEdge(e.name, d)
			}
		}
	}
	return f, nil
}

// ---- stack.yaml.lock (Haskell) ----
//
// Stack locks the resolved extra-deps as YAML:
//
//	packages:
//	- completed:
//	    hackage: crypton-1.1.4@sha256:...,15142
//	  original:
//	    hackage: crypton-1.1.4@sha256:...,15142
//
// Every pinned Hackage package appears on a "hackage:" line as
// name-version@sha256:...,size. Hackage package-name components must
// contain a letter, so the last '-' followed by digits+dots is always
// the version split. git/github extra-deps have no hackage line and are
// skipped. Only extra-deps are listed (the snapshot's packages are not),
// so the file explains what the project pins on top of its resolver.
func parseStackYamlLock(p string, data []byte) (*File, error) {
	f := newFile(p, "stack.yaml.lock", Hackage)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		val, ok := strings.CutPrefix(line, "hackage:")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		if i := strings.IndexByte(val, '@'); i >= 0 {
			val = val[:i]
		}
		if name, ver, ok := cutHackageVersion(val); ok {
			f.add(name, ver)
		}
	}
	return f, nil
}

// cutHackageVersion splits "unordered-containers-0.2.19.1" into name and
// version at the last dash whose suffix is all digits and dots.
func cutHackageVersion(s string) (name, ver string, ok bool) {
	i := strings.LastIndexByte(s, '-')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	name, ver = s[:i], s[i+1:]
	if !versionLike(ver) {
		return "", "", false
	}
	return name, ver, true
}

func versionLike(s string) bool {
	if s == "" || s[0] < '0' || s[0] > '9' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// ---- cabal.project.freeze / cabal.config (Haskell) ----
//
// `cabal freeze` writes exact-version constraints for the whole build
// plan:
//
//	constraints: any.aeson ==2.1.2.1,
//	             any.text -simdutf,
//	             any.base ==4.18.2.0
//
// Stackage's downloadable cabal.config uses the same constraint syntax
// without the "any." prefix. Flag constraints (+flag/-flag) and
// "installed" constraints carry no version and are skipped.
var cabalConstraintRe = regexp.MustCompile(`^(?:any\.)?([A-Za-z][A-Za-z0-9-]*)\s*==\s*([0-9][0-9.]*)$`)

func parseCabalFreeze(p string, data []byte) (*File, error) {
	f := newFile(p, "cabal.project.freeze", Hackage)
	content := strings.ReplaceAll(string(data), "\n", ",")
	for _, tok := range strings.Split(content, ",") {
		tok = strings.TrimSpace(tok)
		if rest, ok := strings.CutPrefix(tok, "constraints:"); ok {
			tok = strings.TrimSpace(rest)
		}
		if m := cabalConstraintRe.FindStringSubmatch(tok); m != nil {
			f.add(m[1], m[2])
		}
	}
	return f, nil
}

// ---- manifest.toml (Gleam) ----
//
// Gleam locks resolved packages (mostly from Hex) in manifest.toml:
//
//	packages = [
//	  { name = "gleam_stdlib", version = "0.38.0", build_tools = ["gleam"],
//	    requirements = [], otp_app = "gleam_stdlib", source = "hex",
//	    outer_checksum = "..." },
//	]
//	[requirements]
//	gleam_stdlib = { version = ">= 0.34.0 and < 2.0.0" }
//
// Per-package requirements arrays give the dependency graph; the
// [requirements] table names the project's direct dependencies (roots).
// Hex is the OSV ecosystem — same as mix.lock.
var gleamReqArrayRe = regexp.MustCompile(`requirements\s*=\s*\[([^\]]*)\]`)

func parseGleamManifest(p string, data []byte) (*File, error) {
	f := newFile(p, "manifest.toml", Hex)
	inReqTable := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inReqTable = line == "[requirements]"
			continue
		}
		if inReqTable {
			if m := tomlBareKeyRe.FindStringSubmatch(line); m != nil {
				f.addRoot(m[1])
			}
			continue
		}
		if !strings.Contains(line, "name =") {
			continue
		}
		var name, version string
		if m := tomlNameRe.FindStringSubmatch(line); m != nil {
			name = m[1]
		}
		if m := gleamVersionRe.FindStringSubmatch(line); m != nil {
			version = m[1]
		}
		if name == "" || version == "" {
			continue
		}
		f.add(name, version)
		// Gleam can also resolve packages from git or a local path;
		// those never appear on hex.pm and must not trip registry
		// signals.
		fromHex := true
		if m := gleamSourceRe.FindStringSubmatch(line); m != nil && m[1] != "hex" {
			f.markNonRegistry(name)
			fromHex = false
		}
		// outer_checksum = sha256 of the hex.pm tarball; immutable per
		// version.
		if m := gleamChecksumRe.FindStringSubmatch(line); m != nil && fromHex {
			f.setPin(name, version, "sha256:"+strings.ToLower(m[1]), "")
		}
		if m := gleamReqArrayRe.FindStringSubmatch(line); m != nil {
			for _, item := range strings.Split(m[1], ",") {
				if d := strings.Trim(strings.TrimSpace(item), `"`); d != "" {
					f.addEdge(name, d)
				}
			}
		}
	}
	return f, nil
}

var gleamVersionRe = regexp.MustCompile(`version\s*=\s*"([^"]+)"`)
var gleamSourceRe = regexp.MustCompile(`source\s*=\s*"([^"]+)"`)
var gleamChecksumRe = regexp.MustCompile(`outer_checksum\s*=\s*"([^"]+)"`)

// sniffManifestTOML routes the ambiguous basename: Julia writes
// Manifest.toml (and historically some tooling lowercases it), Gleam
// writes manifest.toml. The two shapes are trivially distinguishable.
func sniffManifestTOML(preferJulia bool) func(string, []byte) (*File, error) {
	return func(p string, data []byte) (*File, error) {
		s := string(data)
		isJulia := strings.Contains(s, "manifest_format") ||
			strings.Contains(s, "[[deps.") ||
			strings.Contains(s, "git-tree-sha1")
		isGleam := strings.Contains(s, "packages = [")
		switch {
		case isJulia:
			return parseJuliaManifest(p, data)
		case isGleam:
			return parseGleamManifest(p, data)
		case preferJulia:
			return parseJuliaManifest(p, data)
		}
		return parseGleamManifest(p, data)
	}
}
