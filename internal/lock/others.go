package lock

import (
	"encoding/json"
	"regexp"
	"strings"
)

// ---- TOML [[package]] blocks: Cargo.lock, uv.lock, poetry.lock ----
//
// All three formats pin packages as:
//   [[package]]
//   name = "foo"
//   version = "1.2.3"
// A full TOML parser is unnecessary for this shape.

var tomlKVRe = regexp.MustCompile(`^(name|version)\s*=\s*"([^"]*)"\s*$`)

// tomlNameRe matches uv.lock dep entries: { name = "requests" [, ...] }
var tomlNameRe = regexp.MustCompile(`name\s*=\s*"([^"]+)"`)

// tomlBareKeyRe matches poetry [package.dependencies] keys: foo = ">=1.0"
var tomlBareKeyRe = regexp.MustCompile(`^["']?([A-Za-z0-9._-]+)["']?\s*=`)

var (
	// Cargo.lock: checksum = "<64-hex sha256>"
	tomlChecksumRe = regexp.MustCompile(`^checksum\s*=\s*"([0-9a-f]{16,})"`)
	// artifact hashes inside inline tables (poetry files, uv sdist/wheels);
	// the boundary keeps poetry's lock-wide content-hash from matching
	tomlHashRe = regexp.MustCompile(`(?:^|[{,]\s*)hash\s*=\s*"([^"]+)"`)
	tomlURLRe  = regexp.MustCompile(`^url\s*=\s*"([^"]+)"`)
	tomlTypeRe = regexp.MustCompile(`^type\s*=\s*"([^"]+)"`)
	// uv: source = { registry = "https://pypi.org/simple" }
	tomlRegistryRe = regexp.MustCompile(`registry\s*=\s*"([^"]+)"`)
)

// tomlSourceHost extracts the registry host from a Cargo/uv source line.
// Cargo: source = "registry+https://github.com/rust-lang/crates.io-index"
// or "sparse+https://index.crates.io/" (both are crates.io);
// uv: source = { registry = "https://…" }.
func tomlSourceHost(line string) string {
	if strings.Contains(line, "github.com/rust-lang/crates.io-index") ||
		strings.Contains(line, "index.crates.io") {
		return "crates.io"
	}
	if m := tomlRegistryRe.FindStringSubmatch(line); m != nil {
		return HostOf(m[1])
	}
	v := line
	if i := strings.IndexByte(v, '"'); i >= 0 {
		v = strings.Trim(v[i:], `"`)
	}
	for _, pre := range []string{"registry+", "sparse+"} {
		if strings.HasPrefix(v, pre) {
			return HostOf(strings.TrimPrefix(v, pre))
		}
	}
	return ""
}

// tomlDepItem extracts the dependency name from one element of a
// `dependencies = [...]` array.
//
//	Cargo: "bar" or "bar 1.0.0 (registry+...)"
//	uv:    { name = "bar" },
//	pdm:   "bar>=1.2" / "bar[extra]==1.0; python_version < \"3.11\"" (PEP 508)
func tomlDepItem(item string) string {
	item = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(item), ","))
	if strings.HasPrefix(item, "{") {
		if m := tomlNameRe.FindStringSubmatch(item); m != nil {
			return m[1]
		}
		return ""
	}
	item = strings.Trim(item, `"`)
	// The name is the leading run of name characters; everything after the
	// first space (Cargo "bar 1.0.0 (...)"), extras bracket, version
	// specifier or environment marker (PEP 508) is not part of it.
	for i := 0; i < len(item); i++ {
		c := item[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}
		item = item[:i]
		break
	}
	return item
}

func parseTOMLPackages(kind string, eco Ecosystem) func(string, []byte) (*File, error) {
	return func(p string, data []byte) (*File, error) {
		f := newFile(p, kind, eco)
		var name, version string
		var deps []string
		var pinHash, pinHost string
		var srcType, srcURL string
		hasSource, rootSource, nonRegistry := false, false, false
		inPackage, inSourceTable := false, false
		mode := "" // "", "deps-array", "poetry-deps"
		flush := func() {
			if inPackage {
				f.add(name, version)
				// poetry: no [package.source] table means "from PyPI";
				// only "legacy" sources (alternate indexes) have a host
				// worth recording — git/path/url sources do not resolve
				// from a registry at all.
				if kind == "poetry.lock" && !nonRegistry && pinHost == "" {
					pinHost = "pypi.org"
				}
				if srcType == "legacy" && srcURL != "" {
					pinHost = HostOf(srcURL)
				}
				if pinHash != "" || pinHost != "" {
					f.setPin(name, version, pinHash, pinHost)
				}
				// Packages that don't come from the public registry:
				// Cargo.lock: no `source` = workspace member / path dep,
				// source = "git+..." = git dep. uv.lock / poetry.lock:
				// explicit git/path/directory/url/editable sources and
				// alternate indexes (marked while scanning lines).
				if nonRegistry || (kind == "Cargo.lock" && !hasSource) {
					f.markNonRegistry(name)
				}
				// Which packages count as the project root differs:
				// Cargo.lock: workspace members have no `source` key.
				// uv.lock: the project has source = { editable/virtual = "." }.
				// poetry.lock: the root is not recorded at all.
				isRoot := (kind == "Cargo.lock" && !hasSource) ||
					(kind == "uv.lock" && rootSource)
				for _, d := range deps {
					if isRoot {
						f.addRoot(d)
					} else if name != "" {
						f.addEdge(name, d)
					}
				}
			}
			name, version, deps = "", "", nil
			pinHash, pinHost, srcType, srcURL = "", "", "", ""
			hasSource, rootSource, nonRegistry = false, false, false
			inSourceTable = false
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			switch mode {
			case "deps-array":
				if line == "]" {
					mode = ""
					continue
				}
				if d := tomlDepItem(line); d != "" {
					deps = append(deps, d)
				}
				continue
			case "poetry-deps":
				if strings.HasPrefix(line, "[") {
					mode = "" // fall through to table handling below
				} else {
					if m := tomlBareKeyRe.FindStringSubmatch(line); m != nil {
						deps = append(deps, m[1])
					}
					continue
				}
			}
			if strings.HasPrefix(line, "[") { // new table/array-of-tables
				switch {
				case line == "[[package]]":
					flush()
					inPackage = true
				case strings.HasPrefix(line, "[package."):
					// sub-table of the current package: keep context
					if inPackage && line == "[package.dependencies]" {
						mode = "poetry-deps"
					}
					inSourceTable = inPackage && line == "[package.source]"
					if inSourceTable {
						// poetry: PyPI packages carry no source table at
						// all; git/directory/file/url/legacy all do.
						nonRegistry = true
					}
				default:
					flush()
					inPackage = false
				}
				continue
			}
			if !inPackage {
				continue
			}
			if m := tomlKVRe.FindStringSubmatch(line); m != nil {
				if m[1] == "name" {
					name = m[2]
				} else {
					version = m[2]
				}
				continue
			}
			if m := tomlChecksumRe.FindStringSubmatch(line); m != nil { // Cargo
				pinHash = m[1]
				continue
			}
			// Artifact hashes: poetry files = [{file=…, hash="sha256:…"}],
			// uv sdist = {…, hash = "sha256:…"} / wheels = [{…}].
			for _, m := range tomlHashRe.FindAllStringSubmatch(line, -1) {
				pinHash = joinHashSet(pinHash, m[1])
			}
			if inSourceTable { // poetry [package.source]: type/url/reference
				if m := tomlURLRe.FindStringSubmatch(line); m != nil {
					srcURL = m[1]
				}
				if m := tomlTypeRe.FindStringSubmatch(line); m != nil {
					srcType = m[1]
				}
				continue
			}
			// pdm.lock records non-registry candidates with package-level
			// keys: git/hg/svn (VCS), path (local), url (direct URL).
			// `files = [` entry lines all start with "{", so these
			// prefixes only match genuine package-level keys.
			if kind == "pdm.lock" && (strings.HasPrefix(line, "git =") ||
				strings.HasPrefix(line, "hg =") || strings.HasPrefix(line, "svn =") ||
				strings.HasPrefix(line, "path =") || strings.HasPrefix(line, "url =") ||
				strings.HasPrefix(line, "editable =")) {
				nonRegistry = true
				continue
			}
			if strings.HasPrefix(line, "source =") {
				hasSource = true
				if strings.Contains(line, "editable") || strings.Contains(line, "virtual") {
					rootSource = true
				}
				if strings.Contains(line, "git+") || strings.Contains(line, "git =") ||
					strings.Contains(line, "path =") || strings.Contains(line, "directory =") ||
					strings.Contains(line, "url =") || rootSource {
					nonRegistry = true // not the format's public registry
				} else if h := tomlSourceHost(line); h != "" {
					pinHost = h // registry source: record the index host
				}
				continue
			}
			if strings.HasPrefix(line, "dependencies = [") {
				rest := strings.TrimPrefix(line, "dependencies = [")
				if i := strings.LastIndexByte(rest, ']'); i >= 0 { // inline array
					for _, item := range splitTopLevel(rest[:i]) {
						if d := tomlDepItem(item); d != "" {
							deps = append(deps, d)
						}
					}
				} else {
					mode = "deps-array"
				}
			}
		}
		flush()
		return f, nil
	}
}

// splitTopLevel splits an inline TOML array body on commas that are not
// inside braces or quotes: `"a", { name = "b", extra = ["c"] }`.
func splitTopLevel(s string) []string {
	var out []string
	depth, start, inStr := 0, 0, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inStr = !inStr
		case '{', '[':
			if !inStr {
				depth++
			}
		case '}', ']':
			if !inStr {
				depth--
			}
		case ',':
			if !inStr && depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// ---- requirements.txt (only exact `==` pins) ----

var reqLineRe = regexp.MustCompile(`^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+*_-]+)`)

var reqHashRe = regexp.MustCompile(`--hash[= ]([A-Za-z0-9:._-]+)`)

func parseRequirementsTxt(p string, data []byte) (*File, error) {
	f := newFile(p, "requirements.txt", PyPI)
	lastName, lastVer := "", ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "-") {
			// pip-compile puts --hash options on continuation lines under
			// the pin they belong to.
			if lastName != "" {
				for _, m := range reqHashRe.FindAllStringSubmatch(line, -1) {
					f.setPin(lastName, lastVer, m[1], "")
				}
			}
			continue
		}
		var hashes []string
		for _, m := range reqHashRe.FindAllStringSubmatch(line, -1) {
			hashes = append(hashes, m[1])
		}
		if i := strings.IndexByte(line, ';'); i >= 0 { // env markers
			line = strings.TrimSpace(line[:i])
		}
		if m := reqLineRe.FindStringSubmatch(line); m != nil {
			lastName, lastVer = normalizePyPI(m[1]), m[2]
			f.add(lastName, lastVer)
			for _, h := range hashes {
				f.setPin(lastName, lastVer, h, "")
			}
		} else {
			lastName, lastVer = "", ""
		}
	}
	return f, nil
}

// normalizePyPI lowercases and collapses ._- to - per PEP 503.
var pypiSepRe = regexp.MustCompile(`[-_.]+`)

func normalizePyPI(name string) string {
	return pypiSepRe.ReplaceAllString(strings.ToLower(name), "-")
}

// ---- go.mod ----

func parseGoMod(p string, data []byte) (*File, error) {
	f := newFile(p, "go.mod", Go)
	f.RootsKnown = true // go.mod annotates transitive deps with "// indirect"
	inRequire, inReplace := false, false
	for _, line := range strings.Split(string(data), "\n") {
		indirect := false
		if i := strings.Index(line, "//"); i >= 0 {
			indirect = strings.Contains(line[i:], "indirect")
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "require (":
			inRequire = true
			continue
		case inRequire && line == ")":
			inRequire = false
			continue
		case line == "replace (":
			inReplace = true
			continue
		case inReplace && line == ")":
			inReplace = false
			continue
		}
		fields := strings.Fields(line)
		// A replaced module doesn't build from the registry: the required
		// version is overridden by a local path or another module, so
		// registry- and advisory-derived claims about it would be wrong
		// (monorepos require workspace siblings at v0.0.0 + replace).
		if inReplace && len(fields) >= 3 {
			f.markNonRegistry(fields[0])
			continue
		}
		if len(fields) >= 4 && fields[0] == "replace" {
			f.markNonRegistry(fields[1])
			continue
		}
		if inRequire && len(fields) == 2 {
			f.add(fields[0], strings.TrimPrefix(fields[1], "v"))
			if !indirect {
				f.addRoot(fields[0])
			}
		} else if len(fields) == 3 && fields[0] == "require" {
			f.add(fields[1], strings.TrimPrefix(fields[2], "v"))
			if !indirect {
				f.addRoot(fields[1])
			}
		}
	}
	return f, nil
}

// ---- go.sum ----
//
// go.sum is not the dependency list (go.mod is): it is the module cache's
// ledger — one "module version h1:hash" line for every module zip the build
// may verify, plus a "module version/go.mod h1:hash" line for its manifest.
// Version churn is go.mod's story, and repeating it here would double every
// bump row; what go.sum ADDS is the hashes, and a released version's hash
// never changes legitimately (the h1 dirhash is deterministic over the
// module's contents). A same-version hash edit means the module's bytes no
// longer match what every earlier build verified — the poisoned-go.sum
// shape: a tampered module only installs if go.sum is edited to agree, and
// for private modules (GONOSUMDB/GOPRIVATE) no checksum database will ever
// object. So the file parses as pins-only: only repins become rows.
func parseGoSum(p string, data []byte) (*File, error) {
	f := newFile(p, "go.sum", Go)
	f.PinsOnly = true
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(strings.TrimRight(line, "\r"))
		if len(fields) != 3 || !strings.HasPrefix(fields[1], "v") ||
			!strings.HasPrefix(fields[2], "h1:") {
			continue
		}
		name, ver := fields[0], fields[1]
		hash := fields[2]
		if strings.HasSuffix(ver, "/go.mod") {
			// The manifest's own hash, artifact-scoped so a zip hash and
			// a go.mod hash are each compared against their own kind.
			ver = strings.TrimSuffix(ver, "/go.mod")
			hash = "go.mod#" + hash
		}
		ver = strings.TrimPrefix(ver, "v")
		f.add(name, ver)
		f.setPin(name, ver, hash, "")
	}
	return f, nil
}

// ---- composer.lock ----

func parseComposerLock(p string, data []byte) (*File, error) {
	f := newFile(p, "composer.lock", Packagist)
	type composerPkg struct {
		Name    string            `json:"name"`
		Version string            `json:"version"`
		Require map[string]string `json:"require"`
		// Composer writes notification-url for every package installed
		// from Packagist; VCS/path repository pins lack it (or point at
		// a private registry). Their versions may not exist on
		// packagist.org at all, so registry-derived signals must skip
		// them.
		NotificationURL string `json:"notification-url"`
		Dist            struct {
			Reference string `json:"reference"`
		} `json:"dist"`
	}
	var doc struct {
		Packages    []composerPkg `json:"packages"`
		PackagesDev []composerPkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	for _, pkg := range append(doc.Packages, doc.PackagesDev...) {
		ver := strings.TrimPrefix(pkg.Version, "v")
		f.add(pkg.Name, ver)
		if !strings.HasPrefix(pkg.NotificationURL, "https://packagist.org/") {
			f.markNonRegistry(pkg.Name)
		}
		// dist.reference is the commit the released tag pointed at when it
		// was resolved. Tagged releases are supposed to be immutable, so a
		// same-version reference change means the upstream tag was moved.
		// Branch pins (dev-main, 1.x-dev, 9999999-dev aliases) legitimately
		// track moving heads and are never recorded.
		if ref := strings.ToLower(pkg.Dist.Reference); len(ref) == 40 &&
			!strings.HasPrefix(pkg.Version, "dev-") &&
			!strings.HasSuffix(pkg.Version, "-dev") {
			f.setPin(pkg.Name, ver, "commit:"+ref, "")
		}
		for dep := range pkg.Require {
			// skip platform requirements: php, ext-*, lib-*, composer-*
			if !strings.Contains(dep, "/") {
				continue
			}
			f.addEdge(pkg.Name, dep)
		}
	}
	return f, nil
}

// ---- Gemfile.lock ----

var (
	gemSpecRe = regexp.MustCompile(`^    ([A-Za-z0-9._-]+) \(([0-9][^)]*)\)\s*$`)
	gemDepRe  = regexp.MustCompile(`^      ([A-Za-z0-9._-]+)(?: \([^)]*\))?\s*$`)
	gemRootRe = regexp.MustCompile(`^  ([A-Za-z0-9._-]+)(?:!)?(?: \([^)]*\))?!?\s*$`)
	// Bundler ≥ 2.6 CHECKSUMS entries: "  name (version) sha256=hex".
	// Entries recorded without a checksum ("  name (version)") stay
	// unmatched on purpose — an absent hash proves nothing.
	gemChecksumRe = regexp.MustCompile(`^  ([A-Za-z0-9._-]+) \(([0-9][^)]*)\) ([a-z0-9]{1,8})=([A-Za-z0-9+/=_-]+)\s*$`)
)

func parseGemfileLock(p string, data []byte) (*File, error) {
	f := newFile(p, "Gemfile.lock", RubyGems)
	inSpecs, inDependencies := false, false
	// Specs under GIT / PATH / PLUGIN SOURCE sections come from a
	// repository or the local disk, not rubygems.org — their versions
	// (a pinned fork, an unreleased bump) may not exist on the registry
	// at all, so registry-derived signals must skip them.
	nonRegistrySection := false
	inChecksums := false
	currentSpec, remoteHost := "", ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.TrimSpace(line) == "specs:":
			inSpecs = true
			continue
		case line == "DEPENDENCIES":
			inSpecs, inDependencies, inChecksums = false, true, false
			continue
		case line != "" && line[0] != ' ': // new top-level section (GEM, PLATFORMS, ...)
			inSpecs, inDependencies = false, false
			inChecksums = line == "CHECKSUMS"
			nonRegistrySection = line != "GEM"
			remoteHost = ""
			continue
		case !inSpecs && strings.HasPrefix(strings.TrimSpace(line), "remote: "):
			if !nonRegistrySection {
				remoteHost = HostOf(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "remote:")))
			}
			continue
		}
		if inChecksums {
			// Bundler ≥ 2.6 records the sha256 of every gem it installed
			// from a registry, per exact version string — platform gems
			// ("1.16.0-x86_64-linux") keep their own line and so their
			// own hash. Same keys as the GEM specs above, so the pins
			// machinery lines them up without translation.
			if m := gemChecksumRe.FindStringSubmatch(line); m != nil {
				f.setPin(m[1], m[2], m[3]+":"+m[4], "")
			}
			continue
		}
		if inDependencies {
			// two-space entries list the Gemfile's direct dependencies
			if m := gemRootRe.FindStringSubmatch(line); m != nil {
				f.addRoot(strings.TrimSuffix(m[1], "!"))
			}
			continue
		}
		if !inSpecs {
			continue
		}
		if m := gemSpecRe.FindStringSubmatch(line); m != nil {
			f.add(m[1], m[2])
			if nonRegistrySection {
				f.markNonRegistry(m[1])
			} else if remoteHost != "" {
				f.setPin(m[1], m[2], "", remoteHost)
			}
			currentSpec = m[1]
			continue
		}
		if m := gemDepRe.FindStringSubmatch(line); m != nil && currentSpec != "" {
			f.addEdge(currentSpec, m[1])
		}
	}
	return f, nil
}
