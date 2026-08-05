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

// tomlDepItem extracts the dependency name from one element of a
// `dependencies = [...]` array.
//
//	Cargo: "bar" or "bar 1.0.0 (registry+...)"
//	uv:    { name = "bar" },
func tomlDepItem(item string) string {
	item = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(item), ","))
	if strings.HasPrefix(item, "{") {
		if m := tomlNameRe.FindStringSubmatch(item); m != nil {
			return m[1]
		}
		return ""
	}
	item = strings.Trim(item, `"`)
	if i := strings.IndexByte(item, ' '); i > 0 { // "bar 1.0.0 (...)"
		item = item[:i]
	}
	return item
}

func parseTOMLPackages(kind string, eco Ecosystem) func(string, []byte) (*File, error) {
	return func(p string, data []byte) (*File, error) {
		f := newFile(p, kind, eco)
		var name, version string
		var deps []string
		hasSource, rootSource, nonRegistry := false, false, false
		inPackage := false
		mode := "" // "", "deps-array", "poetry-deps"
		flush := func() {
			if inPackage {
				f.add(name, version)
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
			hasSource, rootSource, nonRegistry = false, false, false
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
					if inPackage && line == "[package.source]" {
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
			if strings.HasPrefix(line, "source =") {
				hasSource = true
				if strings.Contains(line, "editable") || strings.Contains(line, "virtual") {
					rootSource = true
				}
				if strings.Contains(line, "git+") || strings.Contains(line, "git =") ||
					strings.Contains(line, "path =") || strings.Contains(line, "directory =") ||
					strings.Contains(line, "url =") || rootSource {
					nonRegistry = true // not the format's public registry
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

func parseRequirementsTxt(p string, data []byte) (*File, error) {
	f := newFile(p, "requirements.txt", PyPI)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.IndexByte(line, ';'); i >= 0 { // env markers
			line = strings.TrimSpace(line[:i])
		}
		if m := reqLineRe.FindStringSubmatch(line); m != nil {
			f.add(normalizePyPI(m[1]), m[2])
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
	}
	var doc struct {
		Packages    []composerPkg `json:"packages"`
		PackagesDev []composerPkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	for _, pkg := range append(doc.Packages, doc.PackagesDev...) {
		f.add(pkg.Name, strings.TrimPrefix(pkg.Version, "v"))
		if !strings.HasPrefix(pkg.NotificationURL, "https://packagist.org/") {
			f.markNonRegistry(pkg.Name)
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
)

func parseGemfileLock(p string, data []byte) (*File, error) {
	f := newFile(p, "Gemfile.lock", RubyGems)
	inSpecs, inDependencies := false, false
	// Specs under GIT / PATH / PLUGIN SOURCE sections come from a
	// repository or the local disk, not rubygems.org — their versions
	// (a pinned fork, an unreleased bump) may not exist on the registry
	// at all, so registry-derived signals must skip them.
	nonRegistrySection := false
	currentSpec := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.TrimSpace(line) == "specs:":
			inSpecs = true
			continue
		case line == "DEPENDENCIES":
			inSpecs, inDependencies = false, true
			continue
		case line != "" && line[0] != ' ': // new top-level section (GEM, PLATFORMS, ...)
			inSpecs, inDependencies = false, false
			nonRegistrySection = line != "GEM"
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
