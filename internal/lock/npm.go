package lock

import (
	"encoding/json"
	"regexp"
	"strings"
)

// ---- package-lock.json / npm-shrinkwrap.json (v1, v2, v3) ----

func parseNPMLock(p string, data []byte) (*File, error) {
	f := newFile(p, "package-lock.json", NPM)
	var doc struct {
		Packages map[string]struct {
			Name                 string            `json:"name"`
			Version              string            `json:"version"`
			Link                 bool              `json:"link"`
			Resolved             string            `json:"resolved"`
			Integrity            string            `json:"integrity"`
			Dependencies         map[string]string `json:"dependencies"`
			DevDependencies      map[string]string `json:"devDependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
		} `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Packages) > 0 { // lockfile v2/v3
		for key, pkg := range doc.Packages {
			if key == "" || !strings.Contains(key, "node_modules/") {
				// Root project or a workspace member: its declared deps
				// are the *direct* dependencies.
				for dep := range pkg.Dependencies {
					f.addRoot(dep)
				}
				for dep := range pkg.DevDependencies {
					f.addRoot(dep)
				}
				for dep := range pkg.OptionalDependencies {
					f.addRoot(dep)
				}
				if key == "" {
					continue
				}
			}
			if pkg.Link || pkg.Version == "" {
				continue
			}
			name := key
			if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
				name = key[i+len("node_modules/"):]
			} else {
				continue // workspace member itself, not an installed package
			}
			f.add(name, pkg.Version)
			if pkg.Name != "" && pkg.Name != name {
				// An aliased install ("react-loadable": "npm:@docusaurus/
				// react-loadable@^5.5.2"): the entry's name field records
				// the REAL package. Registry claims under the alias name
				// would be wrong (yarn alias precedent).
				f.markNonRegistry(name)
			}
			if strings.HasPrefix(pkg.Resolved, "git") || strings.HasPrefix(pkg.Resolved, "file:") {
				f.markNonRegistry(name) // git or local-path dependency
			} else {
				f.setPin(name, pkg.Version, pkg.Integrity, HostOf(pkg.Resolved))
			}
			for dep := range pkg.Dependencies {
				f.addEdge(name, dep)
			}
			for dep := range pkg.OptionalDependencies {
				f.addEdge(name, dep)
			}
		}
		return f, nil
	}
	// lockfile v1: nested "dependencies" tree ("requires" records edges)
	var walk func(deps map[string]json.RawMessage)
	walk = func(deps map[string]json.RawMessage) {
		for name, raw := range deps {
			var e struct {
				Version      string                     `json:"version"`
				Resolved     string                     `json:"resolved"`
				Integrity    string                     `json:"integrity"`
				Requires     map[string]string          `json:"requires"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(raw, &e) == nil {
				f.add(name, e.Version)
				if !strings.HasPrefix(e.Resolved, "git") && !strings.HasPrefix(e.Resolved, "file:") {
					f.setPin(name, e.Version, e.Integrity, HostOf(e.Resolved))
				}
				for dep := range e.Requires {
					f.addEdge(name, dep)
				}
				if len(e.Dependencies) > 0 {
					walk(e.Dependencies)
				}
			}
		}
	}
	walk(doc.Dependencies)
	return f, nil
}

// ---- pnpm-lock.yaml (v5.x through v9+) ----
//
// We only need the keys of the `packages:` section, which look like:
//
//	v5/v6:  /@scope/name@1.2.3(peer@x):   or   /name/1.2.3:
//	v9:     '@scope/name@1.2.3':          or   name@1.2.3:
var pnpmKeyRe = regexp.MustCompile(`^  ['"]?(/?[^:'"]+)['"]?:\s*$`)

var (
	pnpmIntegrityRe = regexp.MustCompile(`integrity:\s*['"]?([A-Za-z0-9+/=_-]+)`)
	pnpmTarballRe   = regexp.MustCompile(`tarball:\s*['"]?([^'",}\s]+)`)
)

// pnpmPkgName extracts the package name from a packages:/snapshots: entry key
// like "/@scope/name@1.2.3(peer@x)", "/name/1.2.3" or "name@1.2.3".
func pnpmPkgName(key string) (name, version string) {
	key = strings.TrimPrefix(key, "/")
	if i := strings.IndexByte(key, '('); i >= 0 { // strip peer suffixes
		key = key[:i]
	}
	name, version = splitNameAtVersion(key)
	if name == "" { // old style: /name/1.2.3
		if i := strings.LastIndexByte(key, '/'); i > 0 && !strings.Contains(key[i+1:], "@") {
			name, version = key[:i], key[i+1:]
		}
	}
	return name, version
}

func pnpmIndent(line string) int {
	n := 0
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n
}

// pnpmMapKey extracts "name" from a YAML map key line like
// "      name: value", "      '@scope/name': 1.2.3" or "      name:".
func pnpmMapKey(line string) string {
	line = strings.TrimSpace(line)
	i := strings.Index(line, ":")
	if i <= 0 {
		return ""
	}
	// key must end here: either end of line or followed by a space (value)
	if i+1 < len(line) && line[i+1] != ' ' {
		// could be '@scope/name': value — the colon inside quotes is fine
		// because quoted keys end with the quote before the colon.
		if line[0] != '\'' && line[0] != '"' {
			return ""
		}
	}
	return strings.Trim(line[:i], `'"`)
}

func parsePnpmLock(p string, data []byte) (*File, error) {
	f := newFile(p, "pnpm-lock.yaml", NPM)
	section := ""    // current top-level section
	current := ""    // current package (packages:/snapshots:) or importer
	currentVer := "" // version of the current packages: entry
	inDeps := false  // inside a dependencies:/optionalDependencies: block
	depIndent := 0   // indent of the dep-name lines
	isDepsKey := func(s string) bool {
		return s == "dependencies:" || s == "devDependencies:" || s == "optionalDependencies:"
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		ind := pnpmIndent(line)
		if ind == 0 { // new top-level section
			section = strings.TrimSuffix(line, ":")
			current, inDeps = "", false
			// lockfile v5: top-level dependencies:/devDependencies: hold
			// the project's direct deps at 2-space indent.
			if isDepsKey(line) {
				section = "@rootdeps"
			}
			continue
		}
		switch section {
		case "@rootdeps":
			if ind == 2 {
				if k := pnpmMapKey(line); k != "" {
					f.addRoot(k)
				}
			}
		case "importers":
			switch {
			case ind == 2:
				current, inDeps = "importer", false
			case ind == 4:
				inDeps = isDepsKey(strings.TrimSpace(line))
			case ind >= 6 && inDeps && ind == 6:
				if k := pnpmMapKey(line); k != "" {
					f.addRoot(k)
				}
			}
		case "packages", "snapshots":
			switch {
			case ind == 2:
				inDeps = false
				m := pnpmKeyRe.FindStringSubmatch(line)
				if m == nil {
					current, currentVer = "", ""
					continue
				}
				name, version := pnpmPkgName(m[1])
				current, currentVer = name, ""
				if section == "packages" && version != "" && version[0] >= '0' && version[0] <= '9' {
					f.add(name, version)
					currentVer = version
				}
			case ind == 4:
				trimmed := strings.TrimSpace(line)
				inDeps = isDepsKey(trimmed)
				depIndent = 6
				if section == "packages" && currentVer != "" && strings.HasPrefix(trimmed, "resolution:") {
					var integ, host string
					if m := pnpmIntegrityRe.FindStringSubmatch(trimmed); m != nil {
						integ = m[1]
					}
					if m := pnpmTarballRe.FindStringSubmatch(trimmed); m != nil {
						host = HostOf(m[1])
					}
					f.setPin(current, currentVer, integ, host)
				}
			case section == "packages" && currentVer != "" && ind == 6 && !inDeps:
				// block-style resolution: integrity/tarball on their own lines
				trimmed := strings.TrimSpace(line)
				if m := pnpmIntegrityRe.FindStringSubmatch(trimmed); m != nil {
					f.setPin(current, currentVer, m[1], "")
				} else if m := pnpmTarballRe.FindStringSubmatch(trimmed); m != nil {
					f.setPin(current, currentVer, "", HostOf(m[1]))
				}
			case inDeps && ind == depIndent && current != "":
				if k := pnpmMapKey(line); k != "" {
					f.addEdge(current, k)
				}
			}
		}
	}
	return f, nil
}

// splitNameAtVersion splits "name@1.2.3" or "@scope/name@1.2.3".
func splitNameAtVersion(key string) (name, version string) {
	start := 0
	if strings.HasPrefix(key, "@") {
		start = 1
	}
	if i := strings.IndexByte(key[start:], '@'); i > 0 {
		return key[:start+i], key[start+i+1:]
	}
	return "", ""
}

// ---- yarn.lock (classic v1 and berry v2+) ----

var yarnVersionRe = regexp.MustCompile(`^\s{2}version:?\s+"?([^"\s]+)"?\s*$`)

func parseYarnLock(p string, data []byte) (*File, error) {
	f := newFile(p, "yarn.lock", NPM)
	var currentNames []string
	currentVer := ""
	isWorkspace, inDeps, versionSeen, skipPins := false, false, false, false
	setPins := func(integ, host string) {
		if isWorkspace || skipPins || currentVer == "" {
			return
		}
		for _, n := range currentNames {
			f.setPin(n, currentVer, integ, host)
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] != ' ' && strings.HasSuffix(line, ":") { // entry header
			currentNames = currentNames[:0]
			currentVer = ""
			isWorkspace, inDeps, versionSeen, skipPins = false, false, false, false
			header := strings.TrimSuffix(line, ":")
			for _, spec := range strings.Split(header, ",") {
				spec = strings.Trim(strings.TrimSpace(spec), `"`)
				if strings.Contains(spec, "@workspace:") { // yarn berry project/workspace entry
					isWorkspace = true
				}
				// Non-registry protocols (berry patch:/git/link:/portal:/
				// file:/exec:, or a bare URL requirement): their checksums
				// hash locally-built artifacts, which must not be compared
				// against registry tarball hashes across revisions.
				for _, proto := range []string{"@patch:", "@git", "@https://", "@http://", "@ssh://", "@link:", "@portal:", "@file:", "@exec:"} {
					if strings.Contains(spec, proto) {
						skipPins = true
						break
					}
				}
				if name := yarnSpecName(spec); name != "" {
					currentNames = appendUnique(currentNames, name)
					// npm-protocol alias ("wrap-ansi-cjs@npm:wrap-ansi@^7"):
					// the recorded name is an alias that doesn't exist on
					// the registry — the real package is the one after
					// "npm:". Skip registry-derived claims for the alias.
					if rest := spec[len(name)+1:]; strings.HasPrefix(rest, "npm:") && strings.Contains(rest[len("npm:"):], "@") {
						f.markNonRegistry(name)
					}
				}
			}
			continue
		}
		if !versionSeen {
			if m := yarnVersionRe.FindStringSubmatch(line); m != nil {
				versionSeen = true
				if !isWorkspace {
					currentVer = m[1]
					for _, n := range currentNames {
						f.add(n, m[1])
					}
				}
				continue
			}
		}
		trimmed := strings.TrimSpace(line)
		if pnpmIndent(line) == 2 {
			switch {
			case strings.HasPrefix(trimmed, "resolved "): // classic
				v := strings.Trim(strings.TrimPrefix(trimmed, "resolved "), `"`)
				host, integ := yarnResolvedMeta(v)
				setPins(integ, host)
				continue
			case strings.HasPrefix(trimmed, "integrity "): // classic
				setPins(strings.TrimSpace(strings.TrimPrefix(trimmed, "integrity ")), "")
				continue
			case strings.HasPrefix(trimmed, "checksum: "): // berry
				setPins(strings.TrimSpace(strings.TrimPrefix(trimmed, "checksum: ")), "")
				continue
			}
			inDeps = trimmed == "dependencies:" || (isWorkspace && trimmed == "devDependencies:")
			continue
		}
		if inDeps && pnpmIndent(line) == 4 {
			dep := yarnDepName(trimmed)
			if dep == "" {
				continue
			}
			if isWorkspace {
				f.addRoot(dep)
				continue
			}
			for _, n := range currentNames {
				f.addEdge(n, dep)
			}
		}
	}
	return f, nil
}

// yarnResolvedMeta splits a yarn-classic resolved value
// "https://host/path#sha1hex" into the registry host and the fragment hash.
// git/file resolutions return "" for both.
func yarnResolvedMeta(v string) (host, integ string) {
	if strings.HasPrefix(v, "git") || strings.HasPrefix(v, "file:") {
		return "", ""
	}
	if i := strings.LastIndexByte(v, '#'); i >= 0 {
		integ = v[i+1:]
		v = v[:i]
	}
	host = HostOf(v)
	switch host {
	case "codeload.github.com", "github.com", "gitlab.com", "bitbucket.org":
		return "", "" // git-hosted tarball, not a registry (and the
		// fragment is a commit-ish, not a content hash)
	}
	return host, integ
}

// yarnDepName extracts the package name from a dependencies: sub-line —
// classic: `dep-a "^2.0.0"` / `"@scope/a" "^1.0"`; berry: `dep-a: ^2.0.0`.
func yarnDepName(s string) string {
	i, j := strings.IndexByte(s, ':'), strings.IndexByte(s, ' ')
	if i > 0 && (j < 0 || i < j) && (s[0] != '"' || strings.IndexByte(s[1:], '"') < i) {
		return strings.Trim(s[:i], `"`) // berry: `dep: ^1.0` / `"@s/d": ^1.0`
	}
	if j > 0 {
		return strings.Trim(s[:j], `"`) // classic: `dep "^1.0"` / `"@s/d" "^1.0"`
	}
	return ""
}

// yarnSpecName extracts "name" from "name@^1.0.0" or "@scope/name@npm:^1.0.0".
func yarnSpecName(spec string) string {
	start := 0
	if strings.HasPrefix(spec, "@") {
		start = 1
	}
	i := strings.IndexByte(spec[start:], '@')
	if i <= 0 {
		return ""
	}
	return spec[:start+i]
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// ---- bun.lock (JSONC) ----

var trailingCommaRe = regexp.MustCompile(`,(\s*[}\]])`)

func parseBunLock(p string, data []byte) (*File, error) {
	f := newFile(p, "bun.lock", NPM)
	clean := trailingCommaRe.ReplaceAll(data, []byte("$1"))
	var doc struct {
		Packages map[string]json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(clean, &doc); err != nil {
		return nil, err
	}
	for _, raw := range doc.Packages {
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) != nil || len(arr) == 0 {
			continue
		}
		var ident string
		if json.Unmarshal(arr[0], &ident) != nil {
			continue
		}
		name, version := splitNameAtVersion(ident)
		f.add(name, version)
		// [ident, registry, meta, integrity]: string elements after the
		// ident are the registry URL ("" = default) and the SRI hash.
		for _, el := range arr[1:] {
			var s string
			if json.Unmarshal(el, &s) != nil || s == "" {
				continue
			}
			switch {
			case strings.HasPrefix(s, "sha512-") || strings.HasPrefix(s, "sha256-") || strings.HasPrefix(s, "sha1-"):
				f.setPin(name, version, s, "")
			case strings.Contains(s, "://"):
				f.setPin(name, version, "", HostOf(s))
			}
		}
	}
	return f, nil
}
