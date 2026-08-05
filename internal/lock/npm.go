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
			Version              string            `json:"version"`
			Link                 bool              `json:"link"`
			Resolved             string            `json:"resolved"`
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
			if strings.HasPrefix(pkg.Resolved, "git") || strings.HasPrefix(pkg.Resolved, "file:") {
				f.markNonRegistry(name) // git or local-path dependency
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
				Requires     map[string]string          `json:"requires"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(raw, &e) == nil {
				f.add(name, e.Version)
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
	section := ""   // current top-level section
	current := ""   // current package (packages:/snapshots:) or importer
	inDeps := false // inside a dependencies:/optionalDependencies: block
	depIndent := 0  // indent of the dep-name lines
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
					current = ""
					continue
				}
				name, version := pnpmPkgName(m[1])
				current = name
				if section == "packages" && version != "" && version[0] >= '0' && version[0] <= '9' {
					f.add(name, version)
				}
			case ind == 4:
				inDeps = isDepsKey(strings.TrimSpace(line))
				depIndent = 6
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
	isWorkspace, inDeps, versionSeen := false, false, false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] != ' ' && strings.HasSuffix(line, ":") { // entry header
			currentNames = currentNames[:0]
			isWorkspace, inDeps, versionSeen = false, false, false
			header := strings.TrimSuffix(line, ":")
			for _, spec := range strings.Split(header, ",") {
				spec = strings.Trim(strings.TrimSpace(spec), `"`)
				if strings.Contains(spec, "@workspace:") { // yarn berry project/workspace entry
					isWorkspace = true
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
					for _, n := range currentNames {
						f.add(n, m[1])
					}
				}
				continue
			}
		}
		trimmed := strings.TrimSpace(line)
		if pnpmIndent(line) == 2 {
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
	}
	return f, nil
}
