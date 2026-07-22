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
			Version string `json:"version"`
			Link    bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Packages) > 0 { // lockfile v2/v3
		for key, pkg := range doc.Packages {
			if key == "" || pkg.Link || pkg.Version == "" {
				continue
			}
			name := key
			if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
				name = key[i+len("node_modules/"):]
			}
			f.add(name, pkg.Version)
		}
		return f, nil
	}
	// lockfile v1: nested "dependencies" tree
	var walk func(deps map[string]json.RawMessage)
	walk = func(deps map[string]json.RawMessage) {
		for name, raw := range deps {
			var e struct {
				Version      string                     `json:"version"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(raw, &e) == nil {
				f.add(name, e.Version)
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

func parsePnpmLock(p string, data []byte) (*File, error) {
	f := newFile(p, "pnpm-lock.yaml", NPM)
	inPackages := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if trimmed == "packages:" || trimmed == "snapshots:" {
			inPackages = trimmed == "packages:"
			continue
		}
		if len(trimmed) > 0 && trimmed[0] != ' ' { // new top-level section
			inPackages = false
			continue
		}
		if !inPackages {
			continue
		}
		m := pnpmKeyRe.FindStringSubmatch(trimmed)
		if m == nil {
			continue
		}
		key := strings.TrimPrefix(m[1], "/")
		if i := strings.IndexByte(key, '('); i >= 0 { // strip peer suffixes
			key = key[:i]
		}
		name, version := splitNameAtVersion(key)
		if name == "" { // old style: /name/1.2.3
			if i := strings.LastIndexByte(key, '/'); i > 0 && !strings.Contains(key[i+1:], "@") {
				name, version = key[:i], key[i+1:]
			}
		}
		if version != "" && version[0] >= '0' && version[0] <= '9' {
			f.add(name, version)
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
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] != ' ' && strings.HasSuffix(line, ":") { // entry header
			currentNames = currentNames[:0]
			header := strings.TrimSuffix(line, ":")
			for _, spec := range strings.Split(header, ",") {
				spec = strings.Trim(strings.TrimSpace(spec), `"`)
				if name := yarnSpecName(spec); name != "" {
					currentNames = appendUnique(currentNames, name)
				}
			}
			continue
		}
		if m := yarnVersionRe.FindStringSubmatch(line); m != nil {
			for _, n := range currentNames {
				f.add(n, m[1])
			}
			currentNames = currentNames[:0]
		}
	}
	return f, nil
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
