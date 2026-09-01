package lock

import (
	"regexp"
	"strings"
)

// parsePylock reads pylock.toml — Python's standardized lockfile
// (PEP 751, installable with `pip install --require-hashes` semantics;
// written by uv, pip, pipenv, pdm, …). Every locked package is a
// [[packages]] entry:
//
//	[[packages]]
//	name = "attrs"
//	version = "25.1.0"
//	index = "https://pypi.org/simple/"                    (optional)
//	sdist = { url = "…", hashes = { sha256 = "…" } }      (inline, uv)
//	wheels = [ { url = "…", hashes = { sha256 = "…" } } ] (inline array)
//
// or, in pip's sub-table style:
//
//	[[packages.wheels]]
//	name = "attrs-25.1.0-py3-none-any.whl"
//	url = "https://files.pythonhosted.org/…"
//	[packages.wheels.hashes]
//	sha256 = "…"
//
// name/version are only trusted at the entry root — wheel/sdist
// sub-tables carry their own `name` (the artifact filename).
// vcs/directory/archive sources do not resolve from an index at all →
// NonRegistry. Artifact hashes and the index/artifact host feed the
// integrity/resolution tamper checks. The optional per-package
// `dependencies` array (entries referencing other locked packages by
// name) becomes graph edges; PEP 751 records no project root.
func parsePylock(p string, data []byte) (*File, error) {
	f := newFile(p, "pylock.toml", PyPI)
	var name, version, pinHash, pinHost, artHost string
	var deps []string
	nonReg, sawPath, sawRemote := false, false, false
	inPkg := false
	sub := ""   // current sub-table under the entry: wheels/sdist/vcs/…
	array := "" // multi-line inline array being scanned: "wheels"/"dependencies"

	flush := func() {
		if inPkg && name != "" {
			f.add(name, version)
			if nonReg || (sawPath && !sawRemote) {
				f.markNonRegistry(name)
			}
			host := pinHost
			if host == "" {
				host = artHost
			}
			f.setPin(name, version, pinHash, host)
			for _, d := range deps {
				f.addEdge(name, d)
			}
		}
		name, version, pinHash, pinHost, artHost = "", "", "", "", ""
		deps = nil
		nonReg, sawPath, sawRemote = false, false, false
		sub = ""
	}

	harvest := func(line string) { // hashes + artifact url/path in a line
		for _, m := range pylockHashesRe.FindAllStringSubmatch(line, -1) {
			for _, kv := range pylockHashKVRe.FindAllStringSubmatch(m[1], -1) {
				pinHash = joinHashSet(pinHash, kv[1]+":"+kv[2])
			}
		}
		if m := pylockURLRe.FindStringSubmatch(line); m != nil {
			sawRemote = true
			if artHost == "" {
				artHost = HostOf(m[1])
			}
		}
		if pylockPathRe.MatchString(line) {
			sawPath = true
		}
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if array != "" { // inside a multi-line inline array
			if line == "]" || line == "]," {
				array = ""
				continue
			}
			if array == "dependencies" {
				if m := tomlNameRe.FindStringSubmatch(line); m != nil {
					deps = append(deps, m[1])
				}
			} else {
				harvest(line)
			}
			continue
		}
		if strings.HasPrefix(line, "[") { // table headers
			switch {
			case line == "[[packages]]":
				flush()
				inPkg = true
			case strings.HasPrefix(line, "[[packages.") || strings.HasPrefix(line, "[packages."):
				if !inPkg {
					continue
				}
				parts := strings.Split(strings.Trim(line, "[]"), ".")
				sub = parts[1]
				switch sub {
				case "vcs", "directory", "archive":
					nonReg = true
				}
				if parts[len(parts)-1] == "hashes" {
					sub = "hashes"
				}
			default:
				flush()
				inPkg = false
			}
			continue
		}
		if !inPkg {
			continue
		}
		switch sub {
		case "dependencies": // [[packages.dependencies]] sub-table shape
			if m := tomlKVRe.FindStringSubmatch(line); m != nil && m[1] == "name" {
				deps = append(deps, m[2])
			}
			continue
		case "hashes": // [packages.wheels.hashes]: sha256 = "…"
			if kv := pylockHashKVRe.FindStringSubmatch(line); kv != nil {
				pinHash = joinHashSet(pinHash, kv[1]+":"+kv[2])
			}
			continue
		case "wheels", "sdist", "archive": // sub-table artifact keys
			harvest(line)
			continue
		case "": // entry root
		default: // tool / attestation-identities / vcs / directory: skip
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
		switch {
		case strings.HasPrefix(line, "index ="):
			if m := pylockStrRe.FindStringSubmatch(line); m != nil {
				pinHost = HostOf(m[1])
				sawRemote = true
			}
		case strings.HasPrefix(line, "vcs ="),
			strings.HasPrefix(line, "directory ="),
			strings.HasPrefix(line, "archive ="):
			nonReg = true // inline-table source shapes
		case strings.HasPrefix(line, "sdist =") || strings.HasPrefix(line, "wheels ="):
			harvest(line)
			if strings.HasSuffix(line, "[") {
				array = "wheels" // multi-line wheels = [ … ]
			}
		case strings.HasPrefix(line, "dependencies ="):
			if strings.HasSuffix(line, "[") {
				array = "dependencies"
			} else { // single line: dependencies = [{name = "a"}, …]
				for _, m := range tomlNameRe.FindAllStringSubmatch(line, -1) {
					deps = append(deps, m[1])
				}
			}
		}
	}
	flush()
	return f, nil
}

var (
	// hashes = { sha256 = "…", … } inline tables (uv, pipenv)
	pylockHashesRe = regexp.MustCompile(`hashes\s*=\s*\{([^}]*)\}`)
	// one algo/hex pair, inline or as a [….hashes] sub-table line
	pylockHashKVRe = regexp.MustCompile(`(?:^|[{,])\s*([a-z0-9_]+)\s*=\s*"([^"]+)"`)
	// url anywhere in an inline artifact table, or a sub-table url line
	pylockURLRe = regexp.MustCompile(`(?:^|[{,]\s*)url\s*=\s*"([^"]+)"`)
	// path = "…" → artifact stored next to the lock, not on an index
	pylockPathRe = regexp.MustCompile(`(?:^|[{,]\s*)path\s*=\s*"`)
	// any single string value (index = "…")
	pylockStrRe = regexp.MustCompile(`"([^"]+)"`)
)

// isPylockName reports whether base is a PEP 751 lockfile name:
// pylock.toml or pylock.<name>.toml.
func isPylockName(base string) bool {
	if base == "pylock.toml" {
		return true
	}
	return strings.HasPrefix(base, "pylock.") && strings.HasSuffix(base, ".toml") &&
		len(base) > len("pylock.")+len(".toml")
}
