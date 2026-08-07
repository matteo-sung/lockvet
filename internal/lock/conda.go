package lock

import (
	"path"
	"strings"
)

// ---- pixi.lock (v4 through v7) and conda-lock.yml (v1) ----
//
// Both are machine-generated YAML with rigidly regular indentation, parsed
// line-by-line like pnpm-lock.yaml (lockvet has no YAML dependency).
//
// pixi.lock top-level `packages:` entries come in two generations:
//
//	v4/v5:  - kind: conda            v6/v7:  - conda: https://…/name-1.2.3-build.conda
//	          name: numpy                      depends:
//	          version: 1.26.4                  - libgomp >=7.5.0
//	          url: https://…                 - pypi: https://…/x.whl
//	          depends:                         name: tzdata
//	          - libgomp >=7.5.0                version: '2025.1'
//
// v6/v7 conda entries carry no name/version fields: both come from the URL
// basename, which is always <name>-<version>-<build>(.conda|.tar.bz2) and
// conda versions never contain dashes, so splitting on the last two dashes
// is exact. pypi entries always carry explicit name/version (a bare
// `- pypi: .` path dep has no version and is skipped).
//
// conda-lock.yml `package:` entries are flat maps with `dependencies:` as a
// nested map (its keys are the dep names); `manager: pip` marks PyPI
// packages, everything else is conda.
//
// Conda itself has no OSV.dev ecosystem and no deps.dev coverage, so conda
// packages get diff/graph/semver treatment only, while pip/pypi packages in
// the same file are marked PyPI via File.PkgEco and get the full
// vulnerability, age and deprecation data.

// condaNV splits a conda package URL basename into name and version.
// "…/ld_impl_linux-64-2.46.1-default_hbd61a6d_102.conda" → ("ld_impl_linux-64", "2.46.1").
func condaNV(url string) (name, version string) {
	base := path.Base(url)
	for _, suf := range []string{".conda", ".tar.bz2"} {
		if strings.HasSuffix(base, suf) {
			base = strings.TrimSuffix(base, suf)
			// name-version-build: split on the last two dashes.
			i := strings.LastIndexByte(base, '-')
			if i <= 0 {
				return "", ""
			}
			j := strings.LastIndexByte(base[:i], '-')
			if j <= 0 {
				return "", ""
			}
			return base[:j], base[j+1 : i]
		}
	}
	return "", ""
}

// condaDepName extracts the package name from a conda depends entry like
// "libgomp >=7.5.0" or "_libgcc_mutex 0.1 conda_forge". Virtual packages
// ("__glibc >=2.17") describe the platform, not a dependency.
func condaDepName(s string) string {
	name, _, _ := strings.Cut(strings.TrimSpace(s), " ")
	if strings.HasPrefix(name, "__") {
		return ""
	}
	return name
}

// pypiReqName extracts the package name from a PEP 508 requirement like
// "matplotlib>=3.3.3", "colorama ; platform_system == 'Windows'" or
// "zensical ; extra == 'docs'".
func pypiReqName(s string) string {
	s = strings.TrimSpace(s)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			continue
		}
		return s[:i]
	}
	return s
}

// pypiNorm is PEP 503 name normalization, used to resolve requires_dist
// names (often dashed) against wheel-derived package names (often
// underscored).
func pypiNorm(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '_' || r == '.' {
			return '-'
		}
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)
}

func yamlVal(s string) string { return strings.Trim(strings.TrimSpace(s), `'"`) }

type condaEntry struct {
	kind    string // "conda" or "pypi"
	url     string
	name    string
	version string
	sha     string   // sha256 of the artifact, when the lockfile records it
	deps    []string // conda depends entries / conda-lock dependencies keys
	reqs    []string // pypi requires_dist entries
}

type pypiEdge struct{ from, to string } // to is PEP 503-normalized

func flushCondaEntry(f *File, e *condaEntry, pypiEdges *[]pypiEdge) {
	if e == nil || e.kind == "" {
		return
	}
	name, version := e.name, e.version
	if e.kind == "conda" && (name == "" || version == "") {
		name, version = condaNV(e.url)
	}
	if name == "" || version == "" {
		return
	}
	f.add(name, version)
	// Conda rebuilds the SAME version under new build numbers routinely
	// (py312h..._0 -> _1), so artifact hashes can't anchor to (name,
	// version) — only the resolution host is recorded for conda entries.
	// PyPI wheels inside conda/pixi locks are immutable per file.
	integ := ""
	if e.kind == "pypi" {
		integ = withPrefixIfSet("sha256:", strings.ToLower(e.sha))
	}
	f.setPin(name, version, integ, HostOf(e.url))
	if e.kind == "pypi" {
		if f.PkgEco == nil {
			f.PkgEco = map[string]Ecosystem{}
		}
		f.PkgEco[Sanitize(name)] = PyPI
		for _, r := range e.reqs {
			if to := pypiReqName(r); to != "" {
				*pypiEdges = append(*pypiEdges, pypiEdge{name, pypiNorm(to)})
			}
		}
		return
	}
	for _, d := range e.deps {
		if to := condaDepName(d); to != "" {
			f.addEdge(name, to)
		}
	}
	// conda-lock pip entries route through here with kind "pypi" only;
	// conda deps of pip packages don't occur.
}

// resolvePypiEdges matches normalized requires_dist names against the
// packages actually present in the lockfile.
func resolvePypiEdges(f *File, edges []pypiEdge) {
	if len(edges) == 0 {
		return
	}
	byNorm := map[string]string{}
	for name := range f.Packages {
		byNorm[pypiNorm(name)] = name
	}
	for _, e := range edges {
		if to, ok := byNorm[e.to]; ok {
			f.addEdge(e.from, to)
		}
	}
}

func parsePixiLock(p string, data []byte) (*File, error) {
	f := newFile(p, "pixi.lock", Conda)
	var (
		section   string
		cur       *condaEntry
		curList   string // "deps" or "reqs" while inside depends:/requires_dist:
		pypiEdges []pypiEdge
	)
	flush := func() {
		flushCondaEntry(f, cur, &pypiEdges)
		cur, curList = nil, ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '-' { // new top-level key
			flush()
			section = strings.TrimSuffix(line, ":")
			continue
		}
		if section != "packages" && section != "package" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "- "): // new entry
			flush()
			cur = &condaEntry{}
			key, val, ok := strings.Cut(line[2:], ":")
			if !ok {
				continue
			}
			val = yamlVal(val)
			switch key {
			case "conda", "pypi":
				cur.kind, cur.url = key, val
			case "kind":
				cur.kind = val
			case "name":
				cur.name = val
			}
		case cur != nil && strings.HasPrefix(line, "  ") && len(line) > 2 && line[2] != ' ' && line[2] != '-':
			// entry field at exactly 2-space indent
			key, val, ok := strings.Cut(line[2:], ":")
			if !ok {
				curList = ""
				continue
			}
			val = yamlVal(val)
			switch key {
			case "name":
				cur.name = val
			case "version":
				cur.version = val
			case "url":
				cur.url = val
			case "sha256":
				cur.sha = val
			case "depends":
				curList = "deps"
				continue
			case "requires_dist":
				curList = "reqs"
				continue
			}
			curList = ""
		case cur != nil && strings.HasPrefix(line, "  - "):
			// list item at exactly 2-space indent (nested lists like
			// run_exports sit deeper and are ignored)
			switch curList {
			case "deps":
				cur.deps = append(cur.deps, yamlVal(line[4:]))
			case "reqs":
				cur.reqs = append(cur.reqs, yamlVal(line[4:]))
			}
		}
	}
	flush()
	resolvePypiEdges(f, pypiEdges)
	return f, nil
}

func parseCondaLock(p string, data []byte) (*File, error) {
	f := newFile(p, "conda-lock.yml", Conda)
	var (
		section   string
		cur       *condaEntry
		subMap    string // current nested-map field ("dependencies", "hash", …)
		pypiEdges []pypiEdge
	)
	flush := func() {
		if cur != nil && cur.kind == "" {
			cur.kind = "conda"
		}
		flushCondaEntry(f, cur, &pypiEdges)
		cur, subMap = nil, ""
	}
	field := func(key, val string) {
		switch key {
		case "name":
			cur.name = val
		case "version":
			cur.version = val
		case "url":
			cur.url = val
		case "sha256":
			cur.sha = val
		case "manager":
			if val == "pip" {
				cur.kind = "pypi"
			} else {
				cur.kind = "conda"
			}
		}
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if line[0] != ' ' && line[0] != '-' {
			flush()
			section = strings.TrimSuffix(line, ":")
			continue
		}
		if section != "package" && section != "packages" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "- "): // new entry; dash line carries the first field
			flush()
			cur = &condaEntry{}
			if key, val, ok := strings.Cut(line[2:], ":"); ok {
				field(key, yamlVal(val))
			}
		case cur != nil && strings.HasPrefix(line, "  ") && len(line) > 2 && line[2] != ' ':
			key, val, ok := strings.Cut(line[2:], ":")
			if !ok {
				subMap = ""
				continue
			}
			if strings.TrimSpace(val) == "" || strings.TrimSpace(val) == "{}" {
				subMap = key // "dependencies:", "hash:", … open a nested map
			} else {
				subMap = ""
			}
			field(key, yamlVal(val))
		case cur != nil && subMap == "hash" && strings.HasPrefix(line, "    ") && len(line) > 4 && line[4] != ' ':
			if key, val, ok := strings.Cut(strings.TrimSpace(line), ":"); ok && yamlVal(key) == "sha256" {
				cur.sha = yamlVal(val)
			}
		case cur != nil && subMap == "dependencies" && strings.HasPrefix(line, "    ") && len(line) > 4 && line[4] != ' ':
			if key, _, ok := strings.Cut(strings.TrimSpace(line), ":"); ok {
				dep := yamlVal(key)
				if dep != "" && !strings.HasPrefix(dep, "__") {
					if cur.kind == "pypi" {
						cur.reqs = append(cur.reqs, dep)
					} else {
						cur.deps = append(cur.deps, dep)
					}
				}
			}
		}
	}
	flush()
	resolvePypiEdges(f, pypiEdges)
	return f, nil
}
