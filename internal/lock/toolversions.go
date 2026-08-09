package lock

// Version-manager pin files: asdf/mise `.tool-versions` (format #55) and
// mise's own `mise.toml` config (#56). Both pin the exact toolchain a
// project runs — node, python, terraform, kubectl — and `mise up` /
// Renovate's asdf+mise managers bump those pins exactly like lockfile
// entries. Nothing vets them.
//
// What each entry becomes:
//
//   - mise backend-prefixed tools name real registry packages and get the
//     FULL registry treatment lockvet already has: `npm:prettier` → npm,
//     `cargo:eza` → crates.io, `pipx:black` → PyPI, `gem:rubocop` →
//     RubyGems, `dotnet:GitVersion.Tool` → NuGet, `go:github.com/x/y` →
//     Go modules (OSV advisories, ages, deprecation, typosquat, unlisted).
//   - `gradle`, `maven` and `sbt` are registry releases lockvet already
//     verifies: the Gradle distribution (services.gradle.org — ages,
//     withdrawn releases, unlisted) and Maven Central coordinates
//     (org.apache.maven:apache-maven, org.scala-sbt:sbt — real GHSAs).
//   - other tools carry the "mise/asdf" ecosystem: internal/actreg
//     verifies the pin against the tool's OWN repository tags (curated
//     tool→repo map with per-tool tag conventions: go1.23.4, ruby v3_3_4,
//     OTP-27.1, jq-1.7.1, kustomize/v5.4.3, swift-5.10-RELEASE) — compare
//     links, release notes and the ▲ not-a-release flag included.
//     `ubi:`/`aqua:`/`github:`/`spm:` tools name their GitHub repo
//     directly and get the same treatment without any map.
//   - `asdf:`/`vfox:` plugin-sourced tools, `system`, `latest`, `lts*`,
//     `ref:`/`path:`/`prefix:`/`sub-*` pins and templated values honestly
//     claim nothing.

import (
	"regexp"
	"sort"
	"strings"
)

// parseToolVersions parses asdf/mise `.tool-versions`: one tool per line,
// `<tool> <version> [fallback-version ...]`, `#` comments.
func parseToolVersions(p string, data []byte) (*File, error) {
	f := newFile(p, ".tool-versions", MiseTool)
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		addToolEntry(f, fields[0], fields[1:])
	}
	finishToolFile(f)
	return f, nil
}

var (
	miseToolKeyRe = regexp.MustCompile(`^(?:"([^"]+)"|'([^']+)'|([^\s=]+))\s*=\s*(.+)$`)
	miseStrRe     = regexp.MustCompile(`^(?:"([^"]*)"|'([^']*)')`)
	miseVerKeyRe  = regexp.MustCompile(`(?:^|[,{]\s*)version\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

// parseMiseToml parses mise.toml / .mise.toml / mise config.toml: the
// `[tools]` table (string, array and inline-table `{version = "…"}`
// values, quoted backend keys like "npm:prettier") plus `[tools.NAME]`
// subtables with a `version` key.
func parseMiseToml(p string, data []byte) (*File, error) {
	f := newFile(p, "mise.toml", MiseTool)
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = stripTOMLComment(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.Trim(line, "[] \t")
			continue
		}
		m := miseToolKeyRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[1] + m[2] + m[3]
		val := strings.TrimSpace(m[4])
		switch {
		case section == "tools":
			if vs := miseValueVersions(val); len(vs) > 0 {
				addToolEntry(f, key, vs)
			}
		case strings.HasPrefix(section, "tools.") && key == "version":
			tool := strings.Trim(strings.TrimPrefix(section, "tools."), `"'`)
			if v := miseString(val); v != "" {
				addToolEntry(f, tool, []string{v})
			}
		}
	}
	finishToolFile(f)
	return f, nil
}

// miseValueVersions extracts version strings from a [tools] value: a
// string, an array of strings, or an inline table with a version key.
func miseValueVersions(val string) []string {
	switch {
	case strings.HasPrefix(val, "["): // array: all listed fallbacks
		var out []string
		for _, part := range strings.Split(strings.Trim(val, "[] \t"), ",") {
			if v := miseString(strings.TrimSpace(part)); v != "" {
				out = append(out, v)
			}
		}
		return out
	case strings.HasPrefix(val, "{"): // inline table: version = "…"
		if m := miseVerKeyRe.FindStringSubmatch(val); m != nil && m[1]+m[2] != "" {
			return []string{m[1] + m[2]}
		}
		return nil
	default:
		if v := miseString(val); v != "" {
			return []string{v}
		}
		return nil
	}
}

// miseString unquotes a TOML string scalar, or returns "" for anything
// that is not one.
func miseString(val string) string {
	if m := miseStrRe.FindStringSubmatch(val); m != nil {
		return m[1] + m[2]
	}
	return ""
}

// toolBackendEco maps mise backend prefixes to the registry ecosystem the
// named package actually lives in.
var toolBackendEco = map[string]Ecosystem{
	"npm":    NPM,
	"cargo":  CratesIO,
	"pipx":   PyPI,
	"pip":    PyPI,
	"gem":    RubyGems,
	"dotnet": NuGet,
	"go":     Go,
}

// ToolEntryEco maps an asdf/mise tool name to the package name and
// ecosystem lockvet records it as: backend-prefixed names onto their real
// registry ecosystems (npm:prettier → npm), gradle/maven/sbt onto the
// registries that already verify them, everything else onto the
// "mise/asdf" ecosystem. ok=false means the entry names nothing usable.
// nonRegistry marks plugin-sourced tools whose pins claim nothing.
func ToolEntryEco(tool string) (name string, eco Ecosystem, nonRegistry, ok bool) {
	tool = strings.TrimSpace(tool)
	// `ubi:owner/repo[exe=x]` option suffixes are not part of the name.
	if i := strings.IndexByte(tool, '['); i >= 0 {
		tool = tool[:i]
	}
	if tool == "" || strings.Contains(tool, "{{") {
		return "", MiseTool, false, false
	}

	name, eco = tool, MiseTool
	if backend, rest, cut := strings.Cut(tool, ":"); cut {
		switch b := strings.ToLower(backend); b {
		case "npm", "cargo", "pipx", "pip", "gem", "dotnet", "go":
			if rest == "" {
				return "", MiseTool, false, false
			}
			eco, name = toolBackendEco[b], rest
			if b == "pipx" || b == "pip" {
				name = normalizePyPI(name)
			}
			if b == "dotnet" {
				name = strings.ToLower(name)
			}
		case "ubi", "aqua", "github", "spm":
			// owner/repo on GitHub: verified against the repo's own tags.
			if strings.Count(rest, "/") != 1 {
				return "", MiseTool, false, false
			}
			name = strings.ToLower(b) + ":" + rest
		case "asdf", "vfox":
			// Plugin-sourced: the plugin decides what "1.2.3" means and
			// where it downloads from — no claims.
			nonRegistry = true
		default:
			nonRegistry = true // unknown backend: honest version rows only
		}
	} else {
		switch strings.ToLower(tool) {
		case "gradle":
			// The Gradle distribution — verified against
			// services.gradle.org like gradle-wrapper.properties pins.
			eco, name = GradleDist, "gradle"
		case "maven", "mvn":
			eco, name = Maven, "org.apache.maven:apache-maven"
		case "sbt":
			eco, name = Maven, "org.scala-sbt:sbt"
		}
	}
	return name, eco, nonRegistry, true
}

// addToolEntry records one tool's pinned version(s) on the file.
func addToolEntry(f *File, tool string, versions []string) {
	name, eco, nonRegistry, ok := ToolEntryEco(tool)
	if !ok {
		return
	}

	added := false
	for _, v := range versions {
		v = strings.TrimSpace(v)
		if !toolVersionPlain(v) {
			continue
		}
		if eco == Go && !strings.HasPrefix(v, "v") {
			v = "v" + v // Go module versions are v-prefixed
		}
		f.add(name, v)
		added = true
	}
	if !added {
		return
	}
	if eco != MiseTool {
		if f.PkgEco == nil {
			f.PkgEco = map[string]Ecosystem{}
		}
		f.PkgEco[name] = eco
	}
	if nonRegistry {
		f.markNonRegistry(name)
	}
}

// toolVersionPlain reports whether a version string is a concrete pin
// worth a row: `1.2.3`, `22`, `3.13t`, `27.0-rc3`. Symbolic selectors
// (`latest`, `lts*`, `system`, `stable`…), scheme-prefixed refs
// (`ref:`, `path:`, `prefix:`, `sub-1:latest`) and templates are not.
func toolVersionPlain(v string) bool {
	if v == "" || strings.Contains(v, ":") || strings.Contains(v, "{{") ||
		strings.Contains(v, "/") {
		return false
	}
	// A concrete pin names digits somewhere ("1.2.3", "3.13t",
	// "temurin-21.0.2+13" — vendor-prefixed pins still deserve a row,
	// they just claim nothing); symbolic selectors never do.
	return strings.ContainsAny(v, "0123456789")
}

// isMiseConfigPath reports whether a config.toml path is one of mise's
// config locations: a mise/ or .mise/ directory ( .config/mise/config.toml,
// .mise/config.toml, mise/config.toml).
func isMiseConfigPath(p string) bool {
	p = strings.ReplaceAll(p, "\\", "/")
	i := strings.LastIndexByte(p, '/')
	if i < 0 {
		return false
	}
	dir := p[:i]
	if j := strings.LastIndexByte(dir, '/'); j >= 0 {
		dir = dir[j+1:]
	}
	return dir == "mise" || dir == ".mise"
}

// finishToolFile marks every pinned tool as a direct dependency.
func finishToolFile(f *File) {
	f.RootsKnown = true
	for name := range f.Packages {
		f.Roots = append(f.Roots, name)
	}
	sort.Strings(f.Roots)
}
