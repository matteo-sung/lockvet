package lock

// Single-tool version files (format #57) and SDKMAN's `.sdkmanrc` (#58):
// the oldest toolchain-pinning convention there is. `.nvmrc`,
// `.node-version`, `.python-version`, `.ruby-version`, `.go-version`,
// `.java-version`, `.terraform-version` and `.terragrunt-version` each pin
// ONE tool for a repository, and every version manager in that tool's
// ecosystem reads them (nvm/fnm/nodenv, pyenv, rbenv/rvm/chruby, goenv,
// jenv, tfenv/tgenv — plus asdf and mise, which treat them as "idiomatic
// version files"). Renovate bumps them with dedicated managers; nothing
// vets the bumps.
//
// Every entry rides the asdf/mise pipeline (internal/actreg): pins are
// verified against the tool's own repository tags — verified `(=tag)`
// resolutions, compare links, release notes, and ▲ when a concrete pin
// matches no release. Vendor-prefixed values (`corretto-17`,
// `pypy3.10-7.3.16`, `jruby-9.4.5.0`) render honest version rows that
// claim nothing, exactly like their `.tool-versions` spellings; symbolic
// selectors (`latest`, `lts/*`, `system`, `node`) claim nothing at all.
//
// `.sdkmanrc` (`sdk env`) is `candidate=version` per line: `gradle`,
// `maven`, `sbt` map onto the registries lockvet already verifies
// (services.gradle.org, Maven Central); `kotlin`/`scala` verify against
// their repos' tags via the tool map; SDKMAN's vendor-suffixed Java
// builds (`17.0.9-tem`) honestly claim nothing.

import "strings"

// singleToolFiles maps each version-file basename to the tool it pins
// (the asdf/mise tool-map name).
var singleToolFiles = map[string]string{
	".nvmrc":              "node",
	".node-version":       "node",
	".python-version":     "python",
	".ruby-version":       "ruby",
	".go-version":         "go",
	".java-version":       "java",
	".terraform-version":  "terraform",
	".terragrunt-version": "terragrunt",
}

// parseSingleToolPin builds a parser for one single-tool version file.
// One version per line (pyenv's `.python-version` legitimately lists
// several — fallbacks, like `.tool-versions`), `#` comments tolerated.
func parseSingleToolPin(base, tool string) func(string, []byte) (*File, error) {
	return func(p string, data []byte) (*File, error) {
		f := newFile(p, base, MiseTool)
		for _, line := range strings.Split(string(data), "\n") {
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			if v := singleToolVersion(tool, fields[0]); v != "" {
				addToolEntry(f, tool, []string{v})
			}
		}
		finishToolFile(f)
		return f, nil
	}
}

// singleToolVersion normalizes one version-file value: a leading `v`
// before a digit is spelling, not version (`.nvmrc` `v18.16.0`), and
// rvm-style `.ruby-version` values prefix the tool name (`ruby-3.3.4`).
// Everything else is kept verbatim — vendor-prefixed values stay whole
// and simply claim nothing (addToolEntry's toolVersionPlain gate drops
// symbolic selectors).
func singleToolVersion(tool, v string) string {
	if rest, ok := strings.CutPrefix(v, tool+"-"); ok && rest != "" && rest[0] >= '0' && rest[0] <= '9' {
		v = rest
	}
	if len(v) > 1 && v[0] == 'v' && v[1] >= '0' && v[1] <= '9' {
		v = v[1:]
	}
	return v
}

// parseSdkmanrc parses SDKMAN's `.sdkmanrc`: `candidate=version` lines,
// `#` comments.
func parseSdkmanrc(p string, data []byte) (*File, error) {
	f := newFile(p, ".sdkmanrc", MiseTool)
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if key == "" || val == "" || strings.ContainsAny(key, " \t") {
			continue
		}
		addToolEntry(f, key, []string{val})
	}
	finishToolFile(f)
	return f, nil
}
