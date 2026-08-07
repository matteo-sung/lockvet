package lock

import (
	"regexp"
	"strings"
)

// parseBazelModule reads MODULE.bazel — bzlmod's manifest. Like go.mod,
// the manifest pins exact versions (bazel_dep versions are minimum-version
// -selection inputs, and update bots bump them in place), and unlike the
// lockfile most repositories DO commit and diff it, so Renovate/Dependabot
// module bumps land here. Every bazel_dep is a direct dependency (roots
// known). single_version_override wins over the bazel_dep version;
// git_override / archive_override / local_path_override mean the module
// does not come from the registry at all.
func parseBazelModule(p string, data []byte) (*File, error) {
	f := newFile(p, "MODULE.bazel", Bazel)
	src := stripStarlarkComments(string(data))

	for _, call := range starlarkCalls(src, "bazel_dep") {
		name, version := attrOf(call, "name"), attrOf(call, "version")
		if name == "" || version == "" {
			continue // dev-only dep without a version, or unparsable
		}
		f.add(name, version)
		f.addRoot(name)
	}
	for _, call := range starlarkCalls(src, "single_version_override") {
		name, version := attrOf(call, "module_name"), attrOf(call, "version")
		if name == "" {
			continue
		}
		if version != "" {
			// The override version is what resolution actually uses.
			f.Packages[Sanitize(name)] = []string{Sanitize(version)}
		}
		if reg := attrOf(call, "registry"); reg != "" && !strings.Contains(reg, "bcr.bazel.build") {
			f.markNonRegistry(name)
		}
	}
	for _, fn := range []string{"git_override", "archive_override", "local_path_override"} {
		for _, call := range starlarkCalls(src, fn) {
			if name := attrOf(call, "module_name"); name != "" {
				f.markNonRegistry(name)
			}
		}
	}
	return f, nil
}

// starlarkCalls returns the argument text of every top-level call to fn,
// e.g. `bazel_dep(name = "x", version = "1.2")` → `name = "x", version = "1.2"`.
// Calls may span lines; nesting inside the argument list is tolerated by
// paren counting (strings in MODULE.bazel dep declarations don't contain
// parens in practice, and a miscount only drops that one call).
func starlarkCalls(src, fn string) []string {
	var out []string
	for i := 0; ; {
		j := strings.Index(src[i:], fn+"(")
		if j < 0 {
			break
		}
		start := i + j
		// require a call statement, not a substring of a longer name
		if start > 0 {
			if b := src[start-1]; b == '_' || b == '.' ||
				(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
				i = start + len(fn) + 1
				continue
			}
		}
		depth, k := 0, start+len(fn)
		for ; k < len(src); k++ {
			switch src[k] {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 {
				break
			}
		}
		if k >= len(src) {
			break
		}
		out = append(out, src[start+len(fn)+1:k])
		i = k + 1
	}
	return out
}

var starlarkAttrRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"`)

// attrOf extracts a string keyword argument from a call's argument text.
func attrOf(call, key string) string {
	for _, m := range starlarkAttrRe.FindAllStringSubmatch(call, -1) {
		if m[1] == key {
			return strings.TrimSpace(m[2])
		}
	}
	return ""
}

// stripStarlarkComments removes # comments (outside strings) so commented
// -out deps never parse.
func stripStarlarkComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	inStr := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '"' && (i == 0 || src[i-1] != '\\'):
			inStr = !inStr
			b.WriteByte(c)
		case c == '#' && !inStr:
			for i < len(src) && src[i] != '\n' {
				i++
			}
			if i < len(src) {
				b.WriteByte('\n')
			}
		case c == '\n' && inStr:
			// unterminated string on this line (rare triple-quote use):
			// close it off so comment stripping can't eat the rest of file
			inStr = false
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
