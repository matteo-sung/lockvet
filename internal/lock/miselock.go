package lock

// mise.lock (format #59): mise's own lockfile (`lockfile = true` /
// `mise lock`). Where mise.toml can hold ranges, mise.lock records the
// EXACT resolved version per tool — and, per platform, the sha256/blake3
// checksum of the artifact mise downloads. That makes it the richest
// toolchain pin file there is, and the checksums are integrity pins in
// lockvet's sense: a same-version checksum change means the tool's bytes
// changed without its version changing — the poisoned-download shape —
// and flags ‼ REPINNED. Newly added platforms never flag (artifact-scoped
// comparison, the Gradle verification-metadata rule).
//
// Format (TOML, array-of-tables per tool; older mise wrote single
// tables — both parse):
//
//	[[tools.node]]
//	version = "20.11.0"
//	backend = "core:node"
//
//	[tools.node.platforms.linux-x64]
//	checksum = "sha256:…"
//	url = "https://nodejs.org/dist/…"
//
// The backend string is the tool's real identity and picks the pipeline:
// `core:*` and bare names ride the tool map (repo-tag verification),
// `npm:`/`cargo:`/`pipx:`/`pip:`/`gem:`/`dotnet:`/`go:` are real registry
// packages and get the full registry treatment, `ubi:`/`aqua:`/`github:`/
// `spm:` verify against the named GitHub repo, `asdf:`/`vfox:`/`http:`
// plugins honestly claim nothing. A tool may carry several entries for
// one version (Swift's per-distro tarballs, disambiguated by `options`) —
// options join the pin's artifact scope so distinct artifacts never
// cross-compare.

import (
	"regexp"
	"sort"
	"strings"
)

var miseLockKVRe = regexp.MustCompile(`^(?:"([^"]+)"|'([^']+)'|([A-Za-z0-9_.-]+))\s*=\s*(.+)$`)

// miseLockEntry is one [[tools.NAME]] entry mid-parse.
type miseLockEntry struct {
	table   string // the tools.<name> table key
	version string
	backend string
	opts    map[string]string
	pins    [][2]string // {artifact scope, checksum}
}

// parseMiseLock parses mise.lock.
func parseMiseLock(p string, data []byte) (*File, error) {
	f := newFile(p, "mise.lock", MiseTool)
	var cur *miseLockEntry
	section := "" // "", "entry", "platforms", "checksums", "options"
	plat := ""
	flush := func() {
		miseLockFlush(f, cur)
		cur = nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = stripTOMLComment(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			segs := tomlHeaderSegments(line)
			section, plat = "", ""
			switch {
			case len(segs) == 2 && segs[0] == "tools":
				flush()
				cur = &miseLockEntry{table: segs[1]}
				section = "entry"
			case len(segs) == 3 && segs[0] == "tools" && cur != nil && segs[1] == cur.table:
				switch {
				case segs[2] == "checksums" || segs[2] == "assets":
					section = "checksums"
				case segs[2] == "options":
					section = "options"
				case strings.HasPrefix(segs[2], "platforms."):
					// mise serializes the platform subtable as one quoted
					// segment: [tools."github:extism/cli"."platforms.linux-x64"]
					section, plat = "platforms", strings.TrimPrefix(segs[2], "platforms.")
				}
			case len(segs) == 4 && segs[0] == "tools" && cur != nil && segs[1] == cur.table && segs[2] == "platforms":
				section, plat = "platforms", segs[3]
			default:
				// Anything else ([settings], a different tool's subtable
				// out of order, …) ends the current entry's scope.
				if len(segs) == 0 || segs[0] != "tools" {
					flush()
				}
			}
			continue
		}
		m := miseLockKVRe.FindStringSubmatch(line)
		if m == nil || cur == nil {
			continue
		}
		key := m[1] + m[2] + m[3]
		val := strings.TrimSpace(m[4])
		switch section {
		case "entry":
			switch key {
			case "version":
				cur.version = miseString(val)
			case "backend":
				cur.backend = miseString(val)
			case "options":
				for k, v := range miseInlineTable(val) {
					cur.addOpt(k, v)
				}
			}
		case "options":
			cur.addOpt(key, miseString(val))
		case "platforms":
			if key == "checksum" {
				if h := miseChecksum(miseString(val)); h != "" {
					cur.pins = append(cur.pins, [2]string{plat, h})
				}
			}
		case "checksums":
			// Legacy shape: "asset-file.tar.gz" = "sha256:…".
			if h := miseChecksum(miseString(val)); h != "" {
				cur.pins = append(cur.pins, [2]string{key, h})
			}
		}
	}
	flush()
	finishToolFile(f)
	return f, nil
}

func (e *miseLockEntry) addOpt(k, v string) {
	if k == "" || v == "" {
		return
	}
	if e.opts == nil {
		e.opts = map[string]string{}
	}
	e.opts[k] = v
}

// miseLockFlush records one finished entry on the file: the version row
// (through the same backend→ecosystem mapping mise.toml uses) plus one
// artifact-scoped integrity pin per recorded checksum.
func miseLockFlush(f *File, e *miseLockEntry) {
	if e == nil || e.version == "" {
		return
	}
	tool := e.table
	if e.backend != "" {
		tool = strings.TrimPrefix(e.backend, "core:")
	}
	name, eco, _, ok := ToolEntryEco(tool)
	if !ok || !toolVersionPlain(e.version) {
		return
	}
	addToolEntry(f, tool, []string{e.version})
	version := e.version
	if eco == Go && !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	scopePrefix := miseOptsScope(e.opts)
	for _, pin := range e.pins {
		scope := miseScopeLabel(scopePrefix + pin[0])
		if scope == "" {
			continue
		}
		f.setPin(name, version, scope+"#"+pin[1], "")
	}
}

// miseOptsScope canonicalizes an entry's options into a stable scope
// prefix ("swift_platform=ubuntu24.04/") so same-version entries that
// describe different artifacts never cross-compare.
func miseOptsScope(opts map[string]string) string {
	if len(opts) == 0 {
		return ""
	}
	keys := make([]string, 0, len(opts))
	for k := range opts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+opts[k])
	}
	return strings.Join(parts, ",") + "/"
}

// miseScopeLabel sanitizes an artifact-scope label for the space-joined
// pin notation: labels with whitespace or '#' can't be represented.
func miseScopeLabel(s string) string {
	if s == "" || strings.ContainsAny(s, " \t#") {
		return ""
	}
	return s
}

// miseChecksum validates an "algo:hex" checksum value (sha256:…,
// blake3:…).
func miseChecksum(v string) string {
	algo, hex, ok := strings.Cut(v, ":")
	if !ok || algo == "" || len(algo) > 8 || hex == "" || !isHexString(hex) {
		return ""
	}
	for i := 0; i < len(algo); i++ {
		c := algo[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return ""
		}
	}
	return strings.ToLower(algo) + ":" + strings.ToLower(hex)
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return len(s) > 0
}

// tomlHeaderSegments splits a `[a.b."c.d"]` / `[[a.b]]` table header into
// its dotted key segments, honoring quoted segments.
func tomlHeaderSegments(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "[")
	line = strings.TrimPrefix(line, "[")
	line = strings.TrimSuffix(line, "]")
	line = strings.TrimSuffix(line, "]")
	var segs []string
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				b.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '.':
			segs = append(segs, strings.TrimSpace(b.String()))
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	segs = append(segs, strings.TrimSpace(b.String()))
	return segs
}

// miseInlineTable extracts string key/values from a TOML inline table
// (`{ exe = "rg", matching = "musl" }`). Non-string values are skipped.
func miseInlineTable(val string) map[string]string {
	val = strings.TrimSpace(val)
	if !strings.HasPrefix(val, "{") {
		return nil
	}
	val = strings.Trim(val, "{} \t")
	out := map[string]string{}
	for _, part := range splitTopLevelCommas(val) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		k = strings.Trim(strings.TrimSpace(k), `"'`)
		if s := miseString(strings.TrimSpace(v)); k != "" && s != "" {
			out[k] = s
		}
	}
	return out
}

// splitTopLevelCommas splits on commas that sit outside quotes.
func splitTopLevelCommas(s string) []string {
	var parts []string
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			b.WriteByte(c)
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
			b.WriteByte(c)
		case c == ',':
			parts = append(parts, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	parts = append(parts, b.String())
	return parts
}
