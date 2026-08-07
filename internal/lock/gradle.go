package lock

// Gradle's two commit-what-you-resolve files beyond gradle.lockfile:
//
//   - libs.versions.toml (version catalogs): the manifest most Gradle and
//     Android projects actually commit. Renovate and Dependabot bump the
//     catalog directly, so vetting it is what makes lockvet useful on
//     real Gradle PRs — the go.mod / MODULE.bazel precedent. Entries pin
//     exact versions; dynamic versions (1.+, ranges, latest.release) are
//     skipped. Plugins resolve as their Maven plugin-marker coordinate
//     (id:id.gradle.plugin) — the artifact Gradle itself resolves.
//
//   - verification-metadata.xml (dependency verification): per-artifact
//     checksums for everything a build resolves. Diffs of this file are
//     notoriously rubber-stamped walls of XML; lockvet turns them into
//     package changes (full registry treatment) and records the primary
//     artifact's hashes as integrity pins, so a same-version checksum
//     change — the exact tampering the file exists to catch — surfaces
//     as ‼ REPINNED. SNAPSHOT versions mutate legitimately and are
//     never pinned.

import (
	"encoding/xml"
	"regexp"
	"sort"
	"strings"
)

// ---- gradle/libs.versions.toml (Gradle version catalog) ----

var (
	catKeyRe = regexp.MustCompile(`^\s*(?:([A-Za-z0-9._-]+)|"([^"]+)"|'([^']+)')\s*=\s*(.*)$`)
	// module / group / name / id string fields inside an inline table.
	catFieldRe = map[string]*regexp.Regexp{
		"module": regexp.MustCompile(`(?:^|[{,]\s*)module\s*=\s*(?:"([^"]*)"|'([^']*)')`),
		"group":  regexp.MustCompile(`(?:^|[{,]\s*)group\s*=\s*(?:"([^"]*)"|'([^']*)')`),
		"name":   regexp.MustCompile(`(?:^|[{,]\s*)name\s*=\s*(?:"([^"]*)"|'([^']*)')`),
		"id":     regexp.MustCompile(`(?:^|[{,]\s*)id\s*=\s*(?:"([^"]*)"|'([^']*)')`),
	}
	catVerRefRe = regexp.MustCompile(`version\s*\.\s*ref\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	// version = "1.2.3" (the dot-free form; version.ref must not match).
	catVerStrRe = regexp.MustCompile(`(?:^|[{,]\s*)version\s*=\s*(?:"([^"]*)"|'([^']*)')`)
	// version = { strictly = "...", require = "...", prefer = "..." } or
	// the dotted version.strictly = "..." forms.
	catVerRichRe = regexp.MustCompile(`version\s*(?:=\s*\{([^}]*)\}|\.\s*(strictly|require|prefer)\s*=\s*(?:"([^"]*)"|'([^']*)'))`)
	catRichPart  = regexp.MustCompile(`(strictly|require|prefer)\s*=\s*(?:"([^"]*)"|'([^']*)')`)
)

func parseVersionCatalog(p string, data []byte) (*File, error) {
	f := newFile(p, "libs.versions.toml", Maven)

	type entry struct {
		key, raw string
		plugin   bool
	}
	versions := map[string]string{} // [versions] key → declared string
	var entries []entry

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
		m := catKeyRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[1] + m[2] + m[3]
		val := strings.TrimSpace(m[4])
		switch section {
		case "versions":
			versions[key] = catalogVersionOf(val)
		case "libraries":
			entries = append(entries, entry{key: key, raw: val})
		case "plugins":
			entries = append(entries, entry{key: key, raw: val, plugin: true})
		}
	}

	resolve := func(raw string) string {
		if r := catVerRefRe.FindStringSubmatch(raw); r != nil {
			return versions[r[1]+r[2]]
		}
		return catalogVersionOf(raw)
	}

	for _, e := range entries {
		var name, version string
		if !strings.HasPrefix(e.raw, "{") {
			// String shorthand: "group:artifact:version" / "plugin.id:version".
			s := tomlString(e.raw)
			parts := strings.Split(s, ":")
			switch {
			case e.plugin && len(parts) == 2:
				name, version = pluginMarker(parts[0]), parts[1]
			case !e.plugin && len(parts) == 3:
				name, version = parts[0]+":"+parts[1], parts[2]
			}
		} else {
			if e.plugin {
				if id := catField(e.raw, "id"); id != "" {
					name = pluginMarker(id)
				}
			} else if mod := catField(e.raw, "module"); mod != "" {
				if parts := strings.Split(mod, ":"); len(parts) == 2 {
					name = parts[0] + ":" + parts[1]
				}
			} else if g, n := catField(e.raw, "group"), catField(e.raw, "name"); g != "" && n != "" {
				name = g + ":" + n
			}
			version = resolve(e.raw)
		}
		if name == "" || !exactCatalogVersion(version) {
			continue
		}
		f.add(name, version)
	}

	// Every catalog entry is a version the project declares directly.
	for name := range f.Packages {
		f.Roots = append(f.Roots, name)
	}
	sort.Strings(f.Roots)
	f.RootsKnown = len(f.Roots) > 0
	return f, nil
}

// catalogVersionOf extracts the declared version from a [versions] value
// or an inline-table library/plugin value: a plain string, a rich
// version = { strictly/require/prefer } table (first of strictly,
// require, prefer wins — Gradle's precedence), or the dotted
// version.strictly = "..." form. Returns "" when nothing exact appears.
func catalogVersionOf(raw string) string {
	if !strings.HasPrefix(raw, "{") {
		return tomlString(raw)
	}
	m := catVerRichRe.FindStringSubmatch(raw)
	if m == nil {
		if s := catVerStrRe.FindStringSubmatch(raw); s != nil {
			return s[1] + s[2]
		}
		return ""
	}
	if m[2] != "" { // dotted version.strictly = "..."
		return m[3] + m[4]
	}
	got := map[string]string{}
	for _, part := range catRichPart.FindAllStringSubmatch(m[1], -1) {
		if _, dup := got[part[1]]; !dup {
			got[part[1]] = part[2] + part[3]
		}
	}
	for _, k := range []string{"strictly", "require", "prefer"} {
		if v := got[k]; v != "" {
			return v
		}
	}
	return ""
}

func catField(raw, field string) string {
	if m := catFieldRe[field].FindStringSubmatch(raw); m != nil {
		return m[1] + m[2]
	}
	return ""
}

// pluginMarker is the Maven coordinate of a Gradle plugin's marker
// artifact — what Gradle actually resolves for a plugins-block id.
func pluginMarker(id string) string {
	if id == "" {
		return ""
	}
	return id + ":" + id + ".gradle.plugin"
}

// exactCatalogVersion accepts only exact pins: no ranges ([1.0,2.0)),
// no dynamic versions (1.+, latest.release — both lack the shape below
// or carry '+'), no empty strings.
func exactCatalogVersion(v string) bool {
	if v == "" || strings.HasPrefix(v, ".") {
		return false
	}
	digit := false
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return digit
}

// tomlString unquotes a basic or literal TOML string value; anything
// else (arrays, tables, numbers) returns "".
func tomlString(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) >= 2 {
		if (raw[0] == '"' && raw[len(raw)-1] == '"') || (raw[0] == '\'' && raw[len(raw)-1] == '\'') {
			return raw[1 : len(raw)-1]
		}
	}
	return ""
}

// stripTOMLComment removes a # comment that starts outside any quoted
// string.
func stripTOMLComment(line string) string {
	inStr := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inStr != 0:
			if c == inStr {
				inStr = 0
			}
		case c == '"' || c == '\'':
			inStr = c
		case c == '#':
			return strings.TrimSpace(line[:i])
		}
	}
	return line
}

// ---- gradle/verification-metadata.xml (Gradle dependency verification) ----

type vmHash struct {
	Value     string `xml:"value,attr"`
	AlsoTrust []struct {
		Value string `xml:"value,attr"`
	} `xml:"also-trust"`
}

type vmArtifact struct {
	Name   string `xml:"name,attr"`
	MD5    vmHash `xml:"md5"`
	SHA1   vmHash `xml:"sha1"`
	SHA256 vmHash `xml:"sha256"`
	SHA512 vmHash `xml:"sha512"`
}

type vmComponent struct {
	Group     string       `xml:"group,attr"`
	Name      string       `xml:"name,attr"`
	Version   string       `xml:"version,attr"`
	Artifacts []vmArtifact `xml:"artifact"`
}

type vmDoc struct {
	Components struct {
		Component []vmComponent `xml:"component"`
	} `xml:"components"`
}

func parseVerificationMetadata(p string, data []byte) (*File, error) {
	f := newFile(p, "verification-metadata.xml", Maven)
	var doc vmDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	for _, c := range doc.Components.Component {
		if c.Group == "" || c.Name == "" || c.Version == "" {
			continue
		}
		name := c.Group + ":" + c.Name
		f.add(name, c.Version)
		// SNAPSHOT artifacts mutate legitimately: no integrity pin.
		if strings.Contains(strings.ToUpper(c.Version), "SNAPSHOT") {
			continue
		}
		if hashes := vmHashSet(c); hashes != "" {
			f.setPin(name, c.Version, hashes, "")
		}
	}
	return f, nil
}

// vmHashSet renders every artifact's checksums in the pins notation,
// scoped per file ("core-1.8.0.aar#sha256:…"): Gradle records several
// artifacts per component and routinely ADDS entries when a new
// configuration resolves another variant — only the SAME file changing
// its accepted hashes is tampering (the per-scoped-label rule in the
// pins comparison). also-trust alternates stay in the same set, so
// adding one never flags.
func vmHashSet(c vmComponent) string {
	var out []string
	for _, a := range c.Artifacts {
		if a.Name == "" || strings.ContainsAny(a.Name, "# ") {
			continue
		}
		collect := func(algo string, h vmHash) {
			if v := strings.ToLower(strings.TrimSpace(h.Value)); v != "" {
				out = append(out, a.Name+"#"+algo+":"+v)
			}
			for _, at := range h.AlsoTrust {
				if v := strings.ToLower(strings.TrimSpace(at.Value)); v != "" {
					out = append(out, a.Name+"#"+algo+":"+v)
				}
			}
		}
		collect("md5", a.MD5)
		collect("sha1", a.SHA1)
		collect("sha256", a.SHA256)
		collect("sha512", a.SHA512)
	}
	return strings.Join(out, " ")
}
