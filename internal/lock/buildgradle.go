package lock

// parseBuildGradle reads Gradle build scripts — build.gradle /
// build.gradle.kts, settings.gradle(.kts), and any other *.gradle(.kts)
// script (buildSrc convention plugins, init scripts, split files like
// dependencies.gradle). For the majority of Gradle projects the build
// script IS the pin file: dependency coordinates carry exact versions
// and Renovate/Dependabot bump them in place, exactly like pom.xml.
//
// Parsed, in either DSL:
//
//   - coordinate string literals "group:artifact:version" anywhere in
//     the script (implementation/api/classpath/force/…, including
//     resolutionStrategy forces and buildscript classpaths — every one
//     of them is a version the build resolves). Classifier/extension
//     suffixes (":sources", "@jar") are stripped; the version segment
//     must be an exact pin.
//   - map / named-argument form: group: 'g', name: 'a', version: 'v'
//     (Groovy) and group = "g", name = "a", version = "v" (Kotlin),
//     when the three appear on one line — the shape bots write.
//   - plugins blocks: id("org.jmailen.kotlinter") version "5.2.0" and
//     kotlin("jvm") version "2.2.10" resolve as their Maven
//     plugin-marker coordinate (id:id.gradle.plugin), like the version
//     catalog parser.
//
// Interpolated versions ("io.grpc:grpc-api:$grpcVersion") resolve
// against literal single-file assignments (ext.grpcVersion = "1.66.0",
// def/val forms, extra["…"] = "…", set("…", "…")) — the everyday
// Android layout. Anything still unresolved claims nothing: versions
// defined in gradle.properties or a parent project are out of this
// file's sight and lockvet does not guess. Dynamic versions (1.+,
// latest.release, ranges) are skipped; SNAPSHOT versions stay
// NonRegistry. Comments are stripped string-aware first, so a
// coordinate in a commented-out line never counts.

import (
	"regexp"
	"sort"
	"strings"
)

var (
	// "group:artifact:version[:classifier][@ext]" string literals. The
	// version segment must start with a digit — that is what separates a
	// dependency coordinate from arbitrary colon-joined prose.
	gradleCoordRe = regexp.MustCompile(`['"]([A-Za-z0-9._-]+):([A-Za-z0-9._-]+):([^'":\s]+)(?::[A-Za-z0-9._-]+)?(?:@[A-Za-z0-9._-]+)?['"]`)

	// Map-style / named-argument components, one line.
	gradleKVGroupRe   = regexp.MustCompile(`(?:^|[\s,(])group\s*[:=]\s*['"]([^'"$]+)['"]`)
	gradleKVNameRe    = regexp.MustCompile(`(?:^|[\s,(])name\s*[:=]\s*['"]([^'"$]+)['"]`)
	gradleKVVersionRe = regexp.MustCompile(`(?:^|[\s,(])version\s*[:=]\s*['"]([^'"$]+)['"]`)

	// plugins-block entries with an inline version.
	gradlePluginIDRe     = regexp.MustCompile(`\bid\s*\(?\s*['"]([A-Za-z0-9._-]+)['"]\s*\)?\s+version\s+['"]([^'"]+)['"]`)
	gradlePluginKotlinRe = regexp.MustCompile(`\bkotlin\s*\(\s*['"]([A-Za-z0-9.-]+)['"]\s*\)\s+version\s+['"]([^'"]+)['"]`)

	// Single-file version property assignments, both DSLs:
	//   ext.grpcVersion = '1.66.0' | def v = "1" | val v = "1" | v = '1'
	//   extra["grpcVersion"] = "1.66.0" | set("grpcVersion", "1.66.0")
	gradleAssignRe = regexp.MustCompile(`(?:^|[\s.{(])(?:ext\.|extra\.)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]([^'"$]+)['"]`)
	gradleExtraRe  = regexp.MustCompile(`\b(?:extra|ext)\s*\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\]\s*=\s*['"]([^'"$]+)['"]`)
	gradleSetRe    = regexp.MustCompile(`\bset\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*,\s*['"]([^'"$]+)['"]\s*\)`)

	// $var / ${var} / ${project.ext.var} — the whole version segment.
	gradleInterpRe = regexp.MustCompile(`^\$\{?([A-Za-z_][A-Za-z0-9_.]*)\}?$`)
)

func parseBuildGradle(p string, data []byte) (*File, error) {
	f := newFile(p, "build.gradle", Maven)
	src := stripGradleComments(string(data))

	// Pass 1: property assignments for interpolation resolution.
	props := map[string]string{}
	record := func(name, val string) {
		if _, dup := props[name]; !dup {
			props[name] = val
		}
	}
	for _, line := range strings.Split(src, "\n") {
		for _, m := range gradleAssignRe.FindAllStringSubmatch(line, -1) {
			record(m[1], m[2])
		}
		for _, m := range gradleExtraRe.FindAllStringSubmatch(line, -1) {
			record(m[1], m[2])
		}
		for _, m := range gradleSetRe.FindAllStringSubmatch(line, -1) {
			record(m[1], m[2])
		}
	}

	resolve := func(v string) string {
		m := gradleInterpRe.FindStringSubmatch(v)
		if m == nil {
			if strings.Contains(v, "$") {
				return "" // partial interpolation — no guessing
			}
			return v
		}
		key := m[1]
		if i := strings.LastIndex(key, "."); i >= 0 {
			key = key[i+1:] // project.ext.grpcVersion → grpcVersion
		}
		return props[key]
	}

	addDep := func(name, version string) {
		version = resolve(version)
		if name == "" || !exactCatalogVersion(version) {
			return
		}
		f.add(name, version)
		if strings.Contains(strings.ToUpper(version), "SNAPSHOT") {
			f.markNonRegistry(name)
		}
	}

	for _, line := range strings.Split(src, "\n") {
		for _, m := range gradlePluginIDRe.FindAllStringSubmatch(line, -1) {
			addDep(pluginMarker(m[1]), m[2])
		}
		for _, m := range gradlePluginKotlinRe.FindAllStringSubmatch(line, -1) {
			addDep(pluginMarker("org.jetbrains.kotlin."+m[1]), m[2])
		}
		for _, m := range gradleCoordRe.FindAllStringSubmatch(line, -1) {
			group, artifact, version := m[1], m[2], m[3]
			if strings.Contains(group, "$") || strings.Contains(artifact, "$") {
				continue
			}
			addDep(group+":"+artifact, version)
		}
		// Named-argument form only when the line carries no coordinate
		// literal (a coordinate match already consumed its parts) and no
		// plugins-block version keyword shape.
		if gradleCoordRe.MatchString(line) || gradlePluginIDRe.MatchString(line) {
			continue
		}
		g := gradleKVGroupRe.FindStringSubmatch(line)
		n := gradleKVNameRe.FindStringSubmatch(line)
		v := gradleKVVersionRe.FindStringSubmatch(line)
		if g != nil && n != nil && v != nil {
			addDep(g[1]+":"+n[1], v[1])
		}
	}

	for name := range f.Packages {
		f.Roots = append(f.Roots, name)
	}
	sort.Strings(f.Roots)
	f.RootsKnown = len(f.Roots) > 0
	return f, nil
}

// stripGradleComments removes // line comments and /* */ block comments
// (nested-free) from Groovy/Kotlin source, string-aware: comment
// markers inside '…', "…", ”'…”' and """…""" strings are kept, and
// URLs (https://…) never open a comment. Newlines are preserved so the
// result stays line-addressable.
func stripGradleComments(src string) string {
	var b strings.Builder
	b.Grow(len(src))
	const (
		code = iota
		lineComment
		blockComment
		sq  // '…'
		dq  // "…"
		tsq // '''…'''
		tdq // """…"""
	)
	state := code
	for i := 0; i < len(src); i++ {
		c := src[i]
		next := byte(0)
		if i+1 < len(src) {
			next = src[i+1]
		}
		switch state {
		case code:
			switch {
			case c == '/' && next == '/':
				state = lineComment
				i++
			case c == '/' && next == '*':
				state = blockComment
				i++
				b.WriteByte(' ')
			case c == '\'' && strings.HasPrefix(src[i:], "'''"):
				state = tsq
				b.WriteString("'''")
				i += 2
			case c == '"' && strings.HasPrefix(src[i:], `"""`):
				state = tdq
				b.WriteString(`"""`)
				i += 2
			case c == '\'':
				state = sq
				b.WriteByte(c)
			case c == '"':
				state = dq
				b.WriteByte(c)
			default:
				b.WriteByte(c)
			}
		case lineComment:
			if c == '\n' {
				state = code
				b.WriteByte(c)
			}
		case blockComment:
			if c == '*' && next == '/' {
				state = code
				i++
			} else if c == '\n' {
				b.WriteByte(c)
			}
		case sq, dq:
			quote := byte('\'')
			if state == dq {
				quote = '"'
			}
			if c == '\\' && next != 0 {
				b.WriteByte(c)
				b.WriteByte(next)
				i++
				continue
			}
			b.WriteByte(c)
			if c == quote {
				state = code
			}
		case tsq:
			if strings.HasPrefix(src[i:], "'''") {
				b.WriteString("'''")
				i += 2
				state = code
			} else {
				b.WriteByte(c)
			}
		case tdq:
			if strings.HasPrefix(src[i:], `"""`) {
				b.WriteString(`"""`)
				i += 2
				state = code
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}
