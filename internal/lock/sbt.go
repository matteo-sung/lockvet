package lock

// parseSbt reads sbt build definitions — build.sbt (and any *.sbt:
// plugins.sbt, deps.sbt, multi-project *.sbt) plus the project/*.scala
// helper convention (project/Dependencies.scala keeps the version vals
// in many builds). Scala has no npm-style lockfile: the build
// definition IS the pin file — dependency coordinates carry exact
// versions and scala-steward/Renovate bump them in place, exactly like
// pom.xml and build.gradle.
//
// Parsed shapes:
//
//   - "org" %% "artifact" % "1.2.3" — the everyday Scala dependency.
//     %% appends the Scala binary suffix to the artifact name on the
//     registry (cats-core → cats-core_2.13): the suffix is resolved
//     from the same file's scalaVersion := "…" setting. When the file
//     pins no scalaVersion (or pins conflicting ones), the artifact's
//     registry name is unknowable from this file alone — the dependency
//     still gets a version row but claims nothing from registries
//     (NonRegistry), because guessing a suffix could pin advisories to
//     the wrong artifact.
//   - "org" % "artifact" % "1.2.3" — Java-style exact coordinates,
//     full treatment always.
//   - addSbtPlugin("org" % "sbt-thing" % "1.2.3") — sbt plugins
//     publish to Maven Central under the sbt cross-suffix
//     (sbt-thing_2.12_1.0 for the sbt 1.x line, which is what every
//     current build runs). If a given plugin predates Central
//     publishing, the suffixed artifact is simply unknown to the
//     registry and the deps.dev/Central layers already treat unknown
//     packages as claim-free — wrong guesses stay silent, right ones
//     get ages, advisories and unlisted checks.
//   - cross CrossVersion.full / .cross(CrossVersion.for3Use2_13) —
//     the two resolvable cross modifiers map to their documented
//     suffix (_<scalaVersion> and _2.13); any other CrossVersion
//     expression makes the registry name unknowable → NonRegistry.
//   - "%%%" (Scala.js/Native platform artifacts) → the suffix depends
//     on the platform in scope → NonRegistry version rows.
//
// Versions may be string literals or identifiers (val CatsVersion =
// "2.10.0" … % CatsVersion, including dotted Versions.cats forms);
// identifiers resolve against literal val/var/def assignments in the
// same file, anything unresolved claims nothing. Dynamic ("2.+",
// "latest.integration") versions are skipped; SNAPSHOT stays
// NonRegistry. Comments are stripped string-aware first.
//
// parseSbtBuildProps reads project/build.properties: its sbt.version
// pin IS the build-tool pin (scala-steward bumps it everywhere), and
// sbt itself publishes to Maven Central as org.scala-sbt:sbt — so the
// pin gets the full Maven treatment (OSV, ages, unlisted). Files
// without an sbt.version key (ant-style build.properties share the
// basename) parse to an empty file, never a warning.

import (
	"regexp"
	"sort"
	"strings"
)

var (
	// "group" % / %% / %%% "artifact" % <version>, where <version> is a
	// string literal or an identifier. Group/artifact are quoted string
	// literals; the operator run length distinguishes the three forms.
	sbtDepRe = regexp.MustCompile(`"([A-Za-z0-9._-]+)"\s*(%{1,3})\s*"([A-Za-z0-9._-]+)"\s*%\s*(?:"([^"\n]+)"|([A-Za-z_][A-Za-z0-9_.]*))`)

	// addSbtPlugin("org" % "sbt-thing" % <version>) — matched before the
	// generic pass so plugin coordinates get their sbt cross-suffix.
	sbtPluginRe = regexp.MustCompile(`addSbtPlugin\s*\(\s*"([A-Za-z0-9._-]+)"\s*%%?\s*"([A-Za-z0-9._-]+)"\s*%\s*(?:"([^"\n]+)"|([A-Za-z_][A-Za-z0-9_.]*))`)

	// val CatsVersion = "2.10.0" / var / def, optional ": String".
	sbtAssignRe = regexp.MustCompile(`\b(?:val|var|def)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?::\s*String\s*)?=\s*"([^"\n]*)"`)

	// scalaVersion := "3.4.2" (with or without a ThisBuild / prefix);
	// the value may also be a val reference (scalaVersion := scala213).
	sbtScalaVersionRe = regexp.MustCompile(`\bscalaVersion\s*:=\s*(?:"([^"\n]+)"|([A-Za-z_][A-Za-z0-9_.]*))`)

	// sbt.version = 1.10.7 in project/build.properties.
	sbtVersionPropRe = regexp.MustCompile(`(?m)^\s*sbt\.version\s*=\s*(\S+)\s*$`)
)

// sbtCrossWindow is how far past a dependency triple the cross-modifier
// scan looks (modifiers sit on the same expression, virtually always on
// the same line).
const sbtCrossWindow = 160

func parseSbt(p string, data []byte) (*File, error) {
	f := newFile(p, "build.sbt", Maven)
	src := stripGradleComments(string(data))

	// Pass 1: literal assignments for version-identifier resolution.
	props := map[string]string{}
	for _, m := range sbtAssignRe.FindAllStringSubmatch(src, -1) {
		if _, dup := props[m[1]]; !dup {
			props[m[1]] = m[2]
		}
	}

	// Scala binary suffix from this file's scalaVersion pins. Multiple
	// subprojects may pin different Scala versions in one build.sbt —
	// only a unique binary suffix is trusted.
	fullScala, binSuffix := "", ""
	suffixKnown := false
	for _, m := range sbtScalaVersionRe.FindAllStringSubmatch(src, -1) {
		v := m[1]
		if v == "" && m[2] != "" {
			key := m[2]
			if i := strings.LastIndex(key, "."); i >= 0 {
				key = key[i+1:]
			}
			v = props[key]
		}
		if v == "" || strings.Contains(v, "$") {
			continue
		}
		s := scalaBinarySuffix(v)
		if s == "" {
			continue
		}
		if !suffixKnown {
			fullScala, binSuffix, suffixKnown = v, s, true
		} else if s != binSuffix {
			binSuffix = "" // conflicting pins — unknowable
			fullScala = ""
		} else if v != fullScala {
			fullScala = "" // same binary line, different patch — full unknowable
		}
	}

	resolve := func(lit, ident string) string {
		if ident == "" {
			if strings.Contains(lit, "$") {
				return "" // interpolated s"…" style — no guessing
			}
			return lit
		}
		key := ident
		if i := strings.LastIndex(key, "."); i >= 0 {
			key = key[i+1:] // Versions.cats → cats
		}
		return props[key]
	}

	addDep := func(name, version string, nonRegistry bool) {
		if name == "" || !exactCatalogVersion(version) {
			return
		}
		f.add(name, version)
		if nonRegistry || strings.Contains(strings.ToUpper(version), "SNAPSHOT") {
			f.markNonRegistry(name)
		}
	}

	// sbt plugins first; their spans are excluded from the generic pass.
	type span struct{ lo, hi int }
	var pluginSpans []span
	for _, ix := range sbtPluginRe.FindAllStringSubmatchIndex(src, -1) {
		pluginSpans = append(pluginSpans, span{ix[0], ix[1]})
		group := src[ix[2]:ix[3]]
		artifact := src[ix[4]:ix[5]]
		lit, ident := "", ""
		if ix[6] >= 0 {
			lit = src[ix[6]:ix[7]]
		}
		if ix[8] >= 0 {
			ident = src[ix[8]:ix[9]]
		}
		addDep(group+":"+artifact+"_2.12_1.0", resolve(lit, ident), false)
	}

	for _, ix := range sbtDepRe.FindAllStringSubmatchIndex(src, -1) {
		inPlugin := false
		for _, s := range pluginSpans {
			if ix[0] >= s.lo && ix[0] < s.hi {
				inPlugin = true
				break
			}
		}
		if inPlugin {
			continue
		}
		group := src[ix[2]:ix[3]]
		op := src[ix[4]:ix[5]]
		artifact := src[ix[6]:ix[7]]
		lit, ident := "", ""
		if ix[8] >= 0 {
			lit = src[ix[8]:ix[9]]
		}
		if ix[10] >= 0 {
			ident = src[ix[10]:ix[11]]
		}
		version := resolve(lit, ident)

		// Cross modifiers trailing the expression.
		tail := src[ix[1]:]
		if nl := strings.IndexByte(tail, '\n'); nl >= 0 && nl < sbtCrossWindow {
			tail = tail[:nl]
		} else if len(tail) > sbtCrossWindow {
			tail = tail[:sbtCrossWindow]
		}
		cross := ""
		if strings.Contains(tail, "CrossVersion") {
			switch {
			case strings.Contains(tail, "CrossVersion.full"):
				cross = "full"
			case strings.Contains(tail, "CrossVersion.for3Use2_13"):
				cross = "_2.13"
			case strings.Contains(tail, "CrossVersion.for2_13Use3"):
				cross = "_3"
			default:
				cross = "?" // binary/partial/custom — leave as written
			}
		}

		name, nonRegistry := "", false
		switch {
		case op == "%" && cross == "":
			name = group + ":" + artifact
		case op == "%" && cross == "full":
			// addCompilerPlugin style: artifact_<full scala version>.
			if fullScala != "" {
				name = group + ":" + artifact + "_" + fullScala
			} else {
				name, nonRegistry = group+":"+artifact, true
			}
		case op == "%%" && cross == "" && binSuffix != "":
			name = group + ":" + artifact + binSuffix
		case cross == "_2.13" || cross == "_3":
			name = group + ":" + artifact + cross
		default:
			// %%% (platform suffix unknown), %% without a resolvable
			// scalaVersion, or an unresolvable cross expression.
			name, nonRegistry = group+":"+artifact, true
		}
		addDep(name, version, nonRegistry)
	}

	for name := range f.Packages {
		f.Roots = append(f.Roots, name)
	}
	sort.Strings(f.Roots)
	f.RootsKnown = len(f.Roots) > 0
	return f, nil
}

// scalaBinarySuffix maps a full Scala version to the artifact suffix
// its ecosystem publishes under: 3.x → _3, 2.13.x → _2.13, ….
func scalaBinarySuffix(v string) string {
	parts := strings.SplitN(v, ".", 3)
	switch {
	case parts[0] == "3":
		return "_3"
	case parts[0] == "2" && len(parts) >= 2:
		minor := parts[1]
		for _, r := range minor {
			if r < '0' || r > '9' {
				return ""
			}
		}
		if minor == "" {
			return ""
		}
		return "_2." + minor
	}
	return ""
}

// parseSbtBuildProps reads project/build.properties. Only the
// sbt.version key claims anything; other build.properties files (ant
// projects use the basename freely) parse to an empty file.
func parseSbtBuildProps(p string, data []byte) (*File, error) {
	f := newFile(p, "build.properties", Maven)
	if m := sbtVersionPropRe.FindSubmatch(data); m != nil {
		v := strings.TrimSpace(string(m[1]))
		if exactCatalogVersion(v) {
			f.add("org.scala-sbt:sbt", v)
			f.Roots = []string{"org.scala-sbt:sbt"}
			f.RootsKnown = true
		}
	}
	return f, nil
}

// isSbtProjectScalaPath reports whether p is a *.scala file under a
// project/ directory segment — sbt's build-definition area, where the
// Dependencies.scala convention keeps coordinates and version vals.
func isSbtProjectScalaPath(p string) bool {
	q := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	if !strings.HasSuffix(q, ".scala") {
		return false
	}
	for _, seg := range strings.Split(q, "/") {
		if seg == "project" {
			return true
		}
	}
	return false
}
