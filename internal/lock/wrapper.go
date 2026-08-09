package lock

// Build-tool wrapper properties: gradle-wrapper.properties and
// maven-wrapper.properties. The wrapper scripts committed to a repo
// download the build tool itself from the URL pinned in these files —
// which makes them lockfiles for the single most powerful dependency a
// build has, and a classic supply-chain target: point distributionUrl at
// a lookalike host, or swap distributionSha256Sum alongside a poisoned
// mirror, and every developer and CI machine runs the attacker's build
// tool. Renovate and Dependabot bump these files routinely; almost
// nobody reads the diff.
//
//   - gradle/wrapper/gradle-wrapper.properties: distributionUrl pins a
//     Gradle version (gradle-8.10.2-bin.zip); distributionSha256Sum, when
//     present, is an integrity pin the wrapper enforces at download time.
//     Official-host pins are verified against services.gradle.org by the
//     gradlereg layer (ages, broken releases, unlisted versions, and the
//     checksum cross-checked against the one Gradle actually publishes).
//   - .mvn/wrapper/maven-wrapper.properties: distributionUrl and
//     wrapperUrl point into a Maven-repository layout, so the pins are
//     ordinary Maven coordinates (org.apache.maven:apache-maven,
//     org.apache.maven.wrapper:maven-wrapper) and get the full existing
//     Maven treatment (OSV, Central ages, unlisted). distributionSha256Sum
//     and wrapperSha256Sum become integrity pins.
//
// Corporate-mirror hosts are honest NonRegistry: companies re-host both
// distributions internally, and a mirror is not evidence of anything —
// but the offline same-version checksum-swap check still runs, because a
// mirrored artifact is byte-identical to the official one.

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// parseGradleWrapperProps reads gradle-wrapper.properties.
func parseGradleWrapperProps(p string, data []byte) (*File, error) {
	props := parseJavaProperties(data)
	f := newFile(p, "gradle-wrapper.properties", GradleDist)
	distURL := props["distributionUrl"]
	if distURL == "" {
		return f, nil
	}
	u, err := url.Parse(distURL)
	if err != nil || u.Host == "" {
		return f, nil
	}
	ver, ok := gradleDistVersion(u.Path)
	if !ok {
		return f, nil
	}
	const name = "gradle"
	f.add(name, ver)
	f.addRoot(name)
	if !officialGradleHost(u.Host) {
		// Corporate mirror or unknown host: no registry claims. The
		// offline checksum-swap check still applies (mirrors re-host
		// the byte-identical official zips).
		f.markNonRegistry(name)
	}
	if sum, ok := sha256Prop(props["distributionSha256Sum"]); ok {
		f.setPin(name, ver, "sha256:"+sum, u.Host)
	} else {
		f.setPin(name, ver, "", u.Host)
	}
	return f, nil
}

// gradleDistVersion extracts the version from a Gradle distribution
// path: .../gradle-8.10.2-bin.zip, gradle-8.11-rc-1-all.zip, snapshot
// gradle-9.8.0-20260809003445+0000-bin.zip.
var gradleDistRe = regexp.MustCompile(`^gradle-([0-9][^/]*)-(bin|all)\.zip$`)

func gradleDistVersion(path string) (string, bool) {
	seg := path
	if i := strings.LastIndexByte(seg, '/'); i >= 0 {
		seg = seg[i+1:]
	}
	m := gradleDistRe.FindStringSubmatch(seg)
	if m == nil {
		return "", false
	}
	return m[1], true
}

func officialGradleHost(host string) bool {
	switch strings.ToLower(host) {
	case "services.gradle.org", "downloads.gradle.org", "downloads.gradle-dn.com":
		return true
	}
	return false
}

// parseMavenWrapperProps reads maven-wrapper.properties. distributionUrl
// and wrapperUrl point into a Maven-repository layout; the coordinates
// parsed out of them are ordinary Maven packages.
func parseMavenWrapperProps(p string, data []byte) (*File, error) {
	props := parseJavaProperties(data)
	f := newFile(p, "maven-wrapper.properties", Maven)
	addPin := func(rawURL, sumProp string) {
		if rawURL == "" {
			return
		}
		u, err := url.Parse(rawURL)
		if err != nil || u.Host == "" {
			return
		}
		coord, ver, ok := mavenCoordFromPath(u.Path, officialMavenHost(u.Host))
		if !ok {
			return
		}
		f.add(coord, ver)
		f.addRoot(coord)
		if !officialMavenHost(u.Host) {
			f.markNonRegistry(coord)
		}
		if sum, ok := sha256Prop(sumProp); ok {
			f.setPin(coord, ver, "sha256:"+sum, u.Host)
		} else {
			f.setPin(coord, ver, "", u.Host)
		}
	}
	addPin(props["distributionUrl"], props["distributionSha256Sum"])
	addPin(props["wrapperUrl"], props["wrapperSha256Sum"])
	return f, nil
}

func officialMavenHost(host string) bool {
	switch strings.ToLower(host) {
	case "repo.maven.apache.org", "repo1.maven.org", "repo.maven.org":
		return true
	}
	return false
}

// mavenCoordFromPath turns a Maven-repository-layout path into
// "group:artifact" + version. Official Central hosts serve under
// /maven2/, which anchors the group exactly. For mirror hosts the repo
// root is unknown (Nexus/Artifactory prefix segments vary), so known
// non-group prefixes are stripped and the result is only trusted when
// the filename validates against the layout ({artifact}-{version}…).
func mavenCoordFromPath(path string, official bool) (coord, version string, ok bool) {
	path = strings.Trim(path, "/")
	segs := strings.Split(path, "/")
	if official {
		// Anchor at the maven2 root.
		i := 0
		for ; i < len(segs); i++ {
			if segs[i] == "maven2" {
				break
			}
		}
		if i == len(segs) {
			return "", "", false
		}
		segs = segs[i+1:]
	} else {
		// Mirror hosts (Nexus, Artifactory) prefix the layout with
		// arbitrary repository names (/repository/maven-central/…), so
		// anchor at the first segment that looks like the start of a
		// reverse-domain group. No anchor → no claim: better to say
		// nothing than fabricate a coordinate from a mirror path.
		i := -1
		for j, seg := range segs {
			switch strings.ToLower(seg) {
			case "com", "org", "net", "io", "dev", "edu", "gov":
				i = j
			}
			if i >= 0 {
				break
			}
		}
		if i < 0 {
			return "", "", false
		}
		segs = segs[i:]
	}
	if len(segs) < 4 { // group…, artifact, version, filename
		return "", "", false
	}
	file := segs[len(segs)-1]
	version = segs[len(segs)-2]
	artifact := segs[len(segs)-3]
	group := strings.Join(segs[:len(segs)-3], ".")
	if group == "" || version == "" || artifact == "" {
		return "", "", false
	}
	// The filename must follow the layout, or this is not a Maven repo
	// path at all (mirror URLs can be anything).
	if !strings.HasPrefix(file, artifact+"-"+version) {
		return "", "", false
	}
	// Non-official hosts: require a dotted (reverse-domain-shaped) group
	// so a too-short mirror path cannot fabricate a coordinate.
	if !official && !strings.Contains(group, ".") {
		return "", "", false
	}
	return group + ":" + artifact, version, true
}

// sha256Prop validates a *Sha256Sum property value: exactly 64 hex
// characters, normalized to lower case.
func sha256Prop(s string) (string, bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) != 64 {
		return "", false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return "", false
		}
	}
	return s, true
}

// parseJavaProperties reads the java.util.Properties format: key=value
// (or key:value), backslash line continuations, \-escapes including
// \uXXXX, comments starting with # or !.
func parseJavaProperties(data []byte) map[string]string {
	props := map[string]string{}
	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimLeft(strings.TrimSuffix(lines[i], "\r"), " \t\f")
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		// Logical line: trailing single backslash continues onto the
		// next physical line (leading whitespace there is ignored).
		for oddTrailingBackslashes(line) && i+1 < len(lines) {
			i++
			next := strings.TrimLeft(strings.TrimSuffix(lines[i], "\r"), " \t\f")
			line = line[:len(line)-1] + next
		}
		key, val := splitPropertyLine(line)
		if key != "" {
			props[key] = val
		}
	}
	return props
}

func oddTrailingBackslashes(s string) bool {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

// splitPropertyLine separates key from value at the first unescaped
// '=', ':' or whitespace, then unescapes both.
func splitPropertyLine(line string) (key, val string) {
	i := 0
	for ; i < len(line); i++ {
		c := line[i]
		if c == '\\' {
			if i+1 >= len(line) {
				i = len(line)
				break
			}
			i++ // skip escaped char
			continue
		}
		if c == '=' || c == ':' || c == ' ' || c == '\t' || c == '\f' {
			break
		}
	}
	key = unescapeProperty(line[:i])
	if i >= len(line) {
		return key, ""
	}
	rest := strings.TrimLeft(line[i:], " \t\f")
	if rest != "" && (rest[0] == '=' || rest[0] == ':') {
		rest = strings.TrimLeft(rest[1:], " \t\f")
	}
	return key, unescapeProperty(rest)
}

func unescapeProperty(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			if c != '\\' {
				b.WriteByte(c)
			}
			continue
		}
		i++
		switch s[i] {
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 'f':
			b.WriteByte('\f')
		case 'u':
			if i+4 < len(s) {
				var r rune
				if _, err := fmt.Sscanf(s[i+1:i+5], "%04x", &r); err == nil {
					b.WriteRune(r)
					i += 4
					continue
				}
			}
			b.WriteByte('u')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}
