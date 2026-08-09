package lock

// parsePomXML reads Maven's pom.xml — the manifest that IS the pin file
// for most Java projects (Maven has no npm-style lockfile; versions in a
// POM are exact, and Dependabot/Renovate bump them in place). Parsed:
//
//   - <dependencies> and <dependencyManagement> entries with explicit
//     versions (BOM imports included — bumping a junit-bom or
//     spring-boot-dependencies import is the everyday Renovate shape),
//   - <parent> (spring-boot-starter-parent bumps are the single most
//     common Java dependency PR),
//   - <build><plugins>, <pluginManagement> and <extensions> (default
//     groupId org.apache.maven.plugins, per Maven itself),
//   - the same blocks inside <profiles>.
//
// ${property} references resolve against the POM's own <properties>
// (plus the project.* built-ins); anything still unresolved claims
// nothing. Versions that reference the project's own version
// (${project.version}, ${revision}, ${sha1}, ${changelist}) mark the
// dependency as a reactor sibling — NonRegistry, so no registry claims
// are ever made about internal modules. Ranges ([1.0,2.0)), LATEST/
// RELEASE dynamics and managed (version-less) dependencies are skipped;
// SNAPSHOT and system-scope dependencies stay NonRegistry.

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"
)

type pomDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
}

type pomPlugin struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// pomProps keeps <properties> children as a name→value map.
type pomProps map[string]string

func (m *pomProps) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if *m == nil {
		*m = pomProps{}
	}
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			var val string
			if err := d.DecodeElement(&val, &t); err != nil {
				return err
			}
			(*m)[t.Name.Local] = strings.TrimSpace(val)
		case xml.EndElement:
			if t.Name == start.Name {
				return nil
			}
		}
	}
}

type pomBuild struct {
	Plugins          []pomPlugin `xml:"plugins>plugin"`
	PluginManagement []pomPlugin `xml:"pluginManagement>plugins>plugin"`
	Extensions       []pomPlugin `xml:"extensions>extension"`
}

type pomProfile struct {
	Properties   pomProps `xml:"properties"`
	Dependencies []pomDep `xml:"dependencies>dependency"`
	DepMgmt      []pomDep `xml:"dependencyManagement>dependencies>dependency"`
	Build        pomBuild `xml:"build"`
}

type pomProject struct {
	XMLName xml.Name
	Parent  struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Version    string `xml:"version"`
	} `xml:"parent"`
	GroupID      string       `xml:"groupId"`
	ArtifactID   string       `xml:"artifactId"`
	Version      string       `xml:"version"`
	Properties   pomProps     `xml:"properties"`
	Dependencies []pomDep     `xml:"dependencies>dependency"`
	DepMgmt      []pomDep     `xml:"dependencyManagement>dependencies>dependency"`
	Build        pomBuild     `xml:"build"`
	Profiles     []pomProfile `xml:"profiles>profile"`
}

func parsePomXML(p string, data []byte) (*File, error) {
	f := newFile(p, "pom.xml", Maven)

	var doc pomProject
	if err := decodePomXML(data, &doc); err != nil {
		return nil, err
	}
	if doc.XMLName.Local != "project" {
		// Some other tool's pom.xml (the basename is not exclusively
		// Maven's) — nothing to claim.
		return f, nil
	}

	// Effective coordinates: absent groupId/version inherit the parent's.
	effGroup, effVersion := doc.GroupID, doc.Version
	if effGroup == "" {
		effGroup = doc.Parent.GroupID
	}
	if effVersion == "" {
		effVersion = doc.Parent.Version
	}

	props := pomProps{}
	for k, v := range doc.Properties {
		props[k] = v
	}
	for _, prof := range doc.Profiles {
		for k, v := range prof.Properties {
			if _, dup := props[k]; !dup {
				props[k] = v
			}
		}
	}
	// Built-ins that resolve to the project itself. Referencing any of
	// them in a version means "this reactor's own version".
	self := map[string]bool{
		"project.version": true, "version": true, "pom.version": true,
		"project.parent.version": true, "parent.version": true,
		"revision": true, "sha1": true, "changelist": true,
	}
	props["project.groupId"] = effGroup
	props["groupId"] = effGroup
	props["pom.groupId"] = effGroup
	props["project.artifactId"] = doc.ArtifactID
	props["project.parent.groupId"] = doc.Parent.GroupID
	props["project.parent.artifactId"] = doc.Parent.ArtifactID
	if effVersion != "" {
		props["project.version"] = effVersion
		props["version"] = effVersion
		props["pom.version"] = effVersion
	}
	if doc.Parent.Version != "" {
		props["project.parent.version"] = doc.Parent.Version
		props["parent.version"] = doc.Parent.Version
	}

	type entry struct {
		name, version string
		nonRegistry   bool
	}
	var entries []entry
	addDep := func(group, artifact, version, scope string, defGroup string) {
		if version == "" {
			return // managed elsewhere (parent or BOM) — no claim
		}
		g, _ := pomResolve(group, props, self)
		a, _ := pomResolve(artifact, props, self)
		v, selfRef := pomResolve(version, props, self)
		if g == "" && defGroup != "" {
			g = defGroup
		}
		if g == "" || a == "" || v == "" {
			return // unresolved property or malformed — no claim
		}
		if !pomCoordSafe(g) || !pomCoordSafe(a) || !exactCatalogVersion(v) {
			return // ranges, LATEST/RELEASE handled here: brackets/commas fail
		}
		e := entry{name: g + ":" + a, version: v}
		if selfRef || scope == "system" ||
			strings.Contains(strings.ToUpper(v), "SNAPSHOT") {
			// Reactor siblings, system-path jars and snapshots do not
			// come from a release repository.
			e.nonRegistry = true
		}
		entries = append(entries, e)
	}

	collect := func(deps []pomDep, plugins ...[]pomPlugin) {
		for _, d := range deps {
			addDep(d.GroupID, d.ArtifactID, d.Version, strings.TrimSpace(d.Scope), "")
		}
		for _, ps := range plugins {
			for _, pl := range ps {
				addDep(pl.GroupID, pl.ArtifactID, pl.Version, "", "org.apache.maven.plugins")
			}
		}
	}

	if doc.Parent.GroupID != "" && doc.Parent.ArtifactID != "" {
		addDep(doc.Parent.GroupID, doc.Parent.ArtifactID, doc.Parent.Version, "", "")
	}
	collect(doc.Dependencies, doc.Build.Plugins, doc.Build.PluginManagement, doc.Build.Extensions)
	collect(doc.DepMgmt)
	for _, prof := range doc.Profiles {
		collect(prof.Dependencies, prof.Build.Plugins, prof.Build.PluginManagement)
		collect(prof.DepMgmt)
	}

	for _, e := range entries {
		f.add(e.name, e.version)
		if e.nonRegistry {
			f.markNonRegistry(e.name)
		}
	}
	// Everything in a POM is declared directly by this project.
	for name := range f.Packages {
		f.Roots = append(f.Roots, name)
	}
	sort.Strings(f.Roots)
	f.RootsKnown = len(f.Roots) > 0
	return f, nil
}

// pomResolve substitutes ${property} references (up to a fixed depth) and
// reports whether any reference resolved through the project's own
// version. Anything still containing ${ after substitution returns "".
func pomResolve(s string, props pomProps, self map[string]bool) (string, bool) {
	s = strings.TrimSpace(s)
	selfRef := false
	for i := 0; i < 10 && strings.Contains(s, "${"); i++ {
		start := strings.Index(s, "${")
		end := strings.Index(s[start:], "}")
		if end < 0 {
			return "", selfRef
		}
		key := strings.TrimSpace(s[start+2 : start+end])
		if self[key] {
			selfRef = true
		}
		val, ok := props[key]
		if !ok || val == "" {
			return "", selfRef
		}
		s = s[:start] + val + s[start+end+1:]
	}
	if strings.Contains(s, "${") {
		return "", selfRef
	}
	return s, selfRef
}

// pomCoordSafe mirrors the Maven coordinate charset (letters, digits,
// dots, hyphens, underscores).
func pomCoordSafe(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

// decodePomXML unmarshals a POM tolerating the encodings real POMs
// declare: UTF-8/ASCII pass through, ISO-8859-1/windows-1252 are decoded
// byte-for-byte (latin-1 is a Unicode subset; 1252's extra printables
// only affect free-text fields we never read coordinates from).
func decodePomXML(data []byte, v any) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		switch strings.ToLower(charset) {
		case "utf-8", "utf8", "us-ascii", "ascii":
			return input, nil
		case "iso-8859-1", "latin1", "windows-1252", "cp1252":
			raw, err := io.ReadAll(input)
			if err != nil {
				return nil, err
			}
			var b strings.Builder
			b.Grow(len(raw))
			for _, c := range raw {
				b.WriteRune(rune(c))
			}
			return strings.NewReader(b.String()), nil
		}
		return nil, fmt.Errorf("unsupported XML charset %q", charset)
	}
	return dec.Decode(v)
}
