package lock

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// SBOM support: CycloneDX JSON and SPDX JSON documents are parsed into the
// same File representation as lockfiles. Every package carries its own
// ecosystem (File.PkgEco), derived from its package URL (purl), so one SBOM
// can mix npm, PyPI, Go, Alpine apk packages and more — as container-image
// SBOMs from syft or trivy do.

// parseSBOM sniffs the document format and dispatches.
func parseSBOM(p string, data []byte) (*File, error) {
	var probe struct {
		BOMFormat   string `json:"bomFormat"`
		SPDXVersion string `json:"spdxVersion"`
	}
	_ = json.Unmarshal(data, &probe)
	switch {
	case probe.BOMFormat == "CycloneDX":
		return parseCycloneDX(p, data)
	case strings.HasPrefix(probe.SPDXVersion, "SPDX-"):
		return parseSPDX(p, data)
	}
	return nil, fmt.Errorf("not a CycloneDX or SPDX JSON SBOM (no bomFormat / spdxVersion field)")
}

// ---- CycloneDX ----

type cdxComponent struct {
	BOMRef     string         `json:"bom-ref"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl"`
	Components []cdxComponent `json:"components"`
}

func parseCycloneDX(p string, data []byte) (*File, error) {
	var doc struct {
		Metadata struct {
			Component *cdxComponent `json:"component"`
		} `json:"metadata"`
		Components   []cdxComponent `json:"components"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	f := newFile(p, "CycloneDX SBOM", SBOMEco)

	refName := map[string]string{} // bom-ref -> package name
	var walk func(cs []cdxComponent)
	walk = func(cs []cdxComponent) {
		for _, c := range cs {
			if pu, ok := parsePURL(c.PURL); ok {
				f.addSBOMPkg(pu)
				if c.BOMRef != "" {
					refName[c.BOMRef] = pu.name
				}
			}
			walk(c.Components)
		}
	}
	walk(doc.Components)

	// Dependency graph: refs are bom-refs; keep edges between packages we
	// kept. The metadata component is the SBOM's subject — its dependsOn
	// entries are the direct dependencies.
	rootRef := ""
	if doc.Metadata.Component != nil {
		rootRef = doc.Metadata.Component.BOMRef
	}
	for _, d := range doc.Dependencies {
		from, to := d.Ref, d.DependsOn
		if rootRef != "" && from == rootRef {
			for _, dep := range to {
				if n, ok := refName[dep]; ok {
					f.addRoot(n)
				}
			}
			continue
		}
		fn, ok := refName[from]
		if !ok {
			continue
		}
		for _, dep := range to {
			if tn, ok := refName[dep]; ok {
				f.addEdge(fn, tn)
			}
		}
	}
	return f, nil
}

// ---- SPDX ----

func parseSPDX(p string, data []byte) (*File, error) {
	var doc struct {
		DocumentDescribes []string `json:"documentDescribes"`
		Packages          []struct {
			SPDXID       string `json:"SPDXID"`
			ExternalRefs []struct {
				ReferenceType    string `json:"referenceType"`
				ReferenceLocator string `json:"referenceLocator"`
			} `json:"externalRefs"`
		} `json:"packages"`
		Relationships []struct {
			SPDXElementID      string `json:"spdxElementId"`
			RelatedSPDXElement string `json:"relatedSpdxElement"`
			RelationshipType   string `json:"relationshipType"`
		} `json:"relationships"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	f := newFile(p, "SPDX SBOM", SBOMEco)

	idName := map[string]string{} // SPDXID -> package name
	for _, pkg := range doc.Packages {
		for _, ref := range pkg.ExternalRefs {
			if ref.ReferenceType != "purl" {
				continue
			}
			if pu, ok := parsePURL(ref.ReferenceLocator); ok {
				f.addSBOMPkg(pu)
				idName[pkg.SPDXID] = pu.name
			}
			break
		}
	}

	described := map[string]bool{}
	for _, id := range doc.DocumentDescribes {
		described[id] = true
	}
	for _, r := range doc.Relationships {
		if r.RelationshipType == "DESCRIBES" {
			described[r.RelatedSPDXElement] = true
		}
	}
	for _, r := range doc.Relationships {
		if r.RelationshipType != "DEPENDS_ON" {
			continue
		}
		to, ok := idName[r.RelatedSPDXElement]
		if !ok {
			continue
		}
		if described[r.SPDXElementID] {
			// The described element is the SBOM's subject: its
			// dependencies are the direct ones.
			f.addRoot(to)
			continue
		}
		if from, ok := idName[r.SPDXElementID]; ok {
			f.addEdge(from, to)
		}
	}
	return f, nil
}

// addSBOMPkg records a purl-derived package with its per-package ecosystem.
func (f *File) addSBOMPkg(pu purlInfo) {
	name := Sanitize(pu.name)
	if name == "" || pu.version == "" {
		return
	}
	f.add(pu.name, pu.version)
	if f.PkgEco == nil {
		f.PkgEco = map[string]Ecosystem{}
	}
	if _, ok := f.PkgEco[name]; !ok {
		f.PkgEco[name] = Ecosystem(Sanitize(string(pu.eco)))
	}
}

// ---- purl ----

type purlInfo struct {
	eco     Ecosystem
	name    string
	version string
}

var distroRelease = regexp.MustCompile(`(\d+)(\.\d+)?`)

// parsePURL parses a package URL (https://github.com/package-url/purl-spec)
// into an OSV-compatible ecosystem, package name, and version.
func parsePURL(s string) (purlInfo, bool) {
	rest, ok := strings.CutPrefix(s, "pkg:")
	if !ok {
		return purlInfo{}, false
	}
	rest = strings.TrimPrefix(rest, "//") // tolerate pkg://type/... emitters
	rest = strings.TrimLeft(rest, "/")

	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	var quals url.Values
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		quals, _ = url.ParseQuery(rest[i+1:])
		rest = rest[:i]
	}

	segs := strings.Split(rest, "/")
	if len(segs) < 2 {
		return purlInfo{}, false
	}
	typ := strings.ToLower(segs[0])
	last := segs[len(segs)-1]
	ns := segs[1 : len(segs)-1]

	name, version := last, ""
	if i := strings.LastIndexByte(last, '@'); i >= 0 {
		name, version = last[:i], last[i+1:]
	}
	name = pathUnescape(name)
	version = pathUnescape(version)
	nsParts := make([]string, 0, len(ns))
	for _, n := range ns {
		if n = pathUnescape(n); n != "" {
			nsParts = append(nsParts, n)
		}
	}
	namespace := strings.Join(nsParts, "/")
	if name == "" || version == "" {
		return purlInfo{}, false
	}

	joinNS := func(sep string) string {
		if namespace == "" {
			return name
		}
		return namespace + sep + name
	}

	pu := purlInfo{version: version}
	switch typ {
	case "npm":
		pu.eco, pu.name = NPM, joinNS("/")
	case "cargo":
		pu.eco, pu.name = CratesIO, name
	case "pypi":
		pu.eco, pu.name = PyPI, normalizePyPI(name)
	case "golang":
		pu.eco, pu.name = Go, joinNS("/")
	case "composer":
		pu.eco, pu.name = Packagist, joinNS("/")
	case "gem":
		pu.eco, pu.name = RubyGems, name
	case "hex":
		pu.eco, pu.name = Hex, name
	case "pub":
		pu.eco, pu.name = Pub, name
	case "maven":
		pu.eco, pu.name = Maven, joinNS(":")
	case "nuget":
		pu.eco, pu.name = NuGet, name
	case "swift":
		pu.eco, pu.name = SwiftURL, joinNS("/")
	case "cocoapods":
		pu.eco, pu.name = CocoaPods, name
	case "github":
		pu.eco, pu.name = GitHubActions, joinNS("/")
	case "apk":
		pu.eco, pu.name = distroEco(namespace, quals, "Alpine"), name
	case "deb":
		pu.eco, pu.name = distroEco(namespace, quals, "Debian"), name
	case "rpm":
		pu.eco, pu.name = Ecosystem("RPM"), name
	default:
		// Unknown purl type: keep the package visible in the diff,
		// labeled by its type; no OSV/deps.dev lookups.
		pu.eco, pu.name = Ecosystem(typ), joinNS("/")
	}
	return pu, true
}

// distroEco derives a release-qualified OSV ecosystem for OS packages from
// purl qualifiers, e.g. apk + distro=alpine-3.18.4 -> "Alpine:v3.18",
// deb + distro=debian-12 -> "Debian:12". Without a recognizable release the
// bare label is returned (listed in the diff, no OSV queries).
func distroEco(namespace string, quals url.Values, kind string) Ecosystem {
	ns := strings.ToLower(namespace)
	if kind == "Alpine" && strings.Contains(ns, "wolfi") {
		return Ecosystem("Wolfi") // OSV's Wolfi ecosystem is unqualified
	}
	if kind == "Debian" && ns != "" && !strings.Contains(ns, "debian") {
		// Ubuntu and friends: OSV's release naming is not a simple
		// qualifier mapping, so list without vuln data.
		return Ecosystem(strings.ToUpper(ns[:1]) + ns[1:])
	}
	distro := quals.Get("distro")
	if distro == "" {
		distro = quals.Get("os_version")
	}
	m := distroRelease.FindStringSubmatch(distro)
	if m == nil {
		return Ecosystem(kind)
	}
	switch kind {
	case "Alpine":
		if m[2] == "" {
			return Ecosystem(kind)
		}
		return Ecosystem("Alpine:v" + m[1] + m[2]) // major.minor only
	case "Debian":
		return Ecosystem("Debian:" + m[1]) // major only
	}
	return Ecosystem(kind)
}

func pathUnescape(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// SBOMParser returns the format-sniffing SBOM parser. `lockvet diff` uses it
// for files whose names aren't recognizable lockfile names.
func SBOMParser() *Parser { return &Parser{"sbom", SBOMEco, parseSBOM} }
