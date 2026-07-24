package lock

import (
	"reflect"
	"testing"
)

func TestParsePURL(t *testing.T) {
	cases := []struct {
		purl    string
		eco     Ecosystem
		name    string
		version string
	}{
		{"pkg:npm/lodash@4.17.21", NPM, "lodash", "4.17.21"},
		{"pkg:npm/%40babel/core@7.24.0", NPM, "@babel/core", "7.24.0"},
		{"pkg:cargo/serde@1.0.200", CratesIO, "serde", "1.0.200"},
		{"pkg:pypi/Flask_Login@0.6.3", PyPI, "flask-login", "0.6.3"},
		{"pkg:golang/github.com/BurntSushi/toml@v1.2.1", Go, "github.com/BurntSushi/toml", "v1.2.1"},
		{"pkg:composer/symfony/console@v6.4.0", Packagist, "symfony/console", "v6.4.0"},
		{"pkg:gem/rails@7.1.3", RubyGems, "rails", "7.1.3"},
		{"pkg:hex/plug@1.15.0", Hex, "plug", "1.15.0"},
		{"pkg:pub/http@1.2.0", Pub, "http", "1.2.0"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1", Maven, "org.apache.logging.log4j:log4j-core", "2.17.1"},
		{"pkg:nuget/Newtonsoft.Json@13.0.3", NuGet, "Newtonsoft.Json", "13.0.3"},
		{"pkg:swift/github.com/apple/swift-nio@2.63.0", SwiftURL, "github.com/apple/swift-nio", "2.63.0"},
		{"pkg:github/actions/checkout@v4", GitHubActions, "actions/checkout", "v4"},
		{"pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=alpine-3.18.4", "Alpine:v3.18", "musl", "1.2.4-r2"},
		{"pkg:apk/alpine/musl@1.2.4-r2", "Alpine", "musl", "1.2.4-r2"},
		{"pkg:apk/wolfi/glibc@2.39-r1?distro=wolfi-20230201", "Wolfi", "glibc", "2.39-r1"},
		{"pkg:deb/debian/curl@7.88.1-10+deb12u5?arch=amd64&distro=debian-12", "Debian:12", "curl", "7.88.1-10+deb12u5"},
		{"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.15?distro=ubuntu-22.04", "Ubuntu", "openssl", "3.0.2-0ubuntu1.15"},
		{"pkg:rpm/redhat/openssl@3.0.7-1?distro=rhel-9.2", "RPM", "openssl", "3.0.7-1"},
		{"pkg:generic/openssl@3.0.13", "generic", "openssl", "3.0.13"},
	}
	for _, c := range cases {
		pu, ok := parsePURL(c.purl)
		if !ok {
			t.Errorf("parsePURL(%q): not ok", c.purl)
			continue
		}
		if pu.eco != c.eco || pu.name != c.name || pu.version != c.version {
			t.Errorf("parsePURL(%q) = (%q, %q, %q), want (%q, %q, %q)",
				c.purl, pu.eco, pu.name, pu.version, c.eco, c.name, c.version)
		}
	}
	for _, bad := range []string{"", "pkg:", "pkg:npm", "npm/lodash@1.0.0", "pkg:npm/lodash"} {
		if _, ok := parsePURL(bad); ok {
			t.Errorf("parsePURL(%q): ok, want reject", bad)
		}
	}
}

const cdxSample = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": {
    "component": {"bom-ref": "root", "type": "application", "name": "myapp"}
  },
  "components": [
    {"bom-ref": "a", "type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
    {"bom-ref": "b", "type": "library", "name": "musl", "version": "1.2.4-r2", "purl": "pkg:apk/alpine/musl@1.2.4-r2?distro=alpine-3.18.4"},
    {"bom-ref": "c", "type": "library", "name": "express", "version": "4.19.2", "purl": "pkg:npm/express@4.19.2",
     "components": [{"bom-ref": "d", "type": "library", "name": "flask", "version": "3.0.0", "purl": "pkg:pypi/Flask@3.0.0"}]},
    {"bom-ref": "os", "type": "operating-system", "name": "alpine", "version": "3.18.4"}
  ],
  "dependencies": [
    {"ref": "root", "dependsOn": ["c"]},
    {"ref": "c", "dependsOn": ["a"]}
  ]
}`

func TestParseCycloneDX(t *testing.T) {
	f, err := parseSBOM("bom.json", []byte(cdxSample))
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != "CycloneDX SBOM" {
		t.Errorf("kind = %q", f.Kind)
	}
	want := map[string][]string{
		"lodash": {"4.17.21"}, "musl": {"1.2.4-r2"},
		"express": {"4.19.2"}, "flask": {"3.0.0"},
	}
	if !reflect.DeepEqual(f.Packages, want) {
		t.Errorf("packages = %v, want %v", f.Packages, want)
	}
	if f.PkgEco["lodash"] != NPM || f.PkgEco["musl"] != "Alpine:v3.18" || f.PkgEco["flask"] != PyPI {
		t.Errorf("PkgEco = %v", f.PkgEco)
	}
	if !f.RootsKnown || len(f.Roots) != 1 || f.Roots[0] != "express" {
		t.Errorf("roots = %v (known=%v)", f.Roots, f.RootsKnown)
	}
	if !reflect.DeepEqual(f.Deps["express"], []string{"lodash"}) {
		t.Errorf("deps = %v", f.Deps)
	}
}

const spdxSample = `{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "documentDescribes": ["SPDXRef-app"],
  "packages": [
    {"SPDXID": "SPDXRef-app", "name": "myapp", "versionInfo": "1.0.0"},
    {"SPDXID": "SPDXRef-p1", "name": "requests", "versionInfo": "2.32.0",
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.32.0"}]},
    {"SPDXID": "SPDXRef-p2", "name": "urllib3", "versionInfo": "2.2.1",
     "externalRefs": [{"referenceCategory": "PACKAGE_MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/urllib3@2.2.1"}]}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-app", "relationshipType": "DESCRIBES"},
    {"spdxElementId": "SPDXRef-app", "relatedSpdxElement": "SPDXRef-p1", "relationshipType": "DEPENDS_ON"},
    {"spdxElementId": "SPDXRef-p1", "relatedSpdxElement": "SPDXRef-p2", "relationshipType": "DEPENDS_ON"}
  ]
}`

func TestParseSPDX(t *testing.T) {
	f, err := parseSBOM("weird-name.json", []byte(spdxSample))
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != "SPDX SBOM" {
		t.Errorf("kind = %q", f.Kind)
	}
	want := map[string][]string{"requests": {"2.32.0"}, "urllib3": {"2.2.1"}}
	if !reflect.DeepEqual(f.Packages, want) {
		t.Errorf("packages = %v, want %v", f.Packages, want)
	}
	if !f.RootsKnown || len(f.Roots) != 1 || f.Roots[0] != "requests" {
		t.Errorf("roots = %v (known=%v)", f.Roots, f.RootsKnown)
	}
	if !reflect.DeepEqual(f.Deps["requests"], []string{"urllib3"}) {
		t.Errorf("deps = %v", f.Deps)
	}
}

func TestParseSBOMRejectsOther(t *testing.T) {
	if _, err := parseSBOM("bom.json", []byte(`{"hello": 1}`)); err == nil {
		t.Error("want error for non-SBOM JSON")
	}
	if _, err := parseSBOM("bom.json", []byte(`not json`)); err == nil {
		t.Error("want error for non-JSON")
	}
}

func TestIsSBOMName(t *testing.T) {
	yes := []string{"bom.json", "sbom.json", "SBOM.json", "app.cdx.json", "image.spdx.json", "x.cyclonedx.json", "cyclonedx.json", "spdx.json"}
	no := []string{"package.json", "bom.xml", "cdx.json", "foo.json", "bom.json.bak"}
	for _, n := range yes {
		if !isSBOMName(n) {
			t.Errorf("isSBOMName(%q) = false, want true", n)
		}
	}
	for _, n := range no {
		if isSBOMName(n) {
			t.Errorf("isSBOMName(%q) = true, want false", n)
		}
	}
}
