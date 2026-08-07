package lock

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func unsafeString(s string) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl)
}

// FuzzAllParsers feeds arbitrary bytes to every registered parser.
// Parsers may return errors, but must never panic or hang.
func FuzzAllParsers(f *testing.F) {
	seeds := []string{
		"",
		"{}",
		"[]",
		"null",
		"{\"packages\":{\"node_modules/a\":{\"version\":\"1.0.0\"}}}",
		"[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n",
		"a==1.0.0\n# comment\n-r other.txt\n",
		"module m\n\ngo 1.24\n\nrequire (\n\tgithub.com/a/b v1.2.3\n)\n",
		"GEM\n  remote: https://rubygems.org/\n  specs:\n    rake (13.0.6)\n",
		"%{\n  \"plug\": {:hex, :plug, \"1.14.0\", \"abc\", [:mix], [], \"hexpm\"},\n}\n",
		"packages:\n  http:\n    dependency: \"direct main\"\n    version: \"1.2.0\"\n",
		"org.example:lib:1.0=classpath\nempty=\n",
		"lockfileVersion: '9.0'\npackages:\n  /a@1.0.0:\n    resolution: {}\n",
		"\"a@^1.0.0\":\n  version \"1.0.1\"\n",
		"\x00\xff\xfe garbage \x80",
		"{\"version\":2,\"dependencies\":{\"net6.0\":{\"A\":{\"type\":\"Direct\",\"resolved\":\"1.0.0\"}}}}",
		"{\"pins\":[{\"identity\":\"swift-nio\",\"location\":\"https://github.com/apple/swift-nio.git\",\"state\":{\"version\":\"2.0.0\"}}]}",
		"{\"bomFormat\":\"CycloneDX\",\"components\":[{\"bom-ref\":\"a\",\"purl\":\"pkg:npm/a@1.0.0\"}],\"dependencies\":[{\"ref\":\"a\",\"dependsOn\":[\"a\"]}]}",
		"{\"spdxVersion\":\"SPDX-2.3\",\"packages\":[{\"SPDXID\":\"p\",\"externalRefs\":[{\"referenceType\":\"purl\",\"referenceLocator\":\"pkg:apk/alpine/musl@1.2.4-r2?distro=alpine-3.18.4\"}]}]}",
		"version: 7\npackages:\n- conda: https://x/a-1.0-b_0.conda\n  depends:\n  - b >=1\n- pypi: https://x/c-2.0-py3-none-any.whl\n  name: c\n  version: '2.0'\n  requires_dist:\n  - d>=1\n",
		"version: 4\npackages:\n- kind: conda\n  name: a\n  version: '1.0'\n  depends:\n  - b 1.0 x\n",
		"version: 1\npackage:\n- name: a\n  version: '1.0'\n  manager: conda\n  dependencies:\n    b: '>=1'\n  hash:\n    md5: x\n",
		"{\"version\":\"0.5\",\"requires\":[\"zlib/1.3.1#abc%123.4\",\"pkg/1.0@user/ch\"]}",
		"{\"graph_lock\":{\"nodes\":{\"0\":{\"requires\":[\"1\"]},\"1\":{\"ref\":\"a/1.0#r\",\"requires\":[]}}},\"version\":\"0.4\"}",
		"jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: \"o/r/sub@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\" # v1\n",
		"{\"lockFileVersion\":28,\"registryFileHashes\":{\"https://bcr.bazel.build/modules/a/1.0/source.json\":\"ab\"},\"selectedYankedVersions\":{\"a@1.0\":\"why\"}}",
		"{\"lockFileVersion\":3,\"moduleDepGraph\":{\"<root>\":{\"deps\":{\"a\":\"a@1.0\"}},\"a@1.0\":{\"name\":\"a\",\"version\":\"1.0\",\"deps\":{},\"repoSpec\":{\"ruleClassName\":\"http_archive\",\"attributes\":{\"integrity\":\"sha256-x=\"}}}}}",
		"bazel_dep(name = \"rules_java\", version = \"8.6.1\")\nsingle_version_override(\n    module_name = \"rules_java\",\n    version = \"9.0.0\",\n)\n# bazel_dep(name = \"x\", version = \"1\")\n",
		"[versions]\nagp = \"8.1.1\"\n[libraries]\na = { module = \"g:n\", version.ref = \"agp\" }\nb = \"g:n2:1.0\"\n[plugins]\np = { id = \"x.y\", version = { strictly = \"1.0\" } }\n",
		"lock-version = \"1.0\"\ncreated-by = \"uv\"\n\n[[packages]]\nname = \"a\"\nversion = \"1.0\"\nindex = \"https://pypi.org/simple/\"\nwheels = [\n{ url = \"https://x/a.whl\", hashes = { sha256 = \"00dca57bca26fa62a6d7d0\" } },\n]\n",
		"lock-version = \"1.0\"\n[[packages]]\nname = \"b\"\nversion = \"2.0\"\n[[packages.wheels]]\nname = \"b.whl\"\nurl = \"https://x/b.whl\"\n[packages.wheels.hashes]\nsha256 = \"13f3eecb844759ab66efec\"\n[[packages]]\nname = \"c\"\n[packages.vcs]\nurl = \"https://github.com/x/c\"\n",
		"<verification-metadata><components><component group=\"g\" name=\"n\" version=\"1.0\"><artifact name=\"n-1.0.jar\"><sha256 value=\"ab\"/></artifact></component></components></verification-metadata>",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	names := KnownBasenames()
	names = append(names, ".github/workflows/ci.yml")
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, base := range names {
			p := ByBasename(base)
			if p == nil {
				t.Fatalf("no parser for %s", base)
			}
			file, err := p.Parse(base, data)
			if err != nil {
				continue
			}
			if file == nil {
				t.Fatalf("%s: nil file with nil error", base)
			}
			for name, versions := range file.Packages {
				if name == "" {
					t.Errorf("%s: empty package name accepted", base)
				}
				if unsafeString(name) {
					t.Errorf("%s: unsafe name %q", base, name)
				}
				for _, v := range versions {
					if unsafeString(v) {
						t.Errorf("%s: unsafe version %q for %q", base, v, name)
					}
				}
			}
		}
	})
}
