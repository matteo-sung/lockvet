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
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	names := KnownBasenames()
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
