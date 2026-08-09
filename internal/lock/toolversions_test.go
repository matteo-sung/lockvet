package lock

import (
	"reflect"
	"testing"
)

func TestParseToolVersions(t *testing.T) {
	data := []byte(`# toolchain
nodejs 22.4.0
python 3.12.4 3.11.9  # fallback listed too
ruby 3.3.4
golang 1.22.5
terraform 1.9.2
java temurin-21.0.2+13.0.LTS
rust nightly
erlang 27.0
direnv system
node lts
gradle 8.10
maven 3.9.8
sbt 1.10.0
npm:prettier 3.3.3
cargo:eza 0.18.0
pipx:Black 24.4.2
gem:rubocop 1.65.0
go:github.com/DarthSim/hivemind 1.1.5
ubi:BurntSushi/ripgrep[exe=rg] 14.1.0
asdf:community/plugin 1.0.0
python ref:main
`)
	f, err := parseToolVersions(".tool-versions", data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"nodejs":                        {"22.4.0"},
		"python":                        {"3.11.9", "3.12.4"},
		"ruby":                          {"3.3.4"},
		"golang":                        {"1.22.5"},
		"terraform":                     {"1.9.2"},
		"java":                          {"temurin-21.0.2+13.0.LTS"},
		"erlang":                        {"27.0"},
		"gradle":                        {"8.10"},
		"org.apache.maven:apache-maven": {"3.9.8"},
		"org.scala-sbt:sbt":             {"1.10.0"},
		"prettier":                      {"3.3.3"},
		"eza":                           {"0.18.0"},
		"black":                         {"24.4.2"},
		"rubocop":                       {"1.65.0"},
		"github.com/DarthSim/hivemind":  {"v1.1.5"},
		"ubi:BurntSushi/ripgrep":        {"14.1.0"},
		"asdf:community/plugin":         {"1.0.0"},
	}
	if !reflect.DeepEqual(f.Packages, want) {
		t.Errorf("Packages = %#v\nwant %#v", f.Packages, want)
	}
	for name, eco := range map[string]Ecosystem{
		"prettier": NPM, "eza": CratesIO, "black": PyPI, "rubocop": RubyGems,
		"github.com/DarthSim/hivemind": Go, "gradle": GradleDist,
		"org.apache.maven:apache-maven": Maven, "org.scala-sbt:sbt": Maven,
	} {
		if f.PkgEco[name] != eco {
			t.Errorf("PkgEco[%s] = %q, want %q", name, f.PkgEco[name], eco)
		}
	}
	if _, ok := f.PkgEco["nodejs"]; ok {
		t.Error("core tools must keep the file-level mise/asdf ecosystem")
	}
	if !f.NonRegistry["asdf:community/plugin"] {
		t.Error("asdf: plugin tools must be NonRegistry")
	}
	if f.NonRegistry["ubi:BurntSushi/ripgrep"] {
		t.Error("ubi: tools are repo-verifiable, not NonRegistry")
	}
	if !f.RootsKnown || len(f.Roots) != len(want) {
		t.Errorf("roots: known=%v n=%d want %d", f.RootsKnown, len(f.Roots), len(want))
	}
}

func TestParseMiseToml(t *testing.T) {
	data := []byte(`min_version = "2024.1.1"
[env]
FOO = "bar"

[tools]
node = "22.4.0"          # comment
python = ["3.12.4", "3.11.9"]
erlang = { version = "26.2.5", flavor = "x" }
"npm:markdownlint-cli2" = "0.13.0"
"cargo:cargo-binstall" = "1.7.4"
terraform = "1.9"
go = "latest"
zig = "0.13.0"

[tools."ubi:sharkdp/fd"]
version = "10.1.0"

[tasks.build]
run = "make"
image = "node:20"
`)
	f, err := parseMiseToml("mise.toml", data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"node":              {"22.4.0"},
		"python":            {"3.11.9", "3.12.4"},
		"erlang":            {"26.2.5"},
		"markdownlint-cli2": {"0.13.0"},
		"cargo-binstall":    {"1.7.4"},
		"terraform":         {"1.9"},
		"zig":               {"0.13.0"},
		"ubi:sharkdp/fd":    {"10.1.0"},
	}
	if !reflect.DeepEqual(f.Packages, want) {
		t.Errorf("Packages = %#v\nwant %#v", f.Packages, want)
	}
	if f.PkgEco["markdownlint-cli2"] != NPM || f.PkgEco["cargo-binstall"] != CratesIO {
		t.Errorf("backend ecos wrong: %#v", f.PkgEco)
	}
}

func TestMiseConfigPath(t *testing.T) {
	for p, want := range map[string]bool{
		".config/mise/config.toml":      true,
		".mise/config.toml":             true,
		"mise/config.toml":              true,
		"config.toml":                   false,
		"site/config.toml":              false,
		"themes/mise-theme/config.toml": false,
	} {
		if got := isMiseConfigPath(p); got != want {
			t.Errorf("isMiseConfigPath(%s) = %v, want %v", p, got, want)
		}
	}
	if pr := ByBasename(".config/mise/config.toml"); pr == nil || pr.Kind != "mise.toml" {
		t.Errorf("ByBasename mise config = %v", pr)
	}
	if pr := ByBasename("site/config.toml"); pr != nil {
		t.Errorf("generic config.toml must not parse, got %v", pr)
	}
	for _, p := range []string{".tool-versions", "a/b/.tool-versions", "mise.toml", ".mise.toml", "mise.local.toml"} {
		if pr := ByBasename(p); pr == nil {
			t.Errorf("ByBasename(%s) = nil", p)
		}
	}
}
