package lock

import (
	"strings"
	"testing"
)

const miseLockSample = `# mise.lock
[[tools.node]]
version = "20.11.0"
backend = "core:node"

[tools.node.platforms.linux-x64]
checksum = "sha256:a6c213b7a2c3b8b9c0aaf8d7f5b3a5c8d4e2f4a5b6c7d8e9f0a1b2c3d4e5f6a7"
size = 23456789
url = "https://nodejs.org/dist/v20.11.0/node-v20.11.0-linux-x64.tar.xz"

[tools.node.platforms.macos-arm64]
checksum = "blake3:4cf9f2741e6c465ffdb7c26f38056a59e2a2544b51f7cc128ef28337eeae4d8e"

[[tools.ripgrep]]
version = "14.1.1"
backend = "aqua:BurntSushi/ripgrep"
options = { exe = "rg" }

[tools.ripgrep.platforms.linux-x64]
checksum = "sha256:4cf9f2741e6c465ffdb7c26f38056a59e2a2544b51f7cc128ef28337eeae4d8e"

[[tools."npm:prettier"]]
version = "3.3.3"
backend = "npm:prettier"

[[tools.terraform]]
version = "1.5.7"
`

func TestParseMiseLock(t *testing.T) {
	f, err := parseMiseLock("mise.lock", []byte(miseLockSample))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["node"]; len(got) != 1 || got[0] != "20.11.0" {
		t.Fatalf("node: %v", got)
	}
	pin := f.Pin("node", "20.11.0")
	if !strings.Contains(pin.Integrity, "linux-x64#sha256:a6c213b7") ||
		!strings.Contains(pin.Integrity, "macos-arm64#blake3:4cf9f274") {
		t.Fatalf("node pin: %q", pin.Integrity)
	}
	// aqua backend: identity is the repo, options join the pin scope.
	if got := f.Packages["aqua:BurntSushi/ripgrep"]; len(got) != 1 || got[0] != "14.1.1" {
		t.Fatalf("ripgrep: %v (packages: %v)", got, f.Packages)
	}
	pin = f.Pin("aqua:BurntSushi/ripgrep", "14.1.1")
	if !strings.Contains(pin.Integrity, "exe=rg/linux-x64#sha256:") {
		t.Fatalf("ripgrep pin: %q", pin.Integrity)
	}
	// npm backend → real registry package.
	if got := f.Packages["prettier"]; len(got) != 1 || got[0] != "3.3.3" {
		t.Fatalf("prettier: %v", got)
	}
	if f.PkgEco["prettier"] != NPM {
		t.Fatalf("prettier eco: %v", f.PkgEco["prettier"])
	}
	// no backend → table name rides the tool map.
	if got := f.Packages["terraform"]; len(got) != 1 || got[0] != "1.5.7" {
		t.Fatalf("terraform: %v", got)
	}
	if !f.RootsKnown || len(f.Roots) != 4 {
		t.Fatalf("roots: %v", f.Roots)
	}
}

func TestParseMiseLockLegacyChecksums(t *testing.T) {
	data := `[tools.node]
version = "22.11.0"
backend = "core:node"

[tools.node.checksums]
"node-v22.11.0-linux-x64.tar.gz" = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
`
	f, err := parseMiseLock("mise.lock", []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	pin := f.Pin("node", "22.11.0")
	if !strings.Contains(pin.Integrity, "node-v22.11.0-linux-x64.tar.gz#sha256:aaaa") {
		t.Fatalf("legacy pin: %q", pin.Integrity)
	}
}

func TestParseMiseLockHonesty(t *testing.T) {
	data := `[[tools.mytool]]
version = "1.2.3"
backend = "asdf:mise-plugins/mise-mytool"

[tools.mytool.platforms.linux-x64]
checksum = "not-a-checksum"

[[tools.other]]
version = "latest"

[settings]
lockfile = true
`
	f, err := parseMiseLock("mise.lock", []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	// asdf plugin: version row, NonRegistry, no bogus pin.
	name := "asdf:mise-plugins/mise-mytool"
	if got := f.Packages[name]; len(got) != 1 || got[0] != "1.2.3" {
		t.Fatalf("plugin tool: %v", f.Packages)
	}
	if !f.NonRegistry[name] {
		t.Fatalf("plugin tool not NonRegistry")
	}
	if pin := f.Pin(name, "1.2.3"); pin.Integrity != "" {
		t.Fatalf("bogus checksum accepted: %q", pin.Integrity)
	}
	// symbolic version → no row.
	if _, ok := f.Packages["other"]; ok {
		t.Fatalf("symbolic version got a row")
	}
}

// The tamper shape: same version, checksum changed → integrityDiffers via
// the artifact-scoped rule (asserted at the diffx layer by existing pin
// tests; here we just prove the pins land scoped).
func TestMiseLockPinScoping(t *testing.T) {
	old := `[[tools.node]]
version = "20.11.0"
[tools.node.platforms.linux-x64]
checksum = "sha256:` + strings.Repeat("a", 64) + `"
`
	niu := `[[tools.node]]
version = "20.11.0"
[tools.node.platforms.linux-x64]
checksum = "sha256:` + strings.Repeat("b", 64) + `"
[tools.node.platforms.macos-arm64]
checksum = "sha256:` + strings.Repeat("c", 64) + `"
`
	fOld, _ := parseMiseLock("mise.lock", []byte(old))
	fNew, _ := parseMiseLock("mise.lock", []byte(niu))
	if fOld.Pin("node", "20.11.0").Integrity == fNew.Pin("node", "20.11.0").Integrity {
		t.Fatal("pins should differ")
	}
}

// The shape mise actually writes (immich, coder, mise itself): the
// platform subtable is one QUOTED segment containing a dot.
func TestParseMiseLockQuotedPlatformSegment(t *testing.T) {
	data := `[[tools."github:extism/cli"]]
version = "1.6.3"
backend = "github:extism/cli"

[tools."github:extism/cli"."platforms.linux-x64"]
checksum = "sha256:34e7ae9bfded6e2c32dee83f70a4e50d34f9d3e80d1762b09625fe82e214d02d"
url = "https://github.com/extism/cli/releases/download/v1.6.3/extism-v1.6.3-linux-amd64.tar.gz"
`
	f, err := parseMiseLock("mise.lock", []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	name := "github:extism/cli"
	if got := f.Packages[name]; len(got) != 1 || got[0] != "1.6.3" {
		t.Fatalf("packages: %v", f.Packages)
	}
	pin := f.Pin(name, "1.6.3")
	if !strings.Contains(pin.Integrity, "linux-x64#sha256:34e7ae9b") {
		t.Fatalf("pin: %q", pin.Integrity)
	}
}
