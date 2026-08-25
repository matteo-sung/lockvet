package diffx

import (
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/lock"
)

// parse helper: run a real parser so tests exercise the full path.
func parseFile(t *testing.T, name, content string) *lock.File {
	t.Helper()
	pr := lock.ByBasename(name)
	if pr == nil {
		t.Fatalf("no parser for %s", name)
	}
	f, err := pr.Parse(name, []byte(content))
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return f
}

const npmLockTmpl = `{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"left-pad": "^1.3.0"}},
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://%s/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "%s"
    }
  }
}`

func TestIntegrityChangedSameVersion(t *testing.T) {
	oldF := parseFile(t, "package-lock.json", sprintf(npmLockTmpl, "registry.npmjs.org", "sha512-aaaa"))
	newF := parseFile(t, "package-lock.json", sprintf(npmLockTmpl, "registry.npmjs.org", "sha512-bbbb"))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	c := fd.Changes[0]
	if c.Kind != Repinned || !c.IntegrityChanged || len(c.IntegrityVersions) != 1 || c.IntegrityVersions[0] != "1.3.0" {
		t.Fatalf("bad change: %+v", c)
	}
	sum := Summarize([]FileDiff{fd})
	if sum.IntegrityChanged != 1 {
		t.Fatalf("summary: %+v", sum)
	}
}

func TestIntegrityAlgoUpgradeNotFlagged(t *testing.T) {
	// lockfile upgrade sha1 → sha512: no shared algorithm, not comparable
	oldF := parseFile(t, "package-lock.json", sprintf(npmLockTmpl, "registry.npmjs.org", "sha1-aaaa"))
	newF := parseFile(t, "package-lock.json", sprintf(npmLockTmpl, "registry.npmjs.org", "sha512-bbbb"))
	if fd := Diff(oldF, newF); len(fd.Changes) != 0 {
		t.Fatalf("algo upgrade should not flag: %+v", fd.Changes)
	}
}

func TestRegistryMovedFlagsConfusionDirection(t *testing.T) {
	oldF := parseFile(t, "package-lock.json", sprintf(npmLockTmpl, "npm.corp.internal", "sha512-aaaa"))
	newF := parseFile(t, "package-lock.json", sprintf(npmLockTmpl, "registry.npmjs.org", "sha512-bbbb"))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 || !fd.Changes[0].RegistryMoved {
		t.Fatalf("want registry-moved flag: %+v", fd.Changes)
	}
	c := fd.Changes[0]
	if c.OldHost != "npm.corp.internal" || c.NewHost != "registry.npmjs.org" {
		t.Fatalf("hosts: %+v", c)
	}
	// reverse direction (adopting a mirror) must NOT flag
	if fd := Diff(newF, oldF); len(fd.Changes) != 1 || fd.Changes[0].RegistryMoved {
		// integrity still differs → row exists, but no registry flag
		for _, c := range fd.Changes {
			if c.RegistryMoved {
				t.Fatalf("public→private should not flag: %+v", fd.Changes)
			}
		}
	}
}

func TestRegistryMoveSuppressedWhenBytesProvenSame(t *testing.T) {
	oldF := parseFile(t, "package-lock.json", sprintf(npmLockTmpl, "npm.corp.internal", "sha512-aaaa"))
	newF := parseFile(t, "package-lock.json", sprintf(npmLockTmpl, "registry.npmjs.org", "sha512-aaaa"))
	if fd := Diff(oldF, newF); len(fd.Changes) != 0 {
		t.Fatalf("same hash on both hosts is a benign re-point: %+v", fd.Changes)
	}
}

func TestMirrorMigrationSuppressed(t *testing.T) {
	mk := func(host string) string {
		out := `{"lockfileVersion": 3, "packages": {"": {},`
		for _, n := range []string{"a", "b", "c", "d", "e", "f"} {
			out += `"node_modules/` + n + `": {"version": "1.0.0", "resolved": "https://` + host + `/` + n + `.tgz", "integrity": "sha512-` + n + host + `"},`
		}
		return out[:len(out)-1] + "}}"
	}
	oldF := parseFile(t, "package-lock.json", mk("npm.corp.internal"))
	newF := parseFile(t, "package-lock.json", mk("registry.npmjs.org"))
	fd := Diff(oldF, newF)
	for _, c := range fd.Changes {
		if c.RegistryMoved {
			t.Fatalf("6 packages moving between the same hosts is a migration, not an attack: %+v", c)
		}
	}
}

func TestPythonHashSetGrowthNotFlagged(t *testing.T) {
	if integrityDiffers("sha256:aa sha256:bb", "sha256:aa sha256:bb sha256:cc") {
		t.Fatal("adding wheels for an existing release must not flag")
	}
	if !integrityDiffers("sha256:aa sha256:bb", "sha256:cc sha256:dd") {
		t.Fatal("fully disjoint hash sets must flag")
	}
	if integrityDiffers("10c0/abc", "8/abc") { // yarn berry cache-key bump
		t.Fatal("different cache-key namespaces are not comparable")
	}
	if !integrityDiffers("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatal("bare sha1 hex hashes should compare")
	}
}

func TestRepinnedRanksFirst(t *testing.T) {
	if kindRank(Repinned) >= kindRank(Downgraded) {
		t.Fatal("repinned should sort before downgrades")
	}
}

func sprintf(format string, args ...any) string {
	out := format
	for _, a := range args {
		i := indexOf(out, "%s")
		if i < 0 {
			break
		}
		out = out[:i] + a.(string) + out[i+2:]
	}
	return out
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

const flakeLockTmpl = `{
  "nodes": {
    "nixpkgs": {
      "locked": {
        "lastModified": 1720000000,
        "narHash": "%s",
        "owner": "%s",
        "repo": "nixpkgs",
        "rev": "deadbeefcafe1234567890",
        "type": "github"
      }
    },
    "root": {"inputs": {"nixpkgs": "nixpkgs"}}
  },
  "root": "root",
  "version": 7
}`

func TestFlakeNarHashChangeSameRevRepinned(t *testing.T) {
	oldF := parseFile(t, "flake.lock", sprintf(flakeLockTmpl, "sha256-aaaa", "NixOS"))
	newF := parseFile(t, "flake.lock", sprintf(flakeLockTmpl, "sha256-bbbb", "NixOS"))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	c := fd.Changes[0]
	if c.Kind != Repinned || !c.IntegrityChanged {
		t.Errorf("want Repinned+IntegrityChanged, got kind=%s integrity=%v", c.Kind, c.IntegrityChanged)
	}
	if c.SourceRepo != "https://github.com/NixOS/nixpkgs" {
		t.Errorf("SourceRepo = %q", c.SourceRepo)
	}
}

func TestFlakeRepointedRepoSurfacesHosts(t *testing.T) {
	oldF := parseFile(t, "flake.lock", sprintf(flakeLockTmpl, "sha256-aaaa", "NixOS"))
	newLock := sprintf(flakeLockTmpl, "sha256-bbbb", "evilfork")
	newLock = strings.Replace(newLock, "deadbeefcafe1234567890", "0123456789abcdef0123", 1)
	newLock = strings.Replace(newLock, "1720000000", "1720100000", 1)
	newF := parseFile(t, "flake.lock", newLock)
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 change, got %+v", fd.Changes)
	}
	c := fd.Changes[0]
	if c.SourceRepo != "" {
		t.Errorf("re-pointed input must not get a SourceRepo (compare links would lie), got %q", c.SourceRepo)
	}
	if c.OldHost != "github.com/nixos/nixpkgs" || c.NewHost != "github.com/evilfork/nixpkgs" {
		t.Errorf("hosts = %q -> %q", c.OldHost, c.NewHost)
	}
	if !c.RegistryMoved {
		t.Error("re-pointed flake input should flag the resolution-moved lane")
	}
}

func TestFlakeRepointProvenSameBytesQuiet(t *testing.T) {
	// Same rev, same narHash, different owner: content proven identical —
	// a cosmetic mirror switch, not row-worthy.
	oldF := parseFile(t, "flake.lock", sprintf(flakeLockTmpl, "sha256-aaaa", "NixOS"))
	newF := parseFile(t, "flake.lock", sprintf(flakeLockTmpl, "sha256-aaaa", "mirror"))
	if fd := Diff(oldF, newF); len(fd.Changes) != 0 {
		t.Fatalf("proven-identical repoint must stay quiet, got %+v", fd.Changes)
	}
}

func TestFlakeSameLockNoRows(t *testing.T) {
	oldF := parseFile(t, "flake.lock", sprintf(flakeLockTmpl, "sha256-aaaa", "NixOS"))
	newF := parseFile(t, "flake.lock", sprintf(flakeLockTmpl, "sha256-aaaa", "NixOS"))
	if fd := Diff(oldF, newF); len(fd.Changes) != 0 {
		t.Fatalf("identical locks must produce no rows, got %+v", fd.Changes)
	}
}

func TestArtifactScopedIntegrity(t *testing.T) {
	// Gradle verification metadata: hashes scoped per artifact file.
	cases := []struct {
		name     string
		old, new string
		want     bool
	}{
		{"new artifact appears (another variant resolved)",
			"a-1.0.module#sha256:aa a-1.0.pom#sha256:bb",
			"a-1.0.aar#sha256:cc a-1.0.module#sha256:aa a-1.0.pom#sha256:bb", false},
		{"same file loses its hash",
			"a-1.0.aar#sha256:aa a-1.0.pom#sha256:bb",
			"a-1.0.aar#sha256:XX a-1.0.pom#sha256:bb", true},
		{"also-trust added alongside",
			"a-1.0.aar#sha256:aa",
			"a-1.0.aar#sha256:aa a-1.0.aar#sha256:bb", false},
		{"algo upgrade on same file",
			"a-1.0.aar#sha1:aa",
			"a-1.0.aar#sha512:bb", false},
		{"artifact removed entirely",
			"a-1.0.aar#sha256:aa a-1.0.pom#sha256:bb",
			"a-1.0.pom#sha256:bb", false},
	}
	for _, c := range cases {
		if got := integrityDiffers(c.old, c.new); got != c.want {
			t.Errorf("%s: integrityDiffers = %v, want %v", c.name, got, c.want)
		}
	}
}

const goSumOld = `github.com/spf13/cobra v1.8.0 h1:7aJaZx1B85qltLMc546zn58BxxfZdR/W22ej9CFoEf0=
github.com/spf13/cobra v1.8.0/go.mod h1:WXLWApfZ71AjXPya3WOlMsY9yMs7YeiHhFVlvLyhcho=
golang.org/x/text v0.14.0 h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=
golang.org/x/text v0.14.0/go.mod h1:18ZOQIKpY8NJVqYksKHtTdi31H5itFRjB5/qKTNYzSU=
`

func TestGoSumBumpProducesNoRows(t *testing.T) {
	// An ordinary upgrade rewrites go.sum lines wholesale — that story
	// belongs to go.mod's rows; go.sum must stay silent.
	newSum := strings.ReplaceAll(goSumOld, "v0.14.0", "v0.15.0")
	fd := Diff(parseFile(t, "go.sum", goSumOld), parseFile(t, "go.sum", newSum))
	if len(fd.Changes) != 0 {
		t.Fatalf("version churn in go.sum must not produce rows: %+v", fd.Changes)
	}
}

func TestGoSumNewFileProducesNoRows(t *testing.T) {
	fd := Diff(nil, parseFile(t, "go.sum", goSumOld))
	if len(fd.Changes) != 0 {
		t.Fatalf("a brand-new go.sum must not produce rows: %+v", fd.Changes)
	}
}

func TestGoSumSameVersionHashSwapFlags(t *testing.T) {
	// The poisoned-go.sum shape: the version claims nothing moved, but
	// the module hash no longer matches what earlier builds verified.
	newSum := strings.ReplaceAll(goSumOld,
		"h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=",
		"h1:tampered0000000000000000000000000000000000+A=")
	fd := Diff(parseFile(t, "go.sum", goSumOld), parseFile(t, "go.sum", newSum))
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repin, got %+v", fd.Changes)
	}
	c := fd.Changes[0]
	if c.Kind != Repinned || !c.IntegrityChanged || c.Name != "golang.org/x/text" {
		t.Fatalf("bad change: %+v", c)
	}
}

func TestGoSumGoModHashSwapFlags(t *testing.T) {
	// Only the /go.mod manifest hash changes: still a repin (the
	// manifest drives resolution), compared artifact-scoped so it never
	// crosses with the zip hash.
	newSum := strings.ReplaceAll(goSumOld,
		"h1:WXLWApfZ71AjXPya3WOlMsY9yMs7YeiHhFVlvLyhcho=",
		"h1:tampered000000000000000000000000000000000000=")
	fd := Diff(parseFile(t, "go.sum", goSumOld), parseFile(t, "go.sum", newSum))
	if len(fd.Changes) != 1 || fd.Changes[0].Name != "github.com/spf13/cobra" || !fd.Changes[0].IntegrityChanged {
		t.Fatalf("want cobra repin, got %+v", fd.Changes)
	}
}

func TestGoSumUntidiedGrowthStillChecksCommonVersions(t *testing.T) {
	// go.sum grows an extra version (no tidy) in the same edit that swaps
	// an existing version's hash: the common version still gets checked.
	newSum := goSumOld +
		"golang.org/x/text v0.15.0 h1:h1qWSJVwyDCLBWPFHYtIYSRXcxAlxG2Bo0oPS+sGdIs=\n" +
		"golang.org/x/text v0.15.0/go.mod h1:qtEHqOvUCLEHmAJvs8CkhbULhvfyLxwyHqLYaCSP6PE=\n"
	newSum = strings.ReplaceAll(newSum,
		"h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=",
		"h1:tampered0000000000000000000000000000000000+A=")
	fd := Diff(parseFile(t, "go.sum", goSumOld), parseFile(t, "go.sum", newSum))
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repin, got %+v", fd.Changes)
	}
	c := fd.Changes[0]
	if c.Kind != Repinned || !c.IntegrityChanged || c.Name != "golang.org/x/text" ||
		len(c.Old) != 1 || c.Old[0] != "0.14.0" {
		t.Fatalf("bad change: %+v", c)
	}
}

func TestGemfileChecksumSwapFlags(t *testing.T) {
	const tmpl = `GEM
  remote: https://rubygems.org/
  specs:
    rack (3.1.0)

DEPENDENCIES
  rack

CHECKSUMS
  rack (3.1.0) sha256=%s

BUNDLED WITH
   2.6.2
`
	oldF := parseFile(t, "Gemfile.lock", sprintf(tmpl, strings.Repeat("a", 64)))
	newF := parseFile(t, "Gemfile.lock", sprintf(tmpl, strings.Repeat("b", 64)))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repin, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "rack" {
		t.Fatalf("bad change: %+v", c)
	}
}

const vcpkgCfgTmpl = `{"default-registry": {"kind": "git", "repository": "https://github.com/%s", "baseline": "%s"}}`

func TestVcpkgDefaultRegistrySwapFlagsMove(t *testing.T) {
	// Repository swap WITH a baseline change: the whole dependency tree
	// re-points — resolution-moved lane.
	oldF := parseFile(t, "vcpkg-configuration.json", sprintf(vcpkgCfgTmpl, "microsoft/vcpkg", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	newF := parseFile(t, "vcpkg-configuration.json", sprintf(vcpkgCfgTmpl, "evil/vcpkg-fork", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 change, got %+v", fd.Changes)
	}
	c := fd.Changes[0]
	if !c.RegistryMoved {
		t.Error("swapped default-registry should flag the resolution-moved lane")
	}
	if c.OldHost != "github.com/microsoft/vcpkg" || c.NewHost != "github.com/evil/vcpkg-fork" {
		t.Errorf("hosts = %q -> %q", c.OldHost, c.NewHost)
	}
	if c.SourceRepo != "" {
		t.Errorf("re-pointed registry must not get a SourceRepo (compare links would lie), got %q", c.SourceRepo)
	}
}

func TestVcpkgDefaultRegistrySwapSameShaRepins(t *testing.T) {
	// Same commit, different repository: today's content is sha-identical,
	// but every future baseline bump would come from the new repository —
	// surfaced as a repin + move, the setup step of the attack.
	oldF := parseFile(t, "vcpkg-configuration.json", sprintf(vcpkgCfgTmpl, "microsoft/vcpkg", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	newF := parseFile(t, "vcpkg-configuration.json", sprintf(vcpkgCfgTmpl, "evil/vcpkg-fork", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.RegistryMoved {
		t.Errorf("want Repinned+RegistryMoved, got kind=%s moved=%v", c.Kind, c.RegistryMoved)
	}
}

func TestVcpkgSameConfigNoRows(t *testing.T) {
	oldF := parseFile(t, "vcpkg-configuration.json", sprintf(vcpkgCfgTmpl, "microsoft/vcpkg", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	newF := parseFile(t, "vcpkg-configuration.json", sprintf(vcpkgCfgTmpl, "microsoft/vcpkg", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
	if fd := Diff(oldF, newF); len(fd.Changes) != 0 {
		t.Fatalf("identical configs must produce no rows, got %+v", fd.Changes)
	}
}

const zigZonTmpl = `.{
    .name = "myapp",
    .version = "0.1.0",
    .dependencies = .{
        .known_folders = .{
            .url = "https://github.com/ziglibs/known-folders/archive/refs/tags/v1.2.3.tar.gz",
            .hash = "%s",
        },
    },
    .paths = .{""},
}`

// A same-version .hash swap in build.zig.zon is the tampered-archive shape
// the format exists to catch. Regression: Zig hashes match no conventional
// algorithm label, so before they were normalized (zigIntegrity) both
// shapes fell out of hashesByAlgo and the swap compared as no change at
// all — pre-0.14 multihashes always, 0.14+ hashes whenever the leading
// package name was too long or punctuated to pass for an algo label.
func TestZigLegacyHashSwapSameVersion(t *testing.T) {
	oldF := parseFile(t, "build.zig.zon", sprintf(zigZonTmpl,
		"12209cde192558f8b3dc098ac2330fc2a14fdd211c5433afd33085af75caa9183147"))
	newF := parseFile(t, "build.zig.zon", sprintf(zigZonTmpl,
		"1220aaaaaaaa58f8b3dc098ac2330fc2a14fdd211c5433afd33085af75caa9183147"))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "known_folders" {
		t.Fatalf("bad change: %+v", c)
	}
}

func TestZigModernHashSwapSameVersion(t *testing.T) {
	// "known_folders" leads the 0.14+ hash: '_' and 13 chars — the shape
	// generic label-splitting drops outright.
	oldF := parseFile(t, "build.zig.zon", sprintf(zigZonTmpl,
		"known_folders-1.2.3-Fy-PJsbKAACbDh9bBxR0MMThxZSS6A9RH4apWphNHY70"))
	newF := parseFile(t, "build.zig.zon", sprintf(zigZonTmpl,
		"known_folders-1.2.3-Fy-PJsbKAACbDh9bBxR0MMThxZSS6A9RH4apWphNHY71"))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged {
		t.Fatalf("bad change: %+v", c)
	}
}

func TestZigHashShapeMigrationNotFlagged(t *testing.T) {
	// zig 0.14 rewrites the manifest's hashes from multihash to package
	// hash for the same content: distinct labels = no shared algorithm =
	// an algo upgrade, never an integrity alarm. (The 0.0.0 placeholder
	// keeps the version keyed on the URL tag, same as the legacy side.)
	oldF := parseFile(t, "build.zig.zon", sprintf(zigZonTmpl,
		"12209cde192558f8b3dc098ac2330fc2a14fdd211c5433afd33085af75caa9183147"))
	newF := parseFile(t, "build.zig.zon", sprintf(zigZonTmpl,
		"known_folders-0.0.0-Fy-PJsbKAACbDh9bBxR0MMThxZSS6A9RH4apWphNHY70"))
	if fd := Diff(oldF, newF); len(fd.Changes) != 0 {
		t.Fatalf("shape migration should not flag: %+v", fd.Changes)
	}
}
