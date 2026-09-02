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

func TestMultiAlgoDisjointFlags(t *testing.T) {
	// yarn classic pins carry BOTH the sha1 `resolved` fragment and the
	// SRI sha512. yarn verifies the SRI line at install time — a poisoned
	// sha512 with the fragment left intact is the camouflage shape, and
	// two sha512 values can never describe the same bytes. Overlap on
	// sha1 must not suppress the disjoint sha512.
	old := "679591c564c3bffaae8454cf0b3df370c3d6911c sha512-AAAA"
	new_ := "679591c564c3bffaae8454cf0b3df370c3d6911c sha512-BBBB"
	if !integrityDiffers(old, new_) {
		t.Fatal("disjoint sha512 with overlapping sha1 fragment must flag")
	}
	if integritySame(old, new_) {
		t.Fatal("contradictory hash sets must not prove same bytes")
	}
	// ...and the mirror case: swapped fragment, same SRI.
	if !integrityDiffers("aaaa111111111111111111111111111111111111 sha512-XXXX",
		"bbbb222222222222222222222222222222222222 sha512-XXXX") {
		t.Fatal("disjoint sha1 with overlapping sha512 must flag")
	}
}

func TestTerraformPlatformRelockQuiet(t *testing.T) {
	// h1 hashes exist only for the platforms the lock was generated
	// with; re-locking for another platform replaces the h1 set while
	// the registry-published zh set still overlaps. Not a repin.
	tfOld := "h1:linuxAAA zh:f1 zh:f2 zh:f3"
	tfNew := "h1:darwinBBB zh:f1 zh:f2 zh:f3"
	if integrityDiffers(tfOld, tfNew) {
		t.Fatal("platform re-lock with zh overlap must stay quiet")
	}
	if !integritySame(tfOld, tfNew) {
		t.Fatal("zh overlap should still prove the same release")
	}
	// Both families fully disjoint: nothing vouches — flag.
	if !integrityDiffers("h1:aaa zh:x1", "h1:bbb zh:y1") {
		t.Fatal("fully disjoint h1 AND zh must flag")
	}
}

const yarnClassicTmpl = `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c564c3bffaae8454cf0b3df370c3d6911c"
  integrity sha512-%s
`

func TestYarnClassicSRISwapFlagsRepinned(t *testing.T) {
	// End-to-end regression for the pooled-overlap bug: same version,
	// same resolved fragment, swapped SRI sha512 → must surface as a
	// REPINNED row, not "no changes".
	oldF := parseFile(t, "yarn.lock", sprintf(yarnClassicTmpl, "v2kDEe57lecT"))
	newF := parseFile(t, "yarn.lock", sprintf(yarnClassicTmpl, "AAADEe57lecT"))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "lodash" {
		t.Fatalf("bad change: %+v", c)
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

// Siblings of the build.zig.zon bug (v0.6.6): parsers whose checksum
// field is sha256 by definition used to width-validate the value in
// their capture regex — a same-version swap to a malformed width (63
// hex chars here) passed the parser, then fell out of hashesByAlgo,
// and the tamper compared as "no change". The parsers now label the
// value themselves, so bad-width swaps compare within sha256 and flag.

const cargoLockTmpl = `version = 3

[[package]]
name = "serde"
version = "1.0.210"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "%s"
`

func TestCargoMalformedChecksumSwapSameVersion(t *testing.T) {
	oldF := parseFile(t, "Cargo.lock", sprintf(cargoLockTmpl,
		"c8e3592472072e6e22e0a54d5904d9febf8508f65fb8552499a1abc7d1078c3a"))
	newF := parseFile(t, "Cargo.lock", sprintf(cargoLockTmpl,
		"c8e3592472072e6e22e0a54d5904d9febf8552499a1abc7d1078c3a12345678")) // 63 chars
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "serde" {
		t.Fatalf("bad change: %+v", c)
	}
}

const mixLockTmpl = `%%{
  "plug": {:hex, :plug, "1.16.1", "%s", [:mix], [], "hexpm", "%s"},
}`

func TestMixMalformedChecksumSwapSameVersion(t *testing.T) {
	oldF := parseFile(t, "mix.lock", sprintf(mixLockTmpl,
		"40c74619c12f82736d2214557dedec2e9762029b2438d6d175c5074c933edc9d",
		"a13ff6b9006b03d7e33874945b2755253841b238c34071ed85b0e86057f8cddc"))
	newF := parseFile(t, "mix.lock", sprintf(mixLockTmpl,
		"40c74619c12f82736d2214557dedec2e9762029b2438d6d175c5074c933edc9",  // 63 chars
		"a13ff6b9006b03d7e33874945b2755253841b238c34071ed85b0e86057f8cdd")) // 63 chars
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "plug" {
		t.Fatalf("bad change: %+v", c)
	}
}

const denoLockTmpl = `{
  "version": "4",
  "jsr": {
    "@std/path@1.0.6": { "integrity": "%s" }
  }
}`

func TestDenoJSRMalformedIntegritySwapSameVersion(t *testing.T) {
	oldF := parseFile(t, "deno.lock", sprintf(denoLockTmpl,
		"aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899aa"))
	newF := parseFile(t, "deno.lock", sprintf(denoLockTmpl,
		"aaaabbbbccccddddeeeeffff00001111222233334444555566667777888899a")) // 63 chars
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged {
		t.Fatalf("bad change: %+v", c)
	}
}

// Every integrity notation any parser emits must survive splitHash: a
// notation it cannot label is silently dropped from integrity diffing,
// and same-version swaps of that pin compare as "no change" — the bug
// class TestZigLegacyHashSwapSameVersion regressed on. One entry per
// (parser, notation), values verbatim from a real-corpus audit
// (2026-08-25: 29 formats, ~11k hashes). Add a row when a new format's
// setPin introduces a notation.
func TestSplitHashRecognizesEveryParserNotation(t *testing.T) {
	cases := []struct {
		src, hash, wantAlgo string
	}{
		{"npm/pnpm/bun/yarn-berry SRI", "sha512-q8bd8CvnbAxqqhcJ0l7csVSPvcs0hLTRUKrrzM70XvbKw2AHOO9z2rrhZ0mBSuwQvbXwYLLYOh/EJk7EpArKXQ==", "sha512"},
		{"npm SRI sha1 (legacy)", "sha1-tSQ9jz7BqjXxNkYFvA0QNuMKtp8=", "sha1"},
		{"yarn berry cache key", "10c0/e5b6a5ee1c9ee4b0b0dcaa4f8db2a2f1a1e5a30d9e1a5c8dbd7a55545cd54e2e2b", "10c0"},
		{"yarn berry cache key (no compression)", "10/eb77846e506df107208ee6a57aa38c80ce6cdd9ab499ec3518a8e3000334def8", "10"},
		{"yarn classic resolved fragment (bare sha1)", "9469c3aca9a3f4d635a123e0967a89d4b4a09f4d", "sha1"},
		{"python sha256: (poetry/uv/pdm/pipfile/pylock/reqs)", "sha256:9c2ea1e62d871267b78307fe511c0838ba0da28698c5732d54e2790bf3ba9899", "sha256"},
		{"cargo/mix/deno-jsr checksum (normalized)", "sha256:42b1e076c9dfb5d27decfd0c2a659d78bec5eef86bbe0be4bc159cec3f4ed1c0", "sha256"},
		{"bare sha256 (width-detected)", "0efc9a13c53f1aa1a4d3adcbca24c04124528ab6d1b45cd80540367f0e90c33d", "sha256"},
		{"rebar/pod checksum (normalized)", "sha1:3ca45e7fe10ddff8e1f91a0f58c9a906eac8a4f9", "sha1"},
		{"pylock long hashlib/PyPI digest name", "blake2b_256:6ab8e11c1d4c390276943b57e145054000398601c34c319881bf4a3fcaea77d1", "blake2b_256"},
		{"pylock sha3 family", "sha3_256:6ab8e11c1d4c390276943b57e145054000398601c34c319881bf4a3fcaea77d1", "sha3_256"},
		{"bare sha512", strings.Repeat("ab", 64), "sha512"},
		{"go.sum module hash", "h1:1JFLCDsPCbbqKGYIPTa1sm2X/tuw2hxfi9wIyB2a16M=", "h1"},
		{"go.sum manifest hash (artifact-scoped)", "go.mod#h1:vE6IudEVhrDWotDMn/pxpsJbByyewXWEwT1yyMbqTazA=", "go.mod#h1"},
		{"terraform h1 scheme", "h1:uS0X6hjrl7GYAzMSW3yUk2vLn+HgdK3vJwLdTQMGDcs=", "h1"},
		{"terraform zh scheme", "zh:1c1b1bfd89b4fa4a4d4c56d4c6b6cbd0f2b2b6912ad4a24bdb0f6b3f3aca2b6a", "zh"},
		{"gradle verification-metadata (artifact-scoped)", "core-1.8.0.jar#sha256:9c2ea1e62d871267b78307fe511c0838ba0da28698c5732d54e2790bf3ba9899", "core-1.8.0.jar#sha256"},
		{"mise.lock platform-scoped sha256", "linux-x64#sha256:9c2ea1e62d871267b78307fe511c0838ba0da28698c5732d54e2790bf3ba9899", "linux-x64#sha256"},
		{"mise.lock platform-scoped blake3", "macos-arm64#blake3:9c2ea1e62d871267b78307fe511c0838ba0da28698c5732d54e2790bf3ba9899", "macos-arm64#blake3"},
		{"conan recipe revision", "rrev:f52e03ae3d251dec36c6a60d2ef066db", "rrev"},
		{"swift/composer tag commit", "commit:c5b1261d6d3e43071626931fc004f70149baeba2", "commit"},
		{"julia registry git tree", "tree:c5b1261d6d3e43071626931fc004f70149baeba2", "tree"},
		{"zig pre-0.14 multihash (normalized)", "sha256:9cde192558f8b3dc098ac2330fc2a14fdd211c5433afd33085af75caa9183147", "sha256"},
		{"zig 0.14+ package hash (normalized)", "zigpkg:known_folders-1.2.3-Fy-PJsbKAACbDh9bBxR0MMThxZSS6A9RH4apWphNHY70", "zigpkg"},
		{"nix narHash / bazel SRI", "sha256-BZyMKM5nAQE1ehlvvpJqPmcbDMOFcq7BSbwc9nQ8AQ8=", "sha256"},
		{"oci/docker digest", "sha256:c5b1261d6d3e43071626931fc004f70149baeba2c8ec672bd4f27761f8e1ad6b", "sha256"},
		{"conda md5 label", "md5:0123456789abcdef0123456789abcdef", "md5"},
	}
	for _, c := range cases {
		algo, val := splitHash(c.hash)
		if algo != c.wantAlgo || val == "" {
			t.Errorf("%s: splitHash(%q) = (%q, %q), want algo %q and non-empty value",
				c.src, c.hash, algo, val, c.wantAlgo)
		}
	}
	// Hostile or meaningless strings must stay droppable: hashesByAlgo
	// discards anything without both a label and a value — the defensive
	// behavior for attacker-controlled integrity fields.
	for _, junk := range []string{"", "notahash", "12345", "xyz!!:abc", "1220", "-leading", "trailing-"} {
		if algo, val := splitHash(junk); algo != "" && val != "" {
			t.Errorf("junk %q unexpectedly parsed as (%q, %q)", junk, algo, val)
		}
	}
}

const npmLockNoIntegrityTmpl = `{
  "lockfileVersion": 3,
  "packages": {
    "": {"dependencies": {"left-pad": "^1.3.0"}},
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
    }
  }
}`

func TestIntegrityRemovedSameVersion(t *testing.T) {
	// SRI stripped from a registry pin, version unchanged: nothing
	// verifies the artifact anymore — the tampered-pin hiding shape.
	oldF := parseFile(t, "package-lock.json", sprintf(npmLockTmpl, "registry.npmjs.org", "sha512-aaaa"))
	newF := parseFile(t, "package-lock.json", npmLockNoIntegrityTmpl)
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	c := fd.Changes[0]
	if c.Kind != Repinned || !c.IntegrityRemoved ||
		len(c.IntegrityRemovedVersions) != 1 || c.IntegrityRemovedVersions[0] != "1.3.0" {
		t.Fatalf("bad change: %+v", c)
	}
	if c.IntegrityChanged {
		t.Fatalf("removal must not double as change: %+v", c)
	}
	sum := Summarize([]FileDiff{fd})
	if sum.IntegrityRemoved != 1 || sum.IntegrityChanged != 0 {
		t.Fatalf("summary: %+v", sum)
	}
}

func TestRepinnedViaMalformedWidthSwap(t *testing.T) {
	// pubspec.lock's sha256 field is captured loosely and labeled at the
	// parser: a hash swapped to a malformed value (63 hex chars) compares
	// WITHIN the sha256 algorithm and flags as a repin — alarm-grade, not
	// the softer informational removal it used to surface as when the
	// strict-width capture dropped the value entirely.
	const pubTmpl = `packages:
  http:
    dependency: "direct main"
    description:
      name: http
      sha256: "%s"
      url: "https://pub.dev"
    source: hosted
    version: "1.2.0"
sdks:
  dart: ">=3.0.0 <4.0.0"
`
	good := strings.Repeat("a", 64)
	bad := strings.Repeat("b", 63) // one short: no algorithm claims it
	oldF := parseFile(t, "pubspec.lock", sprintf(pubTmpl, good))
	newF := parseFile(t, "pubspec.lock", sprintf(pubTmpl, bad))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 || !fd.Changes[0].IntegrityChanged {
		t.Fatalf("malformed swap should flag as repin: %+v", fd.Changes)
	}
	if fd.Changes[0].IntegrityRemoved {
		t.Fatalf("malformed swap must not read as removal: %+v", fd.Changes)
	}
}

func TestIntegrityRemovedSuppressedForGitSwitch(t *testing.T) {
	// hosted → git override at the same version (a routine fork pin):
	// the git source pins a commit instead of a registry hash — quiet.
	const pubHosted = `packages:
  perm:
    dependency: transitive
    description:
      name: perm
      sha256: "` + "f67cab14b4328574938ecea2db3475dad7af7ead6afab6338772c5f88963e38b" + `"
      url: "https://pub.dev"
    source: hosted
    version: "0.1.2"
sdks:
  dart: ">=3.0.0 <4.0.0"
`
	const pubGit = `packages:
  perm:
    dependency: "direct overridden"
    description:
      path: "."
      ref: fc09b707ab4535a9214c87b16f09feda7e765d90
      resolved-ref: fc09b707ab4535a9214c87b16f09feda7e765d90
      url: "https://github.com/example/perm_noop.git"
    source: git
    version: "0.1.2"
sdks:
  dart: ">=3.0.0 <4.0.0"
`
	oldF := parseFile(t, "pubspec.lock", pubHosted)
	newF := parseFile(t, "pubspec.lock", pubGit)
	for _, c := range Diff(oldF, newF).Changes {
		if c.IntegrityRemoved {
			t.Fatalf("git switch should not flag removal: %+v", c)
		}
	}
}

func TestIntegrityRemovedSuppressedForWholeFileMigration(t *testing.T) {
	// Every pin losing its hash at once is a tooling change (a lockfile
	// regenerated by a tool that writes no hashes), not an attack.
	mk := func(withIntegrity bool) string {
		var b strings.Builder
		b.WriteString(`{"lockfileVersion": 3, "packages": {"": {},`)
		for i := 0; i < migrationThreshold; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			name := "pkg" + strings.Repeat("x", i+1)
			b.WriteString(sprintf(`"node_modules/%s": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/%s/-/%s-1.0.0.tgz"`, name, name, name))
			if withIntegrity {
				b.WriteString(`, "integrity": "sha512-aaaa"`)
			}
			b.WriteString("}")
		}
		b.WriteString("}}")
		return b.String()
	}
	oldF := parseFile(t, "package-lock.json", mk(true))
	newF := parseFile(t, "package-lock.json", mk(false))
	for _, c := range Diff(oldF, newF).Changes {
		if c.IntegrityRemoved {
			t.Fatalf("whole-file migration should not flag removal: %+v", c)
		}
	}
}

const pixiCondaTmpl = `version: 7
environments:
  default:
    channels:
    - url: https://prefix.dev/conda-forge/
    packages:
      linux-64:
      - conda: https://prefix.dev/conda-forge/linux-64/openssl-3.3.1-%s.conda
packages:
- conda: https://prefix.dev/conda-forge/linux-64/openssl-3.3.1-%s.conda
  sha256: %s
  license: Apache-2.0
`

func TestPixiCondaShaSwapFlagsRepinned(t *testing.T) {
	// Same version, same artifact filename, swapped sha256 → REPINNED.
	// Conda hashes are scoped to the artifact filename precisely so this
	// tamper shape compares instead of vanishing (the pre-v0.6.12 parser
	// recorded no integrity for conda entries at all).
	oldF := parseFile(t, "pixi.lock", sprintf(pixiCondaTmpl, "h4bc722e_2", "h4bc722e_2",
		"1111111111111111111111111111111111111111111111111111111111111111"))
	newF := parseFile(t, "pixi.lock", sprintf(pixiCondaTmpl, "h4bc722e_2", "h4bc722e_2",
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "openssl" {
		t.Fatalf("bad change: %+v", c)
	}
}

func TestPixiCondaBuildBumpStaysQuiet(t *testing.T) {
	// Same version rebuilt under a new build number: filename changes, so
	// the scoped algo differs on each side — an algo migration, never a
	// repin. This is the routine conda-forge rebuild churn that made bare
	// (name, version) hash anchoring impossible.
	oldF := parseFile(t, "pixi.lock", sprintf(pixiCondaTmpl, "h4bc722e_2", "h4bc722e_2",
		"1111111111111111111111111111111111111111111111111111111111111111"))
	newF := parseFile(t, "pixi.lock", sprintf(pixiCondaTmpl, "hb9d3cd8_3", "hb9d3cd8_3",
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
	if fd := Diff(oldF, newF); len(fd.Changes) != 0 {
		t.Fatalf("build-number rebuild must stay quiet, got %+v", fd.Changes)
	}
}

const condaLockTmpl = `version: 1
package:
- name: numpy
  version: 1.26.4
  manager: conda
  platform: linux-64
  url: https://conda.anaconda.org/conda-forge/linux-64/numpy-1.26.4-py312heda63a1_0.conda
  hash:
    md5: d8285bea2a350f63fab23bf460221f3f
    sha256: %s
`

func TestCondaLockShaSwapFlagsRepinned(t *testing.T) {
	oldF := parseFile(t, "conda-lock.yml", sprintf(condaLockTmpl,
		"1111111111111111111111111111111111111111111111111111111111111111"))
	newF := parseFile(t, "conda-lock.yml", sprintf(condaLockTmpl,
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "numpy" {
		t.Fatalf("bad change: %+v", c)
	}
}

const pixiLocalPathTmpl = `version: 7
environments:
  default:
    channels:
    - url: https://prefix.dev/conda-forge/
    packages:
      linux-64:
      - pypi: ./rerun_py
packages:
- pypi: ./rerun_py
  name: rerun-sdk
  version: 0.28.0a1+dev
  sha256: %s
  editable: true
`

func TestPixiLocalPathRebuildStaysQuiet(t *testing.T) {
	// A path install ("./rerun_py") is rebuilt locally — its hash changes
	// at the same version on every rebuild. No integrity is recorded for
	// non-URL sources, so the churn never masquerades as a repin (seen
	// live in rerun-io/rerun's pixi.lock history).
	oldF := parseFile(t, "pixi.lock", sprintf(pixiLocalPathTmpl,
		"5e197009d39ead8f8c4a038325965dca25981224b9551062d6a05ccb727c5ba7"))
	newF := parseFile(t, "pixi.lock", sprintf(pixiLocalPathTmpl,
		"80c390cc45bf88b0116c68f5e38604f06c38073bc18b713de29f340d732c0a3f"))
	if fd := Diff(oldF, newF); len(fd.Changes) != 0 {
		t.Fatalf("local-path rebuild must stay quiet, got %+v", fd.Changes)
	}
}

const condaLockHashTmpl = `version: 1
package:
- name: numpy
  version: 1.26.4
  manager: conda
  platform: linux-64
  url: https://conda.anaconda.org/conda-forge/linux-64/numpy-1.26.4-py312heda63a1_0.conda
  hash:
%s`

func TestCondaLockMd5SwapUnderIntactSha256Flags(t *testing.T) {
	// The mirror of the yarn-classic camouflage: md5 swapped while the
	// sha256 line is left intact. Each shared algorithm is judged on its
	// own — two md5 values can never describe the same bytes, so overlap
	// on sha256 must not suppress the disjoint md5. (Pre-v0.6.13 the
	// parser dropped md5 entirely, so this shape compared as no change.)
	oldF := parseFile(t, "conda-lock.yml", sprintf(condaLockHashTmpl,
		"    md5: 11111111111111111111111111111111\n"+
			"    sha256: fe3459c75cf84dcef6ef14efcc4adb0ade66038ddd27cadb894f34f4797687d8\n"))
	newF := parseFile(t, "conda-lock.yml", sprintf(condaLockHashTmpl,
		"    md5: 22222222222222222222222222222222\n"+
			"    sha256: fe3459c75cf84dcef6ef14efcc4adb0ade66038ddd27cadb894f34f4797687d8\n"))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "numpy" {
		t.Fatalf("bad change: %+v", c)
	}
}

func TestCondaLockMd5OnlyHashSwapFlags(t *testing.T) {
	// conda-lock's schema requires only ONE of md5/sha256, and older
	// channel packages carry md5 alone. A same-version md5 swap on such
	// an entry is the full poisoned-checksum shape and must flag.
	oldF := parseFile(t, "conda-lock.yml", sprintf(condaLockHashTmpl,
		"    md5: 11111111111111111111111111111111\n"))
	newF := parseFile(t, "conda-lock.yml", sprintf(condaLockHashTmpl,
		"    md5: 22222222222222222222222222222222\n"))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "numpy" {
		t.Fatalf("bad change: %+v", c)
	}
}

func TestCondaLockHashAlgoMigrationStaysQuiet(t *testing.T) {
	// Re-locks that ADD sha256 to an md5-only entry (same md5), or DROP
	// md5 keeping the same sha256, are algorithm migrations — no shared
	// algorithm disagrees, so neither direction may flag.
	md5Only := sprintf(condaLockHashTmpl,
		"    md5: 11111111111111111111111111111111\n")
	both := sprintf(condaLockHashTmpl,
		"    md5: 11111111111111111111111111111111\n"+
			"    sha256: fe3459c75cf84dcef6ef14efcc4adb0ade66038ddd27cadb894f34f4797687d8\n")
	shaOnly := sprintf(condaLockHashTmpl,
		"    sha256: fe3459c75cf84dcef6ef14efcc4adb0ade66038ddd27cadb894f34f4797687d8\n")
	if fd := Diff(parseFile(t, "conda-lock.yml", md5Only), parseFile(t, "conda-lock.yml", both)); len(fd.Changes) != 0 {
		t.Fatalf("adding sha256 alongside the same md5 must stay quiet, got %+v", fd.Changes)
	}
	if fd := Diff(parseFile(t, "conda-lock.yml", both), parseFile(t, "conda-lock.yml", shaOnly)); len(fd.Changes) != 0 {
		t.Fatalf("dropping md5 with the same sha256 must stay quiet, got %+v", fd.Changes)
	}
}

func TestPixiCondaMd5SwapUnderIntactSha256Flags(t *testing.T) {
	// Same camouflage shape through the pixi.lock parser (flat md5/sha256
	// keys rather than conda-lock's hash sub-map).
	mk := func(md5 string) string {
		return `version: 7
environments:
  default:
    channels:
    - url: https://prefix.dev/conda-forge/
    packages:
      linux-64:
      - conda: https://prefix.dev/conda-forge/linux-64/openssl-3.3.1-h4bc722e_2.conda
packages:
- conda: https://prefix.dev/conda-forge/linux-64/openssl-3.3.1-h4bc722e_2.conda
  sha256: fe3459c75cf84dcef6ef14efcc4adb0ade66038ddd27cadb894f34f4797687d8
  md5: ` + md5 + `
  license: Apache-2.0
`
	}
	oldF := parseFile(t, "pixi.lock", mk("11111111111111111111111111111111"))
	newF := parseFile(t, "pixi.lock", mk("22222222222222222222222222222222"))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "openssl" {
		t.Fatalf("bad change: %+v", c)
	}
}

// Siblings of the strict-width class, second sweep (the parsers that
// width-validated the value in the capture regex itself, so a malformed
// swap parsed as NO integrity and surfaced only as the softer
// informational removal — or, for bare-hash formats, as nothing at all
// once the width detector dropped the value). All now capture loosely
// and label at the parser; a malformed swap flags alarm-grade REPINNED.

const podLockTmpl = `PODS:
  - Alamofire (5.8.1)

DEPENDENCIES:
  - Alamofire

SPEC REPOS:
  trunk:
    - Alamofire

SPEC CHECKSUMS:
  Alamofire: %s

COCOAPODS: 1.15.2
`

func TestPodMalformedChecksumSwapSameVersion(t *testing.T) {
	oldF := parseFile(t, "Podfile.lock", sprintf(podLockTmpl,
		"3ca45e7fe10ddff8e1f91a0f58c9a906eac8a4f9"))
	newF := parseFile(t, "Podfile.lock", sprintf(podLockTmpl,
		"3ca45e7fe10ddff8e1f91a0f58c9a906eac8a4f")) // 39 chars
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "Alamofire" {
		t.Fatalf("bad change: %+v", c)
	}
}

const rebarLockTmpl = `{"1.2.0",
[{<<"redbug">>,{pkg,<<"redbug">>,<<"2.0.6">>},0}]}.
[
{pkg_hash,[
 {<<"redbug">>, <<"%s">>}]}
].
`

func TestRebarMalformedChecksumSwapSameVersion(t *testing.T) {
	oldF := parseFile(t, "rebar.lock", sprintf(rebarLockTmpl,
		"63c8977a2f71f84a2acd7e7cfab74a5eaa787c110105379a34d63c562739b3cf"))
	newF := parseFile(t, "rebar.lock", sprintf(rebarLockTmpl,
		"63c8977a2f71f84a2acd7e7cfab74a5eaa787c110105379a34d63c562739b3c")) // 63 chars
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "redbug" {
		t.Fatalf("bad change: %+v", c)
	}
}

const juliaManifestTmpl = `manifest_format = "2.0"

[[deps.Example]]
git-tree-sha1 = "%s"
uuid = "7876af07-990d-54b4-ab0e-23690620f79a"
version = "0.5.3"
`

func TestJuliaMalformedTreeSwapSameVersion(t *testing.T) {
	oldF := parseFile(t, "Manifest.toml", sprintf(juliaManifestTmpl,
		"46e2578e2d095e8f823874f118cf01f9d4a3dee3"))
	newF := parseFile(t, "Manifest.toml", sprintf(juliaManifestTmpl,
		"46e2578e2d095e8f823874f118cf01f9d4a3dee")) // 39 chars
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "Example" {
		t.Fatalf("bad change: %+v", c)
	}
}

const gleamManifestTmpl = `packages = [
  { name = "gleam_stdlib", version = "0.34.0", build_tools = ["gleam"], requirements = [], otp_app = "gleam_stdlib", source = "hex", outer_checksum = "%s" },
]
`

func TestGleamMalformedChecksumSwapSameVersion(t *testing.T) {
	oldF := parseFile(t, "manifest.toml", sprintf(gleamManifestTmpl,
		"1B6DAB9DCB11F5A0AACD4EAF34E5A15CBA51284D1FF81DC1BE976DDE6C6D6806"))
	newF := parseFile(t, "manifest.toml", sprintf(gleamManifestTmpl,
		"1B6DAB9DCB11F5A0AACD4EAF34E5A15CBA51284D1FF81DC1BE976DDE6C6D680")) // 63 chars
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "gleam_stdlib" {
		t.Fatalf("bad change: %+v", c)
	}
}

const pylockTmpl = `lock-version = "1.0"

[[packages]]
name = "urllib3"
version = "2.2.2"
sdist = { url = "https://files.pythonhosted.org/packages/aa/urllib3-2.2.2.tar.gz", hashes = { %s } }
`

func TestPylockMalformedHashSwapSameVersion(t *testing.T) {
	oldF := parseFile(t, "pylock.toml", sprintf(pylockTmpl,
		`sha256 = "dd505485549a7a552833da5e6063639d0d177c04f23bc3864e41e5dc5f612168"`))
	newF := parseFile(t, "pylock.toml", sprintf(pylockTmpl,
		`sha256 = "dd505485549a7a552833da5e6063639d0d177c04f23bc3864e41e5dc5f61216"`)) // 63 chars
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged {
		t.Fatalf("bad change: %+v", c)
	}
}

func TestPylockLongAlgoNameSwapSameVersion(t *testing.T) {
	// PEP 751 allows any hashlib/PyPI digest name. blake2b_256 (11 chars,
	// underscore) used to fail isAlgoLabel, so an entry hashed only with
	// it carried no comparable integrity and swaps were silent.
	oldF := parseFile(t, "pylock.toml", sprintf(pylockTmpl,
		`blake2b_256 = "6ab8e11c1d4c390276943b57e145054000398601c34c319881bf4a3fcaea77d1"`))
	newF := parseFile(t, "pylock.toml", sprintf(pylockTmpl,
		`blake2b_256 = "aaaae11c1d4c390276943b57e145054000398601c34c319881bf4a3fcaea77d1"`))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged {
		t.Fatalf("bad change: %+v", c)
	}
}

const gemChecksumLockTmpl = `GEM
  remote: https://rubygems.org/
  specs:
    rack (2.2.8)

PLATFORMS
  ruby

DEPENDENCIES
  rack

CHECKSUMS
  rack (2.2.8) sha256=%s

BUNDLED WITH
   2.6.0
`

func TestGemMalformedChecksumSwapSameVersion(t *testing.T) {
	// The old value class ([A-Za-z0-9+/=_-]+) silently rejected values
	// containing other bytes, so a swap to one erased the checksum line.
	oldF := parseFile(t, "Gemfile.lock", sprintf(gemChecksumLockTmpl,
		"7b6df24b5a11c05b31de6a0f2913227b8d5a7fc50a1485e3d0aa1eae57cee7d3"))
	newF := parseFile(t, "Gemfile.lock", sprintf(gemChecksumLockTmpl,
		"7b6df24b5a11c05b31de6a0f2913227b8d5a7fc50a1485e3d0aa1eae57cee7!!"))
	fd := Diff(oldF, newF)
	if len(fd.Changes) != 1 {
		t.Fatalf("want 1 repinned change, got %+v", fd.Changes)
	}
	if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "rack" {
		t.Fatalf("bad change: %+v", c)
	}
}

const juliaGitManifest = `manifest_format = "2.0"

[[deps.Example]]
git-tree-sha1 = "25b0218c72dead9e5e446599b4d15229a472f09a"
repo-rev = "ec3e722"
repo-url = "https://github.com/fonsp/Example.jl.git"
uuid = "7876af07-990d-54b4-ab0e-23690620f79a"
version = "0.5.3"
`

func TestJuliaIntegrityRemovedSuppressedForGitSwitch(t *testing.T) {
	// Registry pin → git checkout at the same version (repo-url appears):
	// the routine fork-pin flow, same suppression pubspec.lock gets — the
	// tree hash now tracks a repo, not an immutable registry version.
	oldF := parseFile(t, "Manifest.toml", sprintf(juliaManifestTmpl,
		"46e2578e2d095e8f823874f118cf01f9d4a3dee3"))
	newF := parseFile(t, "Manifest.toml", juliaGitManifest)
	for _, c := range Diff(oldF, newF).Changes {
		if c.IntegrityRemoved || c.IntegrityChanged {
			t.Fatalf("git switch should be quiet: %+v", c)
		}
	}
}

// Dual-sha256 scoping (mix.lock / rebar.lock). Hex records TWO sha256
// values per package — the tarball contents (inner) and the tarball file
// (outer). They digest different byte streams, so the parsers scope them
// ("contents#sha256:", "tarball#sha256:") gradle-style: pooled under one
// "sha256" label, a one-sided swap overlapped on the untouched sibling
// and compared as no change — the v0.6.11 camouflage shape, hiding
// within a single algorithm instead of across two.

const mixLockDualTmpl = `%%{
  "plug": {:hex, :plug, "1.16.1", "%s", [:mix], [], "hexpm", "%s"},
}`

func TestMixLockOneSidedChecksumSwapFlags(t *testing.T) {
	inner := "40c74619c12f82736d2214557dedec2e9762029b2438d6d175c5074c933edc9d"
	outer := "9419a8a09bf9459b035b50e937c1a1275ab541c599e62b8748a7e4b4760f9c87"
	swapped := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	oldF := parseFile(t, "mix.lock", sprintf(mixLockDualTmpl, inner, outer))
	for name, newContent := range map[string]string{
		"inner swap under intact outer": sprintf(mixLockDualTmpl, swapped, outer),
		"outer swap under intact inner": sprintf(mixLockDualTmpl, inner, swapped),
	} {
		fd := Diff(oldF, parseFile(t, "mix.lock", newContent))
		if len(fd.Changes) != 1 {
			t.Fatalf("%s: want 1 repinned change, got %+v", name, fd.Changes)
		}
		if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "plug" {
			t.Fatalf("%s: bad change: %+v", name, c)
		}
	}
}

func TestMixLockOuterChecksumMigrationStaysQuiet(t *testing.T) {
	// Old-format mix.lock entries carry only the inner checksum; the
	// re-lock that adds the outer one (same inner) is an added scope.
	oldF := parseFile(t, "mix.lock", `%{
  "plug": {:hex, :plug, "1.16.1", "40c74619c12f82736d2214557dedec2e9762029b2438d6d175c5074c933edc9d", [:mix], []},
}`)
	newF := parseFile(t, "mix.lock", sprintf(mixLockDualTmpl,
		"40c74619c12f82736d2214557dedec2e9762029b2438d6d175c5074c933edc9d",
		"9419a8a09bf9459b035b50e937c1a1275ab541c599e62b8748a7e4b4760f9c87"))
	if fd := Diff(oldF, newF); len(fd.Changes) != 0 {
		t.Fatalf("adding the outer checksum must stay quiet, got %+v", fd.Changes)
	}
}

const rebarLockDualTmpl = `{"1.2.0",
[{<<"hackney">>,{pkg,<<"hackney">>,<<"1.20.1">>},0}]}.
[
{pkg_hash,[
 {<<"hackney">>, <<"%s">>}]},
{pkg_hash_ext,[
 {<<"hackney">>, <<"%s">>}]}].
`

func TestRebarLockOneSidedChecksumSwapFlags(t *testing.T) {
	inner := "8D97AEC62DDDDD757D128BFD1DF6C5861093419F8F7A4223823537BAD5D064E2"
	outer := "FE9094E5F1A2A2C0A7D10918FEE36BFEC0EC2A979994CFF8CFE8058CD9AF38E3"
	swapped := "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	oldF := parseFile(t, "rebar.lock", sprintf(rebarLockDualTmpl, inner, outer))
	for name, newContent := range map[string]string{
		"pkg_hash swap under intact pkg_hash_ext": sprintf(rebarLockDualTmpl, swapped, outer),
		"pkg_hash_ext swap under intact pkg_hash": sprintf(rebarLockDualTmpl, inner, swapped),
	} {
		fd := Diff(oldF, parseFile(t, "rebar.lock", newContent))
		if len(fd.Changes) != 1 {
			t.Fatalf("%s: want 1 repinned change, got %+v", name, fd.Changes)
		}
		if c := fd.Changes[0]; c.Kind != Repinned || !c.IntegrityChanged || c.Name != "hackney" {
			t.Fatalf("%s: bad change: %+v", name, c)
		}
	}
}

func TestRebarLockHashExtMigrationStaysQuiet(t *testing.T) {
	// Format 1.1.0 locks carry pkg_hash only; the 1.2.0 re-lock adds
	// pkg_hash_ext (same pkg_hash) — an added scope, never an alarm.
	oldF := parseFile(t, "rebar.lock", `{"1.1.0",
[{<<"hackney">>,{pkg,<<"hackney">>,<<"1.20.1">>},0}]}.
[
{pkg_hash,[
 {<<"hackney">>, <<"8D97AEC62DDDDD757D128BFD1DF6C5861093419F8F7A4223823537BAD5D064E2">>}]}].
`)
	newF := parseFile(t, "rebar.lock", sprintf(rebarLockDualTmpl,
		"8D97AEC62DDDDD757D128BFD1DF6C5861093419F8F7A4223823537BAD5D064E2",
		"FE9094E5F1A2A2C0A7D10918FEE36BFEC0EC2A979994CFF8CFE8058CD9AF38E3"))
	if fd := Diff(oldF, newF); len(fd.Changes) != 0 {
		t.Fatalf("adding pkg_hash_ext must stay quiet, got %+v", fd.Changes)
	}
}
