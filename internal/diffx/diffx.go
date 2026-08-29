// Package diffx computes the semantic difference between two lockfiles.
package diffx

import (
	"regexp"
	"sort"
	"strings"

	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// Kind of change for a single package.
type Kind string

const (
	Added      Kind = "added"
	Removed    Kind = "removed"
	Upgraded   Kind = "upgraded"
	Downgraded Kind = "downgraded"
	Changed    Kind = "changed"  // multi-version set changed
	Repinned   Kind = "repinned" // same version(s), but integrity/resolution changed
)

// Change describes what happened to one package.
type Change struct {
	Name        string     `json:"name"`
	Ecosystem   string     `json:"ecosystem"`
	Kind        Kind       `json:"kind"`
	Old         []string   `json:"old,omitempty"`
	New         []string   `json:"new,omitempty"`
	Level       vers.Level `json:"-"`
	LevelString string     `json:"level,omitempty"`

	// Why the package is in the tree, when the lockfile records its
	// dependency graph. Origin is "direct", "transitive" or "" (unknown).
	// Via is the chain of dependencies from a direct dependency down to
	// (but excluding) this package, e.g. ["react-scripts", "webpack"].
	Origin string   `json:"origin,omitempty"`
	Via    []string `json:"via,omitempty"`

	// Filled in by the OSV layer.
	IntroducedVulns []Vuln `json:"introduced_vulns,omitempty"` // affect new, not old
	FixedVulns      []Vuln `json:"fixed_vulns,omitempty"`      // affected old, not new
	ExistingVulns   []Vuln `json:"existing_vulns,omitempty"`   // affect both
	// RemovedVulns lists advisories that affected a removed package's
	// pin. Informational only: dropping a dependency is not a fix (the
	// package may simply have moved to another lockfile), so these are
	// kept out of the fixed count, queue scoring, and -fail-on.
	RemovedVulns []Vuln `json:"removed_vulns,omitempty"`

	// Filled in by the deps.dev layer (registry metadata for the
	// version this change introduces).
	PublishedAt      string `json:"published_at,omitempty"` // RFC3339, UTC
	AgeDays          int    `json:"age_days,omitempty"`
	Fresh            bool   `json:"fresh,omitempty"` // younger than the cooldown window
	Deprecated       bool   `json:"deprecated,omitempty"`
	DeprecatedReason string `json:"deprecated_reason,omitempty"`

	// Unlisted: at least one incoming version is missing from the
	// registry metadata (deps.dev) even though other versions of the
	// same package are listed. That is what an unpublished or deleted
	// release looks like — registries pull malicious versions, so a
	// lockfile that still pins one is a red flag. (A release published
	// minutes ago may also not be indexed yet.)
	Unlisted         bool     `json:"unlisted,omitempty"`
	UnlistedVersions []string `json:"unlisted_versions,omitempty"`

	// ScriptsAdded: the outgoing version ran no install scripts, the
	// incoming one does (npm only; preinstall/install/postinstall, per
	// the registry's hasInstallScript). Adding execution-on-install in
	// an ordinary-looking bump is how several real npm supply-chain
	// attacks shipped their payload. ScriptedVersions lists the
	// incoming versions that carry scripts.
	ScriptsAdded     bool     `json:"install_scripts_added,omitempty"`
	ScriptedVersions []string `json:"scripted_versions,omitempty"`

	// ProvenanceDropped: every known outgoing version of this package
	// was published with sigstore provenance attestations, the incoming
	// one wasn't (npm, PyPI, crates.io). Legitimate CI keeps attesting; a stolen
	// publish token can publish but cannot make the pipeline attest,
	// so a silent drop is worth a look before trusting the release.
	// UnattestedVersions lists the incoming versions without provenance.
	ProvenanceDropped  bool     `json:"provenance_dropped,omitempty"`
	UnattestedVersions []string `json:"unattested_versions,omitempty"`

	// IntegrityChanged: a version pinned on BOTH sides now records a
	// different content hash — the lockfile expects different bytes for
	// the same version string. Registries never change a published
	// artifact, so outside a registry migration this means the tarball
	// was replaced (registry-side tampering, a hijacked mirror, or a
	// hand-edited lockfile). Compared per hash algorithm: a lockfile
	// upgrade that switches sha1 → sha512 is NOT flagged.
	IntegrityChanged  bool     `json:"integrity_changed,omitempty"`
	IntegrityVersions []string `json:"integrity_changed_versions,omitempty"`

	// DigestChanged: a container image tag pinned on both sides now pins
	// a different digest. Unlike registry tarballs, image tags MOVE by
	// design (base images are rebuilt for security fixes), so a digest
	// bump under an unchanged tag is routine — the row is shown
	// neutrally, and the ocireg layer verifies the new digest against
	// the registry instead: DigestVerified means the registry serves
	// exactly this digest for the tag today. A pin the registry does NOT
	// serve for the tag surfaces via TagMismatch; a digest the registry
	// has never seen at all surfaces via Unlisted. Conan recipe
	// revisions ride the same lane ("rrev:" pins): recipes are
	// re-exported for old versions routinely, so a same-version rrev
	// change is shown neutrally as a recipe-revision update.
	DigestChanged  bool   `json:"digest_changed,omitempty"`
	DigestVerified bool   `json:"digest_verified,omitempty"`
	OldDigest      string `json:"old_digest,omitempty"`
	NewDigest      string `json:"new_digest,omitempty"`

	// OldHost/NewHost: the registry hosts the package resolved from on
	// each side, when the lockfile records them and they differ.
	// RegistryMoved marks the dependency-confusion direction: the
	// resolution moved FROM a private/alternate host TO the ecosystem's
	// public registry — exactly what an attacker's higher-versioned
	// public squat of an internal package name looks like. Whole-file
	// mirror migrations (many packages moving between the same two
	// hosts) are recognized and not flagged.
	OldHost       string `json:"old_host,omitempty"`
	NewHost       string `json:"new_host,omitempty"`
	RegistryMoved bool   `json:"registry_moved,omitempty"`

	// ResolvedRefs maps a pinned ref to the release tag it equals, when
	// the upstream repository's tags were checked (GitHub Actions pins: a
	// commit SHA that is exactly the tag vX.Y.Z, or a floating major tag
	// v4 currently pointing at vX.Y.Z). Display and vulnerability
	// matching use the resolved version where available.
	ResolvedRefs map[string]string `json:"resolved_refs,omitempty"`

	// TyposquatOf: this package just entered the tree, its release is
	// young (or of unknown age), and its name is at most one edit away
	// from the named popular package on the same registry — the shape of
	// a typosquatting attack. Set by the squat layer; empty means clean.
	TyposquatOf string `json:"typosquat_of,omitempty"`

	// Channel: the registry channel the package resolves from, when
	// the lockfile records one — the conda channel for conda formats
	// (conda.anaconda.org/<ch>/…), the chart repository URL for Helm.
	// The condareg/helmreg layers key their lookups on it.
	Channel string `json:"-"`

	// NewPins: what the new lockfile itself pins for each incoming
	// version (a content hash, or "commit:<sha>" for git-resolved
	// formats), for layers that verify pins against the outside world.
	// Not serialized — pin-to-pin differences already surface as
	// IntegrityChanged.
	NewPins map[string]string `json:"-"`

	// TagMismatch: the lockfile pins a version at a commit that is NOT
	// what the upstream repository's tag for that version points at
	// today (SwiftPM: Package.resolved records both the version and the
	// resolved commit). Released tags are supposed to be immutable —
	// either the tag has been re-pointed since resolution (how the
	// tj-actions attack shipped), or the lockfile was edited to fetch a
	// different commit while displaying an innocent version.
	TagMismatch   bool     `json:"tag_mismatch,omitempty"`
	TagMismatches []string `json:"tag_mismatches,omitempty"`

	// NonRegistry: the lockfile says this package doesn't come from the
	// public registry (workspace member, path/git dependency). Suppresses
	// the unlisted flag; not serialized.
	NonRegistry bool `json:"-"`

	// License strings as the registry reports them (per side), and
	// whether the bump changes the license. Only set when deps.dev
	// knows both sides.
	OldLicense     string `json:"old_license,omitempty"`
	NewLicense     string `json:"new_license,omitempty"`
	LicenseChanged bool   `json:"license_changed,omitempty"`

	// Filled in by the changelog layer: the upstream repository and, when
	// both versions match real tags there, links that are verified not
	// to 404.
	SourceRepo string `json:"source_repo,omitempty"`
	CompareURL string `json:"compare_url,omitempty"` // upstream diff old → new
	ReleaseURL string `json:"release_url,omitempty"` // release/tag page for new

	// Filled in by the release-notes layer (opt-in via -changelogs):
	// upstream release notes covering the versions this bump pulls in,
	// newest first.
	ReleaseNotes []ReleaseNote `json:"release_notes,omitempty"`

	// Findings acknowledged via a .lockvetignore file. Ignored lists the
	// suppressed finding kinds ("fresh", "major", …); IgnoredVulns holds
	// advisories moved out of IntroducedVulns. Both stay visible in JSON
	// and as a dim marker in reports, but no longer count toward the
	// summary or -fail-on gates.
	Ignored      []string `json:"ignored,omitempty"`
	IgnoredVulns []Vuln   `json:"ignored_vulns,omitempty"`
}

// HasIgnored reports whether the finding kind was suppressed on this
// change via a .lockvetignore rule.
func (c *Change) HasIgnored(kind string) bool {
	for _, k := range c.Ignored {
		if k == kind {
			return true
		}
	}
	return false
}

// ReleaseNote is one upstream release's notes, excerpted.
type ReleaseNote struct {
	Tag     string `json:"tag"`
	Title   string `json:"title,omitempty"`
	URL     string `json:"url"`
	Excerpt string `json:"excerpt,omitempty"`
}

// Vuln is a known vulnerability reference.
type Vuln struct {
	ID       string `json:"id"`
	Summary  string `json:"summary,omitempty"`
	Severity string `json:"severity,omitempty"`
	URL      string `json:"url,omitempty"`
	// FixedIn is the smallest version that clears this advisory for the
	// pinned version(s), read from the advisory's own ranges. Empty when
	// no fix has been released or the ranges don't say.
	FixedIn string `json:"fixed_in,omitempty"`
}

// FileDiff is the set of changes within one lockfile.
type FileDiff struct {
	Path      string   `json:"path"`
	Kind      string   `json:"lockfile"`
	Ecosystem string   `json:"ecosystem"`
	Changes   []Change `json:"changes"`
}

// Diff compares two parsed lockfiles (either may be nil for created/deleted).
func Diff(oldF, newF *lock.File) FileDiff {
	ref := newF
	if ref == nil {
		ref = oldF
	}
	fd := FileDiff{Path: ref.Path, Kind: ref.Kind, Ecosystem: string(ref.Ecosystem)}

	names := map[string]bool{}
	oldPkgs, newPkgs := map[string][]string{}, map[string][]string{}
	if oldF != nil {
		oldPkgs = oldF.Packages
	}
	if newF != nil {
		newPkgs = newF.Packages
	}
	for n := range oldPkgs {
		names[n] = true
	}
	for n := range newPkgs {
		names[n] = true
	}

	// Per-package ecosystem override (SBOMs mix ecosystems in one file).
	ecoOf := func(name string) lock.Ecosystem {
		if newF != nil {
			if e, ok := newF.PkgEco[name]; ok {
				return e
			}
		}
		if oldF != nil {
			if e, ok := oldF.PkgEco[name]; ok {
				return e
			}
		}
		return ref.Ecosystem
	}

	// Per-package conda channel, from whichever side records one.
	channelOf := func(name string) string {
		if newF != nil {
			if ch, ok := newF.PkgChannel[name]; ok {
				return ch
			}
		}
		if oldF != nil {
			if ch, ok := oldF.PkgChannel[name]; ok {
				return ch
			}
		}
		return ""
	}

	// Per-package source repository, when the lockfile itself records one
	// (Nix flake inputs). When BOTH sides record a repository and they
	// disagree, the input was re-pointed at a different repository: no
	// SourceRepo is set (a compare link across two repos would lie) — the
	// move itself still surfaces through the pins' host fields.
	repoOf := func(name string) string {
		var o, n string
		if oldF != nil {
			o = oldF.PkgRepo[name]
		}
		if newF != nil {
			n = newF.PkgRepo[name]
		}
		if o != "" && n != "" && o != n {
			return ""
		}
		if n != "" {
			return n
		}
		return o
	}

	// Carry the new side's own pins (hash or commit) on the change, for
	// layers that verify them against the outside world (swiftreg).
	newPinsOf := func(name string, versions []string) map[string]string {
		if newF == nil || newF.Pins == nil {
			return nil
		}
		var m map[string]string
		for _, v := range versions {
			if pin := newF.Pin(name, v); pin.Integrity != "" {
				if m == nil {
					m = map[string]string{}
				}
				m[v] = pin.Integrity
			}
		}
		return m
	}

	// The lockfile itself can admit an incoming version is yanked from
	// its registry (Bazel's selectedYankedVersions, written when the
	// build passes --allow_yanked_versions): a fully-offline deprecation
	// signal, no registry roundtrip needed.
	yankedOf := func(name string, versions []string) string {
		if newF == nil || newF.PkgYanked == nil {
			return ""
		}
		for _, v := range versions {
			if r, ok := newF.PkgYanked[name+"@"+v]; ok {
				if r == "" {
					r = "no reason recorded"
				}
				return "version " + v + " is yanked from the registry (allowed via --allow_yanked_versions): " + r
			}
		}
		return ""
	}

	hostMoves := countHostMoves(oldF, newF)
	// Pins-only files (go.sum) exist to record hashes for a sibling
	// manifest: their version churn duplicates the manifest's rows, so
	// only same-version repins — the tampered-hash shape — surface.
	pinsOnly := (oldF != nil && oldF.PinsOnly) || (newF != nil && newF.PinsOnly)
	for name := range names {
		o, n := oldPkgs[name], newPkgs[name]
		if equal(o, n) {
			// Same version(s) on both sides — but did the lockfile change
			// WHAT it pins for them? A different integrity hash or a
			// resolution moved onto the public registry is a finding of
			// its own (tarball swapped / dependency-confusion shape).
			c := Change{Name: name, Ecosystem: string(ecoOf(name)), Kind: Repinned, Old: o, New: n, Channel: channelOf(name), SourceRepo: repoOf(name), NewPins: newPinsOf(name, n)}
			if annotatePinChange(&c, oldF, newF, hostMoves) {
				if (newF != nil && newF.NonRegistry[name]) || (oldF != nil && oldF.NonRegistry[name]) {
					c.NonRegistry = true
				}
				fd.Changes = append(fd.Changes, c)
			}
			continue
		}
		if pinsOnly {
			// Version churn is the sibling manifest's row, not ours — but
			// versions present on BOTH sides still get the repin check
			// (an untidied go.sum can grow entries in the same edit that
			// swaps an existing version's hash).
			if common := intersectVersions(o, n); len(common) > 0 {
				c := Change{Name: name, Ecosystem: string(ecoOf(name)), Kind: Repinned, Old: common, New: common, NewPins: newPinsOf(name, common)}
				if annotatePinChange(&c, oldF, newF, hostMoves) && c.IntegrityChanged {
					fd.Changes = append(fd.Changes, c)
				}
			}
			continue
		}
		eco := ecoOf(name)
		c := Change{Name: name, Ecosystem: string(eco), Old: o, New: n, Channel: channelOf(name), SourceRepo: repoOf(name), NewPins: newPinsOf(name, n)}
		annotatePinChange(&c, oldF, newF, hostMoves)
		if r := yankedOf(name, n); r != "" {
			c.Deprecated = true
			c.DeprecatedReason = r
		}
		if (newF != nil && newF.NonRegistry[name]) || (oldF != nil && oldF.NonRegistry[name]) {
			c.NonRegistry = true
		}
		switch {
		case len(o) == 0:
			c.Kind = Added
		case len(n) == 0:
			c.Kind = Removed
		case len(o) == 1 && len(n) == 1:
			if vers.Compare(o[0], n[0]) < 0 {
				c.Kind = Upgraded
			} else {
				c.Kind = Downgraded
			}
			c.Level = vers.Delta(o[0], n[0])
			c.LevelString = c.Level.String()
		default:
			c.Kind = Changed
			c.Level = maxDelta(o, n)
			c.LevelString = c.Level.String()
		}
		if !eco.HasSemver() {
			// e.g. Nix flake inputs: pinned git revs, not versions —
			// major/minor/patch labels would be noise.
			c.Level = vers.None
			c.LevelString = ""
		}
		if (eco == lock.GitHubActions || eco == lock.PreCommit || eco == lock.GitLabCI || eco == lock.Vcpkg) && (c.Kind == Upgraded || c.Kind == Downgraded) &&
			(looksCommit(o) || looksCommit(n)) {
			// SHA pins order as hex strings, which means nothing: call it
			// "changed" until actreg resolves the commits to releases.
			c.Kind = Changed
			c.Level = vers.Unknown
			c.LevelString = c.Level.String()
		}
		if eco == lock.Zig && (c.Kind == Upgraded || c.Kind == Downgraded) &&
			(looksOpaque(o) || looksOpaque(n)) {
			// build.zig.zon deps without a real version pin commit revs or
			// hash-digest prefixes: those order as strings, which means
			// nothing — report the bump without pretending a direction.
			c.Kind = Changed
			c.Level = vers.Unknown
			c.LevelString = c.Level.String()
		}
		fd.Changes = append(fd.Changes, c)
	}

	annotateOrigins(fd.Changes, oldF, newF)

	fd.Sort()
	return fd
}

// Sort orders changes most-alarming first (major level, then kind, then
// name). Diff calls it; annotation layers that rewrite levels afterwards
// (actreg resolving SHA pins to tags) call it again.
func (fd *FileDiff) Sort() {
	sort.Slice(fd.Changes, func(i, j int) bool {
		a, b := fd.Changes[i], fd.Changes[j]
		if a.Level != b.Level {
			return a.Level > b.Level // major first
		}
		if a.Kind != b.Kind {
			return kindRank(a.Kind) < kindRank(b.Kind)
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
}

// looksOpaque reports whether any version in the set is NOT shaped like a
// release version ("1.2.3", "v0.13.1"): abbreviated commit revs and
// base64 hash-digest prefixes fail the digits-then-dot test.
func looksOpaque(vs []string) bool {
	for _, v := range vs {
		s := strings.TrimPrefix(v, "v")
		i := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == 0 || i >= len(s) || s[i] != '.' {
			return true
		}
	}
	return false
}

// looksCommit reports whether any version in the set is shaped like an
// (abbreviated) git commit SHA.
func looksCommit(vs []string) bool {
	for _, v := range vs {
		if len(v) < 7 || len(v) > 40 {
			continue
		}
		hex, letter := true, false
		for i := 0; i < len(v); i++ {
			switch b := v[i]; {
			case b >= '0' && b <= '9':
			case b >= 'a' && b <= 'f', b >= 'A' && b <= 'F':
				letter = true
			default:
				hex = false
			}
		}
		if hex && (letter || len(v) == 40) {
			return true
		}
	}
	return false
}

func kindRank(k Kind) int {
	switch k {
	case Repinned:
		return 0 // same version, different bytes/registry — most alarming
	case Downgraded:
		return 1
	case Upgraded:
		return 2
	case Changed:
		return 3
	case Added:
		return 4
	case Removed:
		return 5
	}
	return 6
}

// maxDelta classifies a multi-version change (a package vendored at several
// versions at once, e.g. fs-extra 10.x + 11.x in one npm tree). Versions
// present on both sides are unchanged and must not influence the level:
// {10.1.0, 11.3.5} → {10.1.0, 11.3.6} is a patch, not a major. The remaining
// versions are sorted and paired positionally (clamped), and the largest
// paired delta wins.
func maxDelta(o, n []string) vers.Level {
	ro, rn := trimCommon(o, n)
	if len(ro) == 0 {
		ro = append([]string(nil), o...) // copies only added: vs nearest kept
	}
	if len(rn) == 0 {
		rn = append([]string(nil), n...) // copies only removed
	}
	if len(ro) == 0 || len(rn) == 0 {
		return vers.None
	}
	sort.Slice(ro, func(i, j int) bool { return vers.Compare(ro[i], ro[j]) < 0 })
	sort.Slice(rn, func(i, j int) bool { return vers.Compare(rn[i], rn[j]) < 0 })
	max := vers.None
	steps := len(ro)
	if len(rn) > steps {
		steps = len(rn)
	}
	for i := 0; i < steps; i++ {
		ov := ro[clamp(i, len(ro))]
		nv := rn[clamp(i, len(rn))]
		if d := vers.Delta(ov, nv); d != vers.Unknown && d > max {
			max = d
		}
	}
	return max
}

func clamp(i, n int) int {
	if i >= n {
		return n - 1
	}
	return i
}

// trimCommon removes the multiset intersection from both version lists.
func trimCommon(o, n []string) (ro, rn []string) {
	count := map[string]int{}
	for _, v := range o {
		count[v]++
	}
	for _, v := range n {
		if count[v] > 0 {
			count[v]--
		} else {
			rn = append(rn, v)
		}
	}
	for _, v := range o {
		if count[v] > 0 {
			count[v]--
			ro = append(ro, v)
		}
	}
	return ro, rn
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// graphInfo is a per-lockfile view of the dependency graph used to
// classify changes as direct or transitive.
type graphInfo struct {
	roots  map[string]bool
	parent map[string]string // BFS tree: package -> the package that pulled it in
}

// buildGraph derives roots and shortest pull-in chains from a lockfile.
// Returns nil when the format records no graph information.
func buildGraph(f *lock.File) *graphInfo {
	if f == nil || (!f.RootsKnown && len(f.Deps) == 0) {
		return nil
	}
	g := &graphInfo{roots: map[string]bool{}, parent: map[string]string{}}
	var queue []string
	if f.RootsKnown {
		for _, r := range f.Roots {
			g.roots[r] = true
		}
	} else {
		// No recorded roots (yarn classic, poetry, composer): treat
		// packages nothing depends on as the likely direct set.
		hasParent := map[string]bool{}
		for _, deps := range f.Deps {
			for _, d := range deps {
				hasParent[d] = true
			}
		}
		for name := range f.Packages {
			if !hasParent[name] {
				g.roots[name] = true
			}
		}
	}
	for r := range g.roots {
		queue = append(queue, r)
	}
	sort.Strings(queue) // deterministic BFS => deterministic chains
	seen := map[string]bool{}
	for _, r := range queue {
		seen[r] = true
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		deps := append([]string(nil), f.Deps[cur]...)
		sort.Strings(deps)
		for _, d := range deps {
			if seen[d] {
				continue
			}
			seen[d] = true
			g.parent[d] = cur
			queue = append(queue, d)
		}
	}
	return g
}

// classify returns ("direct"|"transitive"|"", chain). The chain runs from a
// direct dependency down to the package's immediate dependent.
func (g *graphInfo) classify(name string) (string, []string) {
	if g == nil {
		return "", nil
	}
	if g.roots[name] {
		return "direct", nil
	}
	if _, ok := g.parent[name]; !ok {
		// Graph info exists but no path found (go.mod has no edges;
		// cycles; optional peers): still known to be non-direct.
		return "transitive", nil
	}
	var chain []string
	for cur := g.parent[name]; ; cur = g.parent[cur] {
		chain = append(chain, cur)
		if _, ok := g.parent[cur]; !ok {
			break
		}
		if len(chain) > 32 { // safety against unexpected cycles
			break
		}
	}
	// reverse: root first
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return "transitive", chain
}

// annotateOrigins fills Origin/Via on each change, using the new lockfile's
// graph (the old one for removed packages).
func annotateOrigins(changes []Change, oldF, newF *lock.File) {
	gNew, gOld := buildGraph(newF), buildGraph(oldF)
	for i := range changes {
		g := gNew
		if changes[i].Kind == Removed {
			g = gOld
		}
		changes[i].Origin, changes[i].Via = g.classify(changes[i].Name)
	}
}

// Filter keeps only the changes whose package name — or any package in
// their via chain — matches one of the comma-separated glob patterns.
// Matching is case-insensitive; '*' matches any run of characters
// (including '/', so "*sys*" matches "golang.org/x/sys") and '?' matches
// one character. Matching via chains means "-only jiff" also shows every
// transitive change that jiff dragged in.
func Filter(diffs []FileDiff, patterns string) []FileDiff {
	res := compilePatterns(patterns)
	if len(res) == 0 {
		return diffs
	}
	var out []FileDiff
	for _, fd := range diffs {
		var kept []Change
		for _, c := range fd.Changes {
			if matchAny(res, c.Name) || matchAnyOf(res, c.Via) {
				kept = append(kept, c)
			}
		}
		if len(kept) > 0 {
			fd.Changes = kept
			out = append(out, fd)
		}
	}
	return out
}

func compilePatterns(patterns string) []*regexp.Regexp {
	var res []*regexp.Regexp
	for _, p := range strings.Split(patterns, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var b strings.Builder
		b.WriteString("(?i)^")
		for _, r := range p {
			switch r {
			case '*':
				b.WriteString(".*")
			case '?':
				b.WriteString(".")
			default:
				b.WriteString(regexp.QuoteMeta(string(r)))
			}
		}
		b.WriteString("$")
		// The pattern is fully escaped above, so this cannot fail.
		res = append(res, regexp.MustCompile(b.String()))
	}
	return res
}

func matchAny(res []*regexp.Regexp, name string) bool {
	for _, re := range res {
		if re.MatchString(name) {
			return true
		}
	}
	return false
}

func matchAnyOf(res []*regexp.Regexp, names []string) bool {
	for _, n := range names {
		if matchAny(res, n) {
			return true
		}
	}
	return false
}

// Summary aggregates counts across file diffs.
type Summary struct {
	Total, Major, Minor, Patch, Added, Removed, Downgraded int
	VulnsIntroduced, VulnsFixed, VulnsExisting             int
	Fresh, Deprecated, LicenseChanged, Unlisted            int
	ScriptsAdded                                           int // npm bumps that newly run install scripts
	Typosquats                                             int // young additions confusable with a popular package
	ProvenanceDropped                                      int // npm bumps that silently stop attesting provenance
	IntegrityChanged                                       int // pins whose recorded content hash changed for an unchanged version
	TagMismatch                                            int // pins whose commit is not what the upstream tag points at
	RegistryMoved                                          int // resolutions moved from a private host to the public registry
	Direct, Transitive                                     int // 0/0 when the formats record no graph
	Ignored                                                int // findings acknowledged via .lockvetignore
}

// Summarize computes totals for a set of file diffs.
func Summarize(diffs []FileDiff) Summary {
	var s Summary
	for _, fd := range diffs {
		for _, c := range fd.Changes {
			s.Total++
			switch c.Kind {
			case Added:
				s.Added++
			case Removed:
				s.Removed++
			case Downgraded:
				if !c.HasIgnored("downgrade") {
					s.Downgraded++
				}
			}
			if c.Kind == Upgraded || c.Kind == Downgraded || c.Kind == Changed {
				switch c.Level {
				case vers.Major:
					if !c.HasIgnored("major") {
						s.Major++
					}
				case vers.Minor:
					s.Minor++
				case vers.Patch:
					s.Patch++
				}
			}
			s.VulnsIntroduced += len(c.IntroducedVulns)
			s.VulnsFixed += len(c.FixedVulns)
			s.VulnsExisting += len(c.ExistingVulns)
			if c.Fresh {
				s.Fresh++
			}
			if c.Deprecated {
				s.Deprecated++
			}
			if c.Unlisted {
				s.Unlisted++
			}
			if c.ScriptsAdded {
				s.ScriptsAdded++
			}
			if c.TyposquatOf != "" && !c.HasIgnored("typosquat") {
				s.Typosquats++
			}
			if c.ProvenanceDropped {
				s.ProvenanceDropped++
			}
			if c.IntegrityChanged && !c.HasIgnored("integrity") {
				s.IntegrityChanged++
			}
			if c.TagMismatch && !c.HasIgnored("integrity") {
				s.TagMismatch++
			}
			if c.RegistryMoved && !c.HasIgnored("registry") {
				s.RegistryMoved++
			}
			if c.LicenseChanged {
				s.LicenseChanged++
			}
			s.Ignored += len(c.Ignored) + len(c.IgnoredVulns)
			switch c.Origin {
			case "direct":
				s.Direct++
			case "transitive":
				s.Transitive++
			}
		}
	}
	return s
}
