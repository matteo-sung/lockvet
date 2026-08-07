package diffx

import (
	"sort"
	"strings"

	"github.com/matteo-sung/lockvet/internal/lock"
)

// migrationThreshold: when at least this many packages in one lockfile move
// between the SAME two registry hosts, that is a registry/mirror migration
// (a config change), not a per-package attack — the per-package
// registry-moved flag is suppressed for that pair. Dependency-confusion
// attacks move one package, or very few.
const migrationThreshold = 5

type hostPair struct{ old, new string }

// countHostMoves tallies, per (oldHost → newHost) pair, how many packages in
// the file moved between those hosts — including packages whose versions
// didn't change, which never become diff rows.
func countHostMoves(oldF, newF *lock.File) map[hostPair]int {
	if oldF == nil || newF == nil || oldF.Pins == nil || newF.Pins == nil {
		return nil
	}
	counts := map[hostPair]int{}
	for name, oldVers := range oldF.Packages {
		newVers, ok := newF.Packages[name]
		if !ok {
			continue
		}
		oh := commonHost(oldF, name, oldVers)
		nh := commonHost(newF, name, newVers)
		if oh != "" && nh != "" && oh != nh {
			counts[hostPair{oh, nh}]++
		}
	}
	return counts
}

// commonHost returns the registry host recorded for the package if every
// version that records one agrees; "" otherwise.
func commonHost(f *lock.File, name string, versions []string) string {
	host := ""
	for _, v := range versions {
		h := f.Pin(name, v).Host
		if h == "" {
			continue
		}
		if host == "" {
			host = h
		} else if host != h {
			return ""
		}
	}
	return host
}

// annotatePinChange fills integrity/host findings on one change. Returns
// true when it found something row-worthy (used to surface same-version
// repins that would otherwise not be diff rows).
func annotatePinChange(c *Change, oldF, newF *lock.File, moves map[hostPair]int) bool {
	if oldF == nil || newF == nil {
		return false // added/removed files: nothing to compare against
	}
	name := c.Name
	if sideEco(oldF, name) != sideEco(newF, name) {
		// The package switched package managers between the two sides
		// (pixi/conda locks: a conda package became a PyPI wheel or vice
		// versa). Hashes and hosts legitimately change wholesale.
		return false
	}
	// Integrity: compare versions present on both sides.
	common := intersectVersions(c.Old, c.New)
	sameBytesProven := len(common) > 0
	for _, v := range common {
		oi := oldF.Pin(name, v).Integrity
		ni := newF.Pin(name, v).Integrity
		if oi == "" || ni == "" {
			sameBytesProven = false
			continue
		}
		if integrityDiffers(oi, ni) {
			c.IntegrityChanged = true
			c.IntegrityVersions = append(c.IntegrityVersions, v)
		}
		if !integritySame(oi, ni) {
			sameBytesProven = false
		}
	}
	sort.Strings(c.IntegrityVersions)

	// Resolution host.
	oh := commonHost(oldF, name, c.Old)
	nh := commonHost(newF, name, c.New)
	if oh != "" && nh != "" && oh != nh {
		c.OldHost, c.NewHost = oh, nh
		eco := lock.Ecosystem(c.Ecosystem)
		switch {
		case eco == lock.Nix:
			// Flake "hosts" are whole repository locations: a host move
			// means the input was re-pointed at a different repository —
			// the flake shape of a hijacked resolution. Content proven
			// identical (same narHash) stays quiet.
			if moves[hostPair{oh, nh}] < migrationThreshold && !sameBytesProven {
				c.RegistryMoved = true
			}
		case eco.PublicRegistryHost(nh) && !eco.PublicRegistryHost(oh) &&
			moves[hostPair{oh, nh}] < migrationThreshold && !sameBytesProven:
			c.RegistryMoved = true
		}
	}
	return c.IntegrityChanged || c.RegistryMoved
}

// sideEco is the ecosystem one side resolves the package with (per-package
// override for SBOM / conda+pip mixed files, else the file's ecosystem).
func sideEco(f *lock.File, name string) lock.Ecosystem {
	if e, ok := f.PkgEco[name]; ok {
		return e
	}
	return f.Ecosystem
}

// intersectVersions returns versions present in both lists (set semantics).
func intersectVersions(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 {
		return nil
	}
	in := map[string]bool{}
	for _, v := range a {
		in[v] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, v := range b {
		if in[v] && !seen[v] {
			out = append(out, v)
			seen[v] = true
		}
	}
	return out
}

// integrityDiffers compares two hash sets algorithm-by-algorithm. Only
// algorithms present on BOTH sides are compared, so a lockfile-format
// upgrade that switches sha1 → sha512 (or yarn berry's cache-key bumps)
// never flags. Within a shared algorithm, any overlapping hash means the
// same artifact is still acceptable — Python lockfiles legitimately GROW
// the hash set when new wheels are added for an existing release.
func integrityDiffers(oldSet, newSet string) bool {
	oldBy := hashesByAlgo(oldSet)
	newBy := hashesByAlgo(newSet)
	sharedAlgo, overlap := false, false
	for algo, oldHashes := range oldBy {
		newHashes, ok := newBy[algo]
		if !ok {
			continue // algo upgrades / added artifacts never flag
		}
		if strings.Contains(algo, "#") {
			// Artifact-scoped (Gradle verification metadata): the SAME
			// file losing every previously accepted hash means its bytes
			// changed — regardless of the component's other artifacts.
			shared := false
			for h := range oldHashes {
				if newHashes[h] {
					shared = true
					break
				}
			}
			if !shared {
				return true
			}
			continue
		}
		sharedAlgo = true
		for h := range oldHashes {
			if newHashes[h] {
				overlap = true
			}
		}
	}
	return sharedAlgo && !overlap // comparable and fully disjoint → changed
}

// integritySame reports whether the two hash sets share at least one
// (algorithm, hash) pair — proof the same artifact is referenced.
func integritySame(oldSet, newSet string) bool {
	oldBy := hashesByAlgo(oldSet)
	newBy := hashesByAlgo(newSet)
	for algo, oldHashes := range oldBy {
		for h := range oldHashes {
			if newBy[algo][h] {
				return true
			}
		}
	}
	return false
}

// hashesByAlgo groups a space-joined hash set by algorithm label.
// Recognized notations: "sha512-…" (npm SRI), "sha256:…" (Python/OCI),
// "10c0/…" (yarn berry cache key), bare 40-hex (sha1), bare 64-hex (sha256).
func hashesByAlgo(set string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, h := range strings.Fields(set) {
		algo, val := splitHash(h)
		if algo == "" || val == "" {
			continue
		}
		if out[algo] == nil {
			out[algo] = map[string]bool{}
		}
		out[algo][val] = true
	}
	return out
}

func splitHash(h string) (algo, val string) {
	// Artifact-scoped notation "file.jar#sha256:hex" (Gradle verification
	// metadata records several artifacts per component; each file's hash
	// set is compared on its own).
	if i := strings.IndexByte(h, '#'); i > 0 && i < len(h)-1 {
		algo, val = splitHash(h[i+1:])
		if algo == "" {
			return "", ""
		}
		return h[:i] + "#" + algo, val
	}
	for _, sep := range []byte{'-', ':', '/'} {
		if i := strings.IndexByte(h, sep); i > 0 {
			// require a plausible algorithm label, not a hash that merely
			// contains the separator (npm SRI base64 contains '-')
			label := strings.ToLower(h[:i])
			if len(label) <= 8 && isAlgoLabel(label) {
				return label, h[i+1:]
			}
		}
	}
	if isHex(h) {
		switch len(h) {
		case 40:
			return "sha1", h
		case 64:
			return "sha256", h
		case 128:
			return "sha512", h
		}
	}
	return "", ""
}

func isAlgoLabel(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
