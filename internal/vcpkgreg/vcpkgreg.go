// Package vcpkgreg verifies what vcpkg manifests pin. There is no OSV
// ecosystem and no deps.dev system for vcpkg, so this package IS the
// metadata layer:
//
//   - Baseline commits ("builtin-baseline", registry baselines from
//     vcpkg-configuration.json) are looked up in the registry's own
//     repository via the GitHub commits API: the commit's date becomes
//     the release age (a freshly-bumped baseline that is itself two
//     years old is worth seeing), and old...new compare links let a
//     reviewer read exactly what the registry picked up. A baseline
//     that is NOT a commit in the registry's repository is the
//     poisoned-registry shape — the build only resolves on a fork that
//     carries the commit — and lands in the ▲ lane. The claim is gated:
//     it is only made when the OUTGOING baseline does resolve (proving
//     the repository is reachable and the project really tracks it),
//     and absence is re-proven with an uncached fetch.
//
//   - Override pins are checked against microsoft/vcpkg's versions
//     database (versions/{c}-/{name}.json), which is append-only:
//     shipped versions are never removed, so a version the database has
//     never listed is real evidence. Also gated on the outgoing
//     version being present (projects overriding from overlay ports or
//     custom registries never had their versions in the official
//     database, and the parser additionally marks overrides NonRegistry
//     when the manifest's own configuration says they resolve
//     elsewhere), compared ignoring the port-version suffix (overlay
//     ports routinely bump #N on an official version), and re-proven
//     uncached before any claim.
//
// api.github.com and raw.githubusercontent.com both send
// Access-Control-Allow-Origin: *, so this layer also works in the
// browser (wasm) playground.
package vcpkgreg

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/hcache"
	"github.com/matteo-sung/lockvet/internal/taglink"
)

// APIBase is the GitHub API host; a var so tests can fake it.
var APIBase = "https://api.github.com"

// RawBase serves the versions database; a var so tests can fake it.
var RawBase = "https://raw.githubusercontent.com"

// Enabled gates the whole layer.
var Enabled = true

// Now is the clock; a var so tests can pin it.
var Now = time.Now

var client = hcache.Client(15 * time.Second)

// liveClient is deliberately uncached: absence evidence is re-proven on
// every run, like every other unlisted path.
var liveClient = &http.Client{Timeout: 15 * time.Second}

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

// Annotate fills vcpkg metadata on the diffs; see the package comment.
// token is an optional GitHub token (raises the anonymous rate limit).
// The returned bool reports whether any pin was actually checked.
func Annotate(diffs []diffx.FileDiff, freshDays int, token string) (bool, error) {
	if !Enabled {
		return false, nil
	}
	var baselines, overrides []*diffx.Change
	var pkgMode []bool
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "vcpkg" {
				continue
			}
			if vcpkgBaselineChange(c) {
				baselines = append(baselines, c)
			} else if !c.NonRegistry {
				overrides = append(overrides, c)
				pkgMode = append(pkgMode, diffs[i].Kind == "pkg")
			}
		}
	}
	if len(baselines) == 0 && len(overrides) == 0 {
		return false, nil
	}

	checked := false
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	for _, c := range baselines {
		ok, err := annotateBaseline(c, freshDays, token)
		checked = checked || ok
		note(err)
	}

	portCache := map[string]map[string]bool{} // port -> base-version set (nil value = unknown port)
	for i, c := range overrides {
		ok, err := annotateOverride(c, portCache, pkgMode[i])
		checked = checked || ok
		note(err)
	}

	if checked {
		return true, nil
	}
	return false, firstErr
}

// vcpkgBaselineChange reports whether the change pins a registry
// baseline commit rather than a port version.
func vcpkgBaselineChange(c *diffx.Change) bool {
	if c.Name != "builtin-baseline" && c.Name != "default-registry" &&
		!strings.HasPrefix(c.Name, "registry ") {
		return false
	}
	for _, v := range append(append([]string{}, c.Old...), c.New...) {
		if !hexShaped(v) {
			return false
		}
	}
	return true
}

func hexShaped(s string) bool {
	if len(s) < 7 || len(s) > 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func annotateBaseline(c *diffx.Change, freshDays int, token string) (bool, error) {
	if c.SourceRepo == "" {
		return false, nil
	}
	// Compare link: revisions address themselves.
	if c.CompareURL == "" && len(c.Old) == 1 && len(c.New) == 1 && c.Old[0] != c.New[0] {
		c.CompareURL = taglink.CompareRevsURL(c.SourceRepo, c.Old[0], c.New[0])
	}
	owner, repo := githubRepo(c.SourceRepo)
	if owner == "" || len(c.New) != 1 {
		return c.CompareURL != "", nil
	}

	newDate, newStatus, err := commitLookup(client, owner, repo, c.New[0], token)
	if err != nil {
		return false, err
	}
	switch {
	case newStatus == 200:
		if !newDate.IsZero() && c.PublishedAt == "" {
			c.PublishedAt = newDate.UTC().Format(time.RFC3339)
			if age := int(Now().Sub(newDate).Hours() / 24); age >= 0 {
				c.AgeDays = age
				c.Fresh = freshDays > 0 && Now().Sub(newDate) < time.Duration(freshDays)*24*time.Hour
			}
		}
	case newStatus == 404 || newStatus == 422:
		// Gate: only claim when the outgoing baseline resolves.
		if len(c.Old) != 1 {
			return true, nil
		}
		_, oldStatus, err := commitLookup(client, owner, repo, c.Old[0], token)
		if err != nil || oldStatus != 200 {
			return true, nil
		}
		// Re-prove absence uncached before claiming.
		_, liveStatus, err := commitLookup(liveClient, owner, repo, c.New[0], token)
		if err != nil || (liveStatus != 404 && liveStatus != 422) {
			return true, nil
		}
		c.Unlisted = true
		c.UnlistedVersions = append(c.UnlistedVersions, c.New[0])
	default:
		// Rate-limited or otherwise unreadable: no claims.
		return false, nil
	}
	return true, nil
}

// commitLookup asks the GitHub API for a commit; returns its committer
// date and the HTTP status (200, or 404/422 for an unknown sha).
func commitLookup(cl *http.Client, owner, repo, sha, token string) (time.Time, int, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/commits/%s", APIBase, owner, repo, sha)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return time.Time{}, 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", userAgent)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := cl.Do(req)
	if err != nil {
		return time.Time{}, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return time.Time{}, 0, err
	}
	if resp.StatusCode != 200 {
		return time.Time{}, resp.StatusCode, nil
	}
	var doc struct {
		Commit struct {
			Committer struct {
				Date time.Time `json:"date"`
			} `json:"committer"`
			Author struct {
				Date time.Time `json:"date"`
			} `json:"author"`
		} `json:"commit"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return time.Time{}, 0, err
	}
	d := doc.Commit.Committer.Date
	if d.IsZero() {
		d = doc.Commit.Author.Date
	}
	return d, 200, nil
}

func githubRepo(repoURL string) (owner, repo string) {
	rest, ok := strings.CutPrefix(strings.ToLower(repoURL), "https://github.com/")
	if !ok {
		return "", ""
	}
	parts := strings.Split(strings.TrimSuffix(rest, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", ""
	}
	return parts[0], parts[1]
}

// pkgMode relaxes the outgoing-version gate: a `lockvet pkg vcpkg:...`
// question is explicitly about the official registry, so an Added-side
// synthetic change with no outgoing version still gets existence claims
// (the port-known gate and the uncached re-prove still apply).
func annotateOverride(c *diffx.Change, cache map[string]map[string]bool, pkgMode bool) (bool, error) {
	if len(c.New) == 0 || (len(c.Old) == 0 && !pkgMode) {
		// In a manifest diff, added overrides can't pass the
		// outgoing-version gate (overlay ports the configuration doesn't
		// mention would FP); make no claims and spend no requests.
		return false, nil
	}
	port := strings.ToLower(c.Name)
	if !validPortName(port) {
		return false, nil
	}
	versions, fetched, err := portVersions(client, port, cache)
	if err != nil {
		return false, err
	}
	if versions == nil {
		// Unknown port: overlay or custom registry — no claims.
		return fetched, nil
	}
	// Gate: every outgoing version must be known to the database.
	for _, v := range c.Old {
		if !versions[baseVersion(v)] {
			return true, nil
		}
	}
	var missing []string
	for _, v := range c.New {
		if !versions[baseVersion(v)] {
			missing = append(missing, v)
		}
	}
	if len(missing) == 0 {
		return true, nil
	}
	// Re-prove absence uncached before claiming.
	live, _, err := portVersions(liveClient, port, nil)
	if err != nil || live == nil {
		return true, nil
	}
	missing = missing[:0]
	for _, v := range c.New {
		if !live[baseVersion(v)] {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		c.Unlisted = true
		c.UnlistedVersions = append(c.UnlistedVersions, missing...)
	}
	return true, nil
}

// baseVersion strips the "#port-version" suffix: overlay ports routinely
// re-cut an official version with a bumped port-version, so only the
// upstream version participates in existence claims.
func baseVersion(v string) string {
	if i := strings.IndexByte(v, '#'); i >= 0 {
		return v[:i]
	}
	return v
}

func validPortName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// portVersions fetches the port's versions-database file and returns the
// set of base versions it lists; (nil, true, nil) means the port is
// unknown to the official registry. cache may be nil.
func portVersions(cl *http.Client, port string, cache map[string]map[string]bool) (map[string]bool, bool, error) {
	if cache != nil {
		if v, ok := cache[port]; ok {
			return v, false, nil
		}
	}
	url := fmt.Sprintf("%s/microsoft/vcpkg/master/versions/%s-/%s.json", RawBase, port[:1], port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, false, err
	}
	if resp.StatusCode == 404 {
		if cache != nil {
			cache[port] = nil
		}
		return nil, true, nil
	}
	if resp.StatusCode != 200 {
		return nil, false, fmt.Errorf("versions database: HTTP %d for %s", resp.StatusCode, port)
	}
	var doc struct {
		Versions []struct {
			Version       string `json:"version"`
			VersionSemver string `json:"version-semver"`
			VersionDate   string `json:"version-date"`
			VersionString string `json:"version-string"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, false, err
	}
	set := map[string]bool{}
	for _, v := range doc.Versions {
		for _, s := range []string{v.Version, v.VersionSemver, v.VersionDate, v.VersionString} {
			if s != "" {
				set[s] = true
			}
		}
	}
	if cache != nil {
		cache[port] = set
	}
	return set, true, nil
}

// Latest returns the newest version the official registry lists for a
// port ("12.2.0#1" form), for pkg mode. The versions database prepends
// new entries, so the first element is the current one.
func Latest(port string) (string, error) {
	port = strings.ToLower(port)
	if !validPortName(port) {
		return "", fmt.Errorf("invalid vcpkg port name %q", port)
	}
	url := fmt.Sprintf("%s/microsoft/vcpkg/master/versions/%s-/%s.json", RawBase, port[:1], port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode == 404 {
		return "", fmt.Errorf("vcpkg knows no port named %q", port)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("versions database: HTTP %d", resp.StatusCode)
	}
	var doc struct {
		Versions []struct {
			Version       string `json:"version"`
			VersionSemver string `json:"version-semver"`
			VersionDate   string `json:"version-date"`
			VersionString string `json:"version-string"`
			PortVersion   int    `json:"port-version"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", err
	}
	if len(doc.Versions) == 0 {
		return "", fmt.Errorf("no versions listed for %q", port)
	}
	v := doc.Versions[0]
	ver := v.Version
	for _, alt := range []string{v.VersionSemver, v.VersionDate, v.VersionString} {
		if ver == "" {
			ver = alt
		}
	}
	if ver == "" {
		return "", fmt.Errorf("no versions listed for %q", port)
	}
	if v.PortVersion > 0 {
		ver = fmt.Sprintf("%s#%d", ver, v.PortVersion)
	}
	return ver, nil
}
