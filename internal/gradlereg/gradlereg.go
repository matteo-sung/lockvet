// Package gradlereg asks services.gradle.org what it knows about the
// Gradle distribution a gradle-wrapper.properties diff pins. There is no
// OSV ecosystem and no deps.dev system for the Gradle distribution
// itself, so this package IS the metadata layer for wrapper pins:
//
//   - Release ages, from the version's own buildTime in
//     /versions/all (the official version index Gradle's tooling uses).
//   - Broken releases: the index marks releases the Gradle project has
//     withdrawn as broken → the deprecation lane.
//   - Unlisted detection: a version absent from the index while the
//     index itself is healthy is real evidence — released Gradle
//     versions are never removed (1.0-milestone-4 is still listed).
//     Absence is re-proven with an uncached fetch AND a live probe of
//     the distribution zip itself before any claim; snapshot/nightly
//     builds (timestamped versions) are exempt, since old snapshots are
//     routinely pruned.
//   - Checksum cross-check: when the wrapper pins distributionSha256Sum,
//     it is compared against the checksum Gradle actually publishes for
//     that version (both -bin and -all distributions). A pin matching
//     neither is the wrapper-tampering shape — the wrapper will happily
//     verify a poisoned distribution against a poisoned checksum — and
//     lands in the same ‼ lane as moved release tags. Mismatch evidence
//     is re-proven with uncached fetches before any claim; a match
//     renders as a positive ✔.
//
// services.gradle.org sends Access-Control-Allow-Origin: *, so this
// layer also works in the browser (wasm) playground.
package gradlereg

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/hcache"
)

// BaseURL is the Gradle version-index host; a var so tests can fake it.
var BaseURL = "https://services.gradle.org"

// Enabled gates the whole layer.
var Enabled = true

// Now is the clock; a var so tests can pin it.
var Now = time.Now

var client = hcache.Client(20 * time.Second)

// liveClient is deliberately uncached: absence and mismatch evidence is
// re-proven on every run, like every other unlisted path.
var liveClient = &http.Client{Timeout: 20 * time.Second}

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

// sourceRepo powers compare links and release notes for wrapper bumps.
const sourceRepo = "https://github.com/gradle/gradle"

// entry is one element of /versions/all.
type entry struct {
	Version     string `json:"version"`
	BuildTime   string `json:"buildTime"` // 20240923212839+0000
	Snapshot    bool   `json:"snapshot"`
	Nightly     bool   `json:"nightly"`
	Broken      bool   `json:"broken"`
	Current     bool   `json:"current"`
	DownloadURL string `json:"downloadUrl"`
	ChecksumURL string `json:"checksumUrl"`
	Checksum    string `json:"checksum"` // sha256 of the -bin distribution
}

// Annotate fills Gradle version-index metadata on the diffs; see the
// package comment for what it covers. The returned bool reports whether
// the index was actually consulted for at least one pin.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	if !Enabled {
		return false, nil
	}
	var slots []*diffx.Change
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "Gradle" || c.NonRegistry {
				continue
			}
			slots = append(slots, c)
		}
	}
	if len(slots) == 0 {
		return false, nil
	}
	index, err := fetchIndex(client, false)
	if err != nil {
		return false, err
	}
	for _, c := range slots {
		annotateChange(c, index, freshDays)
	}
	return true, nil
}

func annotateChange(c *diffx.Change, index map[string]entry, freshDays int) {
	// Release age: the most recently built incoming version.
	latest := ""
	for _, v := range c.New {
		if e, ok := index[v]; ok && e.BuildTime > latest {
			latest = e.BuildTime
		}
	}
	if t, err := time.Parse("20060102150405-0700", latest); err == nil {
		c.PublishedAt = t.UTC().Format(time.RFC3339)
		if age := int(Now().Sub(t).Hours() / 24); age >= 0 {
			c.AgeDays = age
			c.Fresh = freshDays > 0 && Now().Sub(t) < time.Duration(freshDays)*24*time.Hour
		}
	}

	// Broken releases → the deprecation lane.
	if !c.Deprecated {
		for _, v := range c.New {
			if e, ok := index[v]; ok && e.Broken {
				c.Deprecated = true
				c.DeprecatedReason = fmt.Sprintf("Gradle %s is marked broken in the official version index — the Gradle project has withdrawn it", v)
				break
			}
		}
	}

	// Unlisted: incoming versions the index lacks. Released versions are
	// never removed, so absence is real evidence — re-proven uncached,
	// then against the distribution zip itself. Snapshots/nightlies
	// (timestamped versions) are pruned routinely and stay exempt.
	var missing []string
	for _, v := range c.New {
		if _, ok := index[v]; ok {
			continue
		}
		if snapshotShaped(v) {
			continue
		}
		if live := liveIndex(); live != nil {
			if _, ok := live[v]; ok {
				continue
			}
		} else {
			continue // can't re-prove absence: make no claim
		}
		if distributionExists(v) {
			continue
		}
		missing = append(missing, v)
	}
	if len(missing) > 0 {
		c.Unlisted = true
		c.UnlistedVersions = append(c.UnlistedVersions, missing...)
	}

	// Checksum cross-check: a pinned distributionSha256Sum must be one
	// of the checksums Gradle publishes for the version (-bin or -all).
	for _, v := range c.New {
		e, ok := index[v]
		if !ok {
			continue
		}
		pin, ok := strings.CutPrefix(c.NewPins[v], "sha256:")
		if !ok || pin == "" {
			continue
		}
		pin = strings.ToLower(pin)
		officials := officialChecksums(e)
		if len(officials) == 0 {
			continue // can't establish the truth: make no claim
		}
		if officials[pin] {
			c.DigestVerified = true
			continue
		}
		// Re-prove the mismatch with uncached fetches before claiming.
		if live := liveChecksums(e); live == nil || live[pin] {
			if live != nil {
				c.DigestVerified = true
			}
			continue
		}
		c.TagMismatch = true
		c.TagMismatches = append(c.TagMismatches, fmt.Sprintf("%s@%s (distributionSha256Sum %s…)", c.Name, v, pin[:12]))
	}

	if c.SourceRepo == "" {
		c.SourceRepo = sourceRepo
	}
}

// snapshotShaped reports whether a version string looks like a
// snapshot/nightly build (8.12-20241105123456+0000).
func snapshotShaped(v string) bool {
	return strings.Contains(v, "+")
}

func fetchIndex(cl *http.Client, live bool) (map[string]entry, error) {
	req, err := http.NewRequest("GET", BaseURL+"/versions/all", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gradle version index: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	var entries []entry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("gradle version index: %v", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("gradle version index: empty")
	}
	m := make(map[string]entry, len(entries))
	for _, e := range entries {
		if e.Version != "" {
			m[e.Version] = e
		}
	}
	_ = live
	return m, nil
}

var (
	liveMu    sync.Mutex
	liveMemo  map[string]entry
	liveTried bool
)

// liveIndex re-fetches the version index bypassing the cache; nil means
// the truth could not be established. Memoized per run.
func liveIndex() map[string]entry {
	liveMu.Lock()
	defer liveMu.Unlock()
	if liveTried {
		return liveMemo
	}
	liveTried = true
	m, err := fetchIndex(liveClient, true)
	if err == nil {
		liveMemo = m
	}
	return liveMemo
}

// distributionExists probes the distribution zip itself (a same-minute
// release may not be in a CDN-cached index yet; the zip is the truth).
func distributionExists(version string) bool {
	req, err := http.NewRequest("HEAD", BaseURL+"/distributions/gradle-"+version+"-bin.zip", nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := liveClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	return resp.StatusCode == http.StatusOK
}

// officialChecksums returns the set of sha256 checksums Gradle publishes
// for a version's distributions (-bin inline in the index, -all fetched
// from its published .sha256 file), lower-cased. Empty when nothing
// could be established.
func officialChecksums(e entry) map[string]bool {
	set := map[string]bool{}
	if c := strings.ToLower(strings.TrimSpace(e.Checksum)); len(c) == 64 {
		set[c] = true
	}
	if all := allChecksumURL(e); all != "" {
		if c := fetchChecksum(client, all); c != "" {
			set[c] = true
		}
	}
	return set
}

// liveChecksums is officialChecksums with every fetch uncached; nil
// means the truth could not be established.
func liveChecksums(e entry) map[string]bool {
	set := map[string]bool{}
	binURL := e.ChecksumURL
	if binURL == "" && e.DownloadURL != "" {
		binURL = e.DownloadURL + ".sha256"
	}
	if binURL != "" {
		if c := fetchChecksum(liveClient, binURL); c != "" {
			set[c] = true
		}
	}
	if all := allChecksumURL(e); all != "" {
		if c := fetchChecksum(liveClient, all); c != "" {
			set[c] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// allChecksumURL derives the -all distribution's checksum URL from the
// -bin one the index records (handles the snapshot directory too).
func allChecksumURL(e entry) string {
	u := e.ChecksumURL
	if u == "" && e.DownloadURL != "" {
		u = e.DownloadURL + ".sha256"
	}
	if i := strings.LastIndex(u, "-bin.zip"); i >= 0 {
		return u[:i] + "-all.zip" + u[i+len("-bin.zip"):]
	}
	return ""
}

func fetchChecksum(cl *http.Client, url string) string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<10))
	if err != nil {
		return ""
	}
	c := strings.ToLower(strings.TrimSpace(string(body)))
	if len(c) != 64 {
		return ""
	}
	for _, r := range c {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	return c
}

// Latest resolves the current stable Gradle version for pkg mode.
func Latest(name string) (string, error) {
	if name != "gradle" {
		return "", fmt.Errorf("unknown Gradle distribution %q (only \"gradle\")", name)
	}
	index, err := fetchIndex(client, false)
	if err != nil {
		return "", err
	}
	var versions []string
	for v, e := range index {
		if e.Current {
			return v, nil
		}
		if !e.Snapshot && !e.Nightly && !e.Broken {
			versions = append(versions, v)
		}
	}
	sort.Strings(versions)
	if len(versions) == 0 {
		return "", fmt.Errorf("gradle version index lists no releases")
	}
	return versions[len(versions)-1], nil
}

// ResetForTesting clears run-scoped memoization.
func ResetForTesting() {
	liveMu.Lock()
	defer liveMu.Unlock()
	liveMemo, liveTried = nil, false
}
