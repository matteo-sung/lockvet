// Package mvnreg asks the Maven repositories themselves — Maven Central
// and Google's Maven repository — about the artifacts a diff introduces:
//
//   - Relocations: a bump onto a relocation stub (a POM whose
//     <distributionManagement><relocation> points at new coordinates —
//     mysql:mysql-connector-java → com.mysql:mysql-connector-j) lands in
//     the deprecation lane with the new coordinates and the author's
//     message. deps.dev has no relocation concept, so these were
//     invisible before.
//   - The per-version POM probe re-verifies Unlisted flags set by the
//     deps.dev layer, which can lag the repositories by days: a version
//     Central serves is not unlisted. Central is immutable — artifacts
//     are only removed by Sonatype intervention — so a version it lacks
//     while siblings exist keeps the flag.
//   - Release ages: the POM's Last-Modified header is the upload time,
//     backfilling ages (and the ⏱ cooldown flag) for versions deps.dev
//     has not indexed yet.
//
// One anonymous GET per introduced group:artifact version — the same
// CDN-backed files every `mvn` and `gradle` build resolves against; no
// rate limits apply. Artifacts that 404 on Central are retried on
// Google's repository (androidx.* and friends live there, and deps.dev
// indexes both); the winning host is remembered per package. Neither
// host sends CORS headers, so the browser (wasm) build skips this check
// and keeps the deps.dev-only layer.
package mvnreg

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"github.com/matteo-sung/lockvet/internal/hcache"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// DecodeXML unmarshals repository XML tolerating the ASCII-family
// encoding declarations Maven repositories actually serve (the Gradle
// Plugin Portal declares US-ASCII, which encoding/xml refuses without a
// CharsetReader). ASCII is a UTF-8 subset, so passing the bytes through
// is exact.
func DecodeXML(data []byte, v any) error {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		switch strings.ToLower(charset) {
		case "us-ascii", "ascii", "utf-8", "utf8":
			return input, nil
		}
		return nil, fmt.Errorf("unsupported XML charset %q", charset)
	}
	return dec.Decode(v)
}

// CentralURL and GoogleURL are the repository bases; vars so tests can
// fake them.
var (
	CentralURL      = "https://repo1.maven.org/maven2"
	GoogleURL       = "https://dl.google.com/android/maven2"
	PluginPortalURL = "https://plugins.gradle.org/m2"
)

// maxVersionsPerChange caps POM probes for multi-version changes.
const maxVersionsPerChange = 3

var client = hcache.Client(20 * time.Second)

// Now is a var so tests can pin the clock.
var Now = time.Now

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

// relocation is the <distributionManagement><relocation> element of a
// relocation stub POM. Empty fields default to the current coordinate.
type relocation struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Message    string `xml:"message"`
}

type pomFile struct {
	DistributionManagement struct {
		Relocation *relocation `xml:"relocation"`
	} `xml:"distributionManagement"`
}

// probe is what one POM lookup learned about a version.
type probe struct {
	exists    bool
	published time.Time // zero when unknown
	reloc     *relocation
}

// Annotate fills Maven repository signals on the diffs; see the package
// comment for what it flags. Call it AFTER depsdev.Annotate (it
// re-verifies deps.dev-based Unlisted flags and backfills what deps.dev
// lacks). freshDays mirrors the -fresh-days flag for the ⏱ backfill.
// Best-effort: network errors return an error but leave diffs usable.
func Annotate(diffs []diffx.FileDiff, freshDays int) error {
	type slot struct{ fd, ci int }
	type job struct {
		group, artifact, version string
		slots                    []slot
	}
	var jobs []job
	index := map[string]int{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "Maven" || c.NonRegistry {
				continue
			}
			group, artifact, ok := splitCoord(c.Name)
			if !ok {
				continue
			}
			n := 0
			for _, v := range c.New {
				if !versionSafe(v) {
					continue
				}
				if n++; n > maxVersionsPerChange {
					break
				}
				key := c.Name + "\x00" + v
				k, ok := index[key]
				if !ok {
					k = len(jobs)
					index[key] = k
					jobs = append(jobs, job{group: group, artifact: artifact, version: v})
				}
				jobs[k].slots = append(jobs[k].slots, slot{i, j})
			}
		}
	}
	if len(jobs) == 0 {
		return nil
	}

	// Fetch POMs, 8-way concurrent, memoizing each package's home host.
	results := make([]*probe, len(jobs))
	errs := make([]error, len(jobs))
	hosts := &hostCache{m: map[string]string{}}
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i := range jobs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			jb := jobs[i]
			results[i], errs[i] = lookup(hosts, jb.group, jb.artifact, jb.version)
		}(i)
	}
	wg.Wait()

	var firstErr error
	succeeded := false
	now := Now()
	for i, pr := range results {
		if errs[i] != nil {
			if firstErr == nil {
				firstErr = errs[i]
			}
			continue
		}
		succeeded = true
		jb := jobs[i]
		if !pr.exists {
			// Absent from both public repositories: the deps.dev
			// verdict stands, now registry-verified. Nothing to change.
			continue
		}
		for _, s := range jb.slots {
			c := &diffs[s.fd].Changes[s.ci]
			// The repository serves this version: it is not unlisted,
			// whatever a lagging index believed.
			clearUnlisted(c, jb.version)
			if c.PublishedAt == "" && !pr.published.IsZero() {
				t := pr.published.UTC()
				c.PublishedAt = t.Format(time.RFC3339)
				age := int(now.Sub(t).Hours() / 24)
				if age < 0 {
					age = 0
				}
				c.AgeDays = age
				c.Fresh = freshDays > 0 && now.Sub(t) < time.Duration(freshDays)*24*time.Hour
			}
			if r := pr.reloc; r != nil {
				to := relocTarget(jb.group, jb.artifact, r)
				if to != "" && to != jb.group+":"+jb.artifact {
					c.Deprecated = true
					if c.DeprecatedReason == "" {
						reason := "relocated to " + to
						if msg := firstLine(r.Message); msg != "" {
							reason += " — " + msg
						}
						c.DeprecatedReason = reason
					}
				}
			}
		}
	}
	if !succeeded && firstErr != nil {
		return firstErr
	}
	return nil
}

// hostCache remembers which repository serves a package, so later
// versions of the same package skip the 404 half of the probe.
type hostCache struct {
	mu sync.Mutex
	m  map[string]string // "group:artifact" → base URL
}

func (h *hostCache) get(pkg string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, ok := h.m[pkg]
	return b, ok
}

func (h *hostCache) set(pkg, base string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.m[pkg] = base
}

// lookup fetches the POM for one version, trying the package's known
// host first (or a group-based guess), then the other repository.
func lookup(hosts *hostCache, group, artifact, version string) (*probe, error) {
	pkg := group + ":" + artifact
	var order []string
	if base, ok := hosts.get(pkg); ok {
		order = []string{base}
	} else if strings.HasSuffix(artifact, ".gradle.plugin") {
		// Gradle plugin markers (id:id.gradle.plugin, from version
		// catalogs) live on the Plugin Portal; some are mirrored to
		// Central too.
		order = []string{PluginPortalURL, CentralURL}
	} else if googleFirst(group) {
		order = []string{GoogleURL, CentralURL}
	} else {
		order = []string{CentralURL, GoogleURL}
	}
	var firstErr error
	for _, base := range order {
		pr, err := fetchPOM(base, group, artifact, version)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if pr != nil {
			hosts.set(pkg, base)
			return pr, nil
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return &probe{exists: false}, nil // 404 everywhere: genuinely absent
}

// fetchPOM returns the parsed probe when the repository serves the
// version, nil when it 404s, and an error for anything else.
func fetchPOM(base, group, artifact, version string) (*probe, error) {
	url := base + "/" + strings.ReplaceAll(group, ".", "/") + "/" +
		artifact + "/" + version + "/" + artifact + "-" + version + ".pom"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, nil
	default:
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	pr := &probe{exists: true}
	if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		pr.published = t
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return pr, nil // existence + age already known; POM body is a bonus
	}
	var p pomFile
	if DecodeXML(body, &p) == nil {
		pr.reloc = p.DistributionManagement.Relocation
	}
	return pr, nil
}

// relocTarget resolves a relocation's destination coordinates, applying
// Maven's defaulting rules (empty element = unchanged).
func relocTarget(group, artifact string, r *relocation) string {
	g := strings.TrimSpace(r.GroupID)
	a := strings.TrimSpace(r.ArtifactID)
	if g == "" {
		g = group
	}
	if a == "" {
		a = artifact
	}
	if !coordSafe(g) || !coordSafe(a) {
		return ""
	}
	return g + ":" + a
}

// googleFirst guesses that a group lives on Google's Maven repository,
// which only affects probe order, never correctness.
func googleFirst(group string) bool {
	for _, p := range []string{
		"androidx", "android", "com.android", "com.google.android",
		"com.google.firebase", "com.google.gms", "com.google.mlkit",
		"com.google.ar", "com.google.testing.platform",
	} {
		if group == p || strings.HasPrefix(group, p+".") {
			return true
		}
	}
	return false
}

// splitCoord splits "group:artifact" and vets both halves for safe
// verbatim use in a URL path.
func splitCoord(name string) (group, artifact string, ok bool) {
	parts := strings.Split(name, ":")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	if !coordSafe(parts[0]) || !coordSafe(parts[1]) {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func coordSafe(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return s != "" && !strings.Contains(s, "..")
}

// versionSafe vets a version for verbatim use as a URL path segment and
// rejects dynamic Gradle versions ("+", ranges) that name no artifact.
func versionSafe(v string) bool {
	if v == "" || strings.Contains(v, "..") {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-', r == '+':
		default:
			return false
		}
	}
	// A trailing "+" is a Gradle dynamic version, not an artifact name.
	return !strings.HasSuffix(v, "+")
}

func clearUnlisted(c *diffx.Change, version string) {
	if !c.Unlisted {
		return
	}
	kept := c.UnlistedVersions[:0]
	for _, v := range c.UnlistedVersions {
		if v != version {
			kept = append(kept, v)
		}
	}
	c.UnlistedVersions = kept
	if len(kept) == 0 {
		c.Unlisted = false
		c.UnlistedVersions = nil
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
