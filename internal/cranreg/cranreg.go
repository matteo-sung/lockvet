// Package cranreg asks CRAN what it knows about the R packages a diff
// touches (renv.lock resolves CRAN-sourced packages). deps.dev has no
// CRAN system at all, so — like Packagist, hex.pm and pub.dev before it
// — this package IS the metadata layer for R, not a fallback:
//
//   - Release ages and the ⏱ cooldown flag, from METACRAN's per-version
//     timeline (crandb, the CouchDB API behind r-pkg.org, mirrors the
//     canonical CRAN metadata including publication dates for every
//     version ever released — CRAN archives old releases, it does not
//     delete them).
//   - Archived packages (CRAN's package-level removal from the index;
//     `install.packages` stops resolving them) land in the deprecation
//     lane.
//   - Per-version License fields from the DESCRIPTION of each release
//     power license-change detection, exactly like the other registry
//     layers (both sides must be known; case-only differences ignored).
//   - Unlisted detection, double-checked against CRAN itself: a version
//     missing from the crandb timeline could just be mirror lag, so
//     before claiming anything lockvet HEADs the version's source
//     tarball on cran.r-project.org — both the current src/contrib
//     location and the Archive one. Only a version CRAN has in neither
//     place keeps the flag; packages crandb does not know at all are
//     never flagged. The renv.lock parser marks GitHub/GitLab/local/
//     remote installs NonRegistry besides, so dev versions never reach
//     this check.
//   - The upstream source repository from the DESCRIPTION URL (or
//     BugReports) field, which the changelog layers turn into verified
//     compare links and release notes.
//
// Bioconductor packages are left to the OSV layer alone: crandb covers
// CRAN only, and lockvet makes no claims it cannot back.
//
// Neither crandb nor cran.r-project.org sends CORS headers, so the
// browser (wasm) playground skips this layer; the native CLI is
// unaffected.
package cranreg

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/hcache"
)

// BaseURL is the crandb (METACRAN) API base; a var so tests can fake it.
var BaseURL = "https://crandb.r-pkg.org"

// MirrorURL is the canonical CRAN mirror used ONLY to double-check
// absence before an unlisted claim; a var so tests can fake it.
var MirrorURL = "https://cran.r-project.org"

// Enabled gates the whole layer; the wasm playground sets it false
// (no CORS on either endpoint).
var Enabled = true

// Now is a var so tests can pin the clock.
var Now = time.Now

var client = hcache.Client(20 * time.Second)

// headClient is deliberately uncached: absence evidence is re-proven on
// every run, like every other unlisted path. HTTP/1.1 only: CRAN's
// server answers HEAD with a DATA frame over h2, which Go rejects
// noisily.
var headClient = &http.Client{
	Timeout:   20 * time.Second,
	Transport: http1Transport(),
}

func http1Transport() *http.Transport {
	t := &http.Transport{}
	t.Protocols = new(http.Protocols)
	t.Protocols.SetHTTP1(true)
	return t
}

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const maxConcurrent = 8

// pkg is what lockvet keeps per CRAN package.
type pkg struct {
	timeline map[string]string // version → RFC3339 publication time
	licenses map[string]string // version → DESCRIPTION License
	latest   string
	archived bool
	source   string // upstream repository URL, may be ""
}

// Annotate fills CRAN metadata on the diffs; see the package comment for
// what it covers. The returned bool reports whether at least one package
// was actually vetted against CRAN (deps.dev never covers CRAN, so this
// decides whether release metadata was checked at all for R). freshDays
// mirrors -fresh-days. Best-effort: per-package failures skip that
// package; only total failure returns an error.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	if !Enabled {
		return false, nil
	}
	type slot struct{ fd, ci int }
	byPkg := map[string][]slot{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "CRAN" || c.NonRegistry {
				continue
			}
			byPkg[c.Name] = append(byPkg[c.Name], slot{i, j})
		}
	}
	if len(byPkg) == 0 {
		return false, nil
	}

	names := make([]string, 0, len(byPkg))
	for n := range byPkg {
		names = append(names, n)
	}
	sort.Strings(names)
	pkgs, err := fetchAll(names)
	if err != nil {
		return false, err
	}

	checked := false
	for name, slots := range byPkg {
		p := pkgs[name]
		if p == nil {
			continue // not on CRAN at all, or fetch failed: flag nothing
		}
		checked = true
		for _, s := range slots {
			annotateChange(&diffs[s.fd].Changes[s.ci], name, p, freshDays)
		}
	}
	return checked, nil
}

func annotateChange(c *diffx.Change, name string, p *pkg, freshDays int) {
	// Release age: keep the most recently published incoming version,
	// exactly like the deps.dev layer does elsewhere.
	latest := c.PublishedAt
	for _, v := range c.New {
		if ts, ok := p.timeline[v]; ok && ts != "" {
			if t, err := time.Parse(time.RFC3339, ts); err == nil {
				if s := t.UTC().Format(time.RFC3339); s > latest {
					latest = s
				}
			}
		}
	}
	if latest != "" && latest != c.PublishedAt {
		if t, err := time.Parse(time.RFC3339, latest); err == nil {
			c.PublishedAt = latest
			if age := int(Now().Sub(t).Hours() / 24); age >= 0 {
				c.AgeDays = age
				c.Fresh = freshDays > 0 && Now().Sub(t) < time.Duration(freshDays)*24*time.Hour
			}
		}
	}

	// Deprecation lane: an archived package taints every incoming
	// version (removals are good news and stay quiet).
	if p.archived && len(c.New) > 0 {
		c.Deprecated = true
		if c.DeprecatedReason == "" {
			c.DeprecatedReason = "archived on CRAN (no longer installable from the index)"
		}
	}

	// License change: only claimed when CRAN reports a license for BOTH
	// sides and they differ (case-only differences ignored).
	oldLic := newestLicense(p, c.Old)
	newLic := newestLicense(p, c.New)
	if oldLic != "" && newLic != "" && len(c.Old) > 0 && len(c.New) > 0 && c.OldLicense == "" {
		c.OldLicense, c.NewLicense = oldLic, newLic
		c.LicenseChanged = !strings.EqualFold(oldLic, newLic)
	}

	// Unlisted: incoming versions crandb lacks, while the package IS
	// known — but crandb is a mirror, so absence is double-checked
	// against CRAN itself before any claim (mirror lag must not flag a
	// same-day release).
	if len(p.timeline) > 0 {
		var missing []string
		for _, v := range c.New {
			if _, ok := p.timeline[v]; ok {
				continue
			}
			if onCRAN(name, v) {
				continue // crandb lag: CRAN itself serves the tarball
			}
			missing = append(missing, v)
		}
		if len(missing) > 0 {
			c.Unlisted = true
			c.UnlistedVersions = missing
		}
	}

	// Upstream repository, for the changelog layers.
	if c.SourceRepo == "" && p.source != "" {
		c.SourceRepo = p.source
	}
}

// newestLicense returns the license of the highest-published version in
// vs that crandb knows, preferring the most recently published one.
func newestLicense(p *pkg, vs []string) string {
	best, bestTS := "", ""
	for _, v := range vs {
		lic := p.licenses[v]
		if lic == "" {
			continue
		}
		ts := p.timeline[v]
		if best == "" || ts > bestTS {
			best, bestTS = lic, ts
		}
	}
	return best
}

// onCRAN reports whether CRAN itself serves the version's source
// tarball, either as the current release or from the Archive.
func onCRAN(name, version string) bool {
	tarball := url.PathEscape(name) + "_" + url.PathEscape(version) + ".tar.gz"
	for _, p := range []string{
		"/src/contrib/" + tarball,
		"/src/contrib/Archive/" + url.PathEscape(name) + "/" + tarball,
	} {
		req, err := http.NewRequest(http.MethodHead, MirrorURL+p, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", userAgent)
		resp, err := headClient.Do(req)
		if err != nil {
			return true // can't prove absence: make no claim
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return true
		}
	}
	return false
}

// Latest returns the current CRAN release of name, for
// `lockvet pkg cran:<name>`.
func Latest(name string) (string, error) {
	p, err := fetchPkg(name)
	if err != nil {
		return "", err
	}
	if p == nil {
		return "", fmt.Errorf("CRAN: package %s not found", name)
	}
	return p.latest, nil
}

func fetchAll(names []string) (map[string]*pkg, error) {
	out := make(map[string]*pkg, len(names))
	var mu sync.Mutex
	var firstErr error
	failures := 0
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			p, err := fetchPkg(name)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			if p != nil {
				out[name] = p
			}
		}(name)
	}
	wg.Wait()
	if failures == len(names) && firstErr != nil {
		return nil, firstErr // total failure: report it
	}
	return out, nil
}

// fetchPkg returns nil, nil when CRAN does not know the package.
func fetchPkg(name string) (*pkg, error) {
	req, err := http.NewRequest(http.MethodGet, BaseURL+"/"+url.PathEscape(name)+"/all", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crandb unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("crandb rate limit hit; retry in a minute")
	default:
		return nil, fmt.Errorf("crandb answered %d for %s", resp.StatusCode, name)
	}
	var doc struct {
		Versions map[string]struct {
			License    string `json:"License"`
			URL        string `json:"URL"`
			BugReports string `json:"BugReports"`
		} `json:"versions"`
		Timeline map[string]string `json:"timeline"`
		Latest   string            `json:"latest"`
		Archived bool              `json:"archived"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("crandb metadata for %s: %w", name, err)
	}
	if len(doc.Timeline) == 0 && len(doc.Versions) == 0 {
		return nil, nil
	}
	p := &pkg{
		timeline: make(map[string]string, len(doc.Timeline)),
		licenses: make(map[string]string, len(doc.Versions)),
		latest:   doc.Latest,
		archived: doc.Archived,
	}
	for v, ts := range doc.Timeline {
		p.timeline[v] = ts
	}
	for v, d := range doc.Versions {
		if d.License != "" {
			p.licenses[v] = d.License
		}
	}
	if d, ok := doc.Versions[doc.Latest]; ok {
		p.source = repoURL(d.URL, d.BugReports)
	}
	return p, nil
}

// repoURL reduces a DESCRIPTION URL field (comma/whitespace-separated
// list; BugReports as fallback, with its /issues suffix dropped) to the
// bare repository the changelog layers can work with.
func repoURL(candidates ...string) string {
	for _, field := range candidates {
		for _, u := range strings.FieldsFunc(field, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\n' || r == '\t'
		}) {
			u = strings.TrimSuffix(strings.TrimSpace(u), "/")
			if !strings.HasPrefix(u, "https://") {
				continue
			}
			for _, host := range []string{"https://github.com/", "https://gitlab.com/", "https://codeberg.org/", "https://bitbucket.org/"} {
				rest, ok := strings.CutPrefix(u, host)
				if !ok {
					continue
				}
				parts := strings.Split(rest, "/")
				if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
					continue
				}
				return host + parts[0] + "/" + strings.TrimSuffix(parts[1], ".git")
			}
		}
	}
	return ""
}
