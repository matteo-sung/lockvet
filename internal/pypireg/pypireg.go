// Package pypireg asks PyPI's simple API (the JSON flavour, PEP 691)
// what it knows about the versions a diff introduces:
//
//   - PEP 740 provenance: a bump that DROPS attestations where every
//     previous release attested is what publishing with a stolen PyPI
//     token looks like — a token thief can upload, but cannot make the
//     project's trusted-publishing pipeline attest the files.
//   - PEP 592 yanks: an incoming version whose files are all yanked was
//     withdrawn by its maintainers; installs that still pin it deserve
//     a look.
//   - PEP 792 project status: archived and quarantined projects (the
//     latter is PyPI's malware-review state) surface on every change
//     that still pins them.
//   - The versions list re-verifies Unlisted flags set by the deps.dev
//     layer, which can lag PyPI by days: a version PyPI serves is not
//     unlisted; a version PyPI itself lacks keeps the flag — that is
//     exactly what an unpublished (pulled) release looks like.
//
// One GET per changed package. The endpoint answers with
// Access-Control-Allow-Origin: * and the Accept header is
// CORS-safelisted, so the wasm build can use it too.
package pypireg

import (
	"encoding/json"
	"fmt"
	"github.com/matteo-sung/lockvet/internal/hcache"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// SimpleURL is a var so tests can point it at a fake server.
var SimpleURL = "https://pypi.org/simple"

// provenanceMaxAgeDays: incoming versions older than this never get the
// provenance-dropped flag (see the age gate in Annotate).
const provenanceMaxAgeDays = 30

var client = hcache.Client(20 * time.Second)

// Annotate fills PyPI-registry signals on the diffs; see the package
// comment for what it flags. Call it AFTER depsdev.Annotate (it
// re-verifies deps.dev-based Unlisted flags and never overwrites a
// deprecation reason deps.dev already supplied). Best-effort: network
// errors return an error but leave diffs usable.
func Annotate(diffs []diffx.FileDiff) error {
	type slot struct{ fd, ci int }
	byPkg := map[string][]slot{} // every PyPI change with an incoming side
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "PyPI" || c.NonRegistry {
				continue
			}
			if len(c.New) == 0 && !c.Unlisted {
				continue // removals: nothing incoming to vet
			}
			byPkg[normalize(c.Name)] = append(byPkg[normalize(c.Name)], slot{i, j})
		}
	}
	if len(byPkg) == 0 {
		return nil
	}

	names := make([]string, 0, len(byPkg))
	for n := range byPkg {
		names = append(names, n)
	}
	meta, err := fetchMeta(names)
	if err != nil {
		return err
	}

	for name, slots := range byPkg {
		proj, ok := meta[name]
		if !ok {
			continue // package not on PyPI, or fetch failed
		}
		for _, s := range slots {
			c := &diffs[s.fd].Changes[s.ci]

			// Unlisted verification: keep only versions PyPI itself
			// lacks. (A 404 for the whole package keeps every flag —
			// the project is gone from PyPI, which is worse.)
			if c.Unlisted {
				var still []string
				for _, v := range c.UnlistedVersions {
					if _, listed := proj.versions[v]; !listed {
						still = append(still, v)
					}
				}
				c.UnlistedVersions = still
				c.Unlisted = len(still) > 0
			}

			// Project status + yanks → the deprecation surface, unless
			// deps.dev already carries an upstream reason.
			if !c.Deprecated {
				switch proj.status {
				case "quarantined":
					c.Deprecated = true
					c.DeprecatedReason = "quarantined by PyPI (under malware review; not installable)"
				case "archived":
					c.Deprecated = true
					c.DeprecatedReason = "project archived on PyPI (no further releases expected)"
				case "", "active":
				default:
					c.Deprecated = true
					c.DeprecatedReason = "project status on PyPI: " + proj.status
				}
			}
			if !c.Deprecated {
				for _, v := range c.New {
					if info, ok := proj.versions[v]; ok && info.yanked() {
						c.Deprecated = true
						reason := "version " + v + " was yanked on PyPI"
						if info.yankReason != "" {
							reason += ": " + firstLine(info.yankReason)
						}
						c.DeprecatedReason = reason
						break
					}
				}
			}

			// Provenance: transitions only, so bumps only.
			if len(c.Old) == 0 || len(c.New) == 0 {
				continue
			}
			oldSeen, oldAllAttested := false, true
			old := map[string]bool{}
			for _, v := range c.Old {
				old[v] = true
				if info, ok := proj.versions[v]; ok && info.files > 0 {
					oldSeen = true
					oldAllAttested = oldAllAttested && info.attested()
				}
			}
			if !oldSeen || !oldAllAttested {
				continue // old side unknown or not (fully) attested: no practice to drop
			}
			var unattested []string
			young := false
			for _, v := range c.New {
				if old[v] {
					continue
				}
				info, ok := proj.versions[v]
				if !ok || info.files == 0 {
					continue // not on PyPI (unlisted handles that)
				}
				// Only fully unattested incoming versions count: a
				// partial upload (some files attested) is a mixed
				// publishing setup, not a stolen-token signature.
				if info.provenanced == 0 && establishedProvenance(proj, v) {
					unattested = append(unattested, v)
					// Age gate, preferring PyPI's own upload times over
					// deps.dev (which can lag): a stolen token is caught
					// in days, and an unattested release that has
					// survived a month is a maintainer's regular (if
					// untidy) practice, not an attack in progress.
					// Unknown age means brand new, so it stays flagged.
					if t, err := time.Parse(time.RFC3339, info.uploaded); err == nil {
						young = young || time.Since(t) <= provenanceMaxAgeDays*24*time.Hour
					} else {
						young = young || c.PublishedAt == "" || c.AgeDays <= provenanceMaxAgeDays
					}
				}
			}
			if len(unattested) > 0 && young {
				c.ProvenanceDropped = true
				c.UnattestedVersions = unattested
			}
		}
	}
	return nil
}

// establishedProvenance reports whether the project's attestation
// practice was established right below the incoming version: the highest
// 3 stable (non-prerelease, non-yanked) versions strictly below it must
// ALL be fully attested, and at least 2 such versions must exist. This
// keeps one-off adopters quiet while projects that consistently attest —
// the ones where a silent drop means something — stay covered.
func establishedProvenance(proj *project, incoming string) bool {
	var below []string
	for v, info := range proj.versions {
		if info.files == 0 || info.yanked() || isPrerelease(v) {
			continue
		}
		if vers.Compare(v, incoming) < 0 {
			below = append(below, v)
		}
	}
	sort.Slice(below, func(i, j int) bool { return vers.Compare(below[i], below[j]) > 0 })
	if len(below) > 3 {
		below = below[:3]
	}
	if len(below) < 2 {
		return false
	}
	for _, v := range below {
		if !proj.versions[v].attested() {
			return false
		}
	}
	return true
}

// prereleaseRE matches PEP 440 pre-release and dev segments (1.2a1,
// 1.2.0b2, 1.2rc1, 1.2.dev3, also spellings like alpha/beta/preview/c).
// Post-releases (1.2.post1) are releases, not pre-releases.
var prereleaseRE = regexp.MustCompile(`(?i)(^|[0-9.\-_])(a|b|c|rc|alpha|beta|pre|preview)[.\-_]?[0-9]*([.+]|$)|\.?dev[0-9]*([.+]|$)`)

func isPrerelease(v string) bool {
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i] // local version segments never make something a prerelease
	}
	return prereleaseRE.MatchString(v)
}

// normalize implements PEP 503 name normalization: runs of -_. become a
// single dash and everything lowercases. Simple-API URLs require it.
var sepRE = regexp.MustCompile(`[-_.]+`)

func normalize(name string) string {
	return strings.ToLower(sepRE.ReplaceAllString(name, "-"))
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// verInfo is what lockvet keeps per PyPI version.
type verInfo struct {
	files       int    // distribution files seen for this version
	provenanced int    // …of which carry a PEP 740 provenance link
	yankedFiles int    // …of which are yanked
	yankReason  string // first yank reason seen, if any
	uploaded    string // earliest upload-time (RFC3339) seen
}

func (v verInfo) attested() bool { return v.files > 0 && v.provenanced == v.files }
func (v verInfo) yanked() bool   { return v.files > 0 && v.yankedFiles == v.files }

type project struct {
	versions map[string]*verInfo
	status   string // PEP 792: active / archived / quarantined / …
}

// fetchMeta downloads each project's simple-API JSON document a few at a
// time. 404s (and undecodable answers) simply yield no entry; other HTTP
// failures abort with an error so callers can warn once.
func fetchMeta(names []string) (map[string]*project, error) {
	out := make(map[string]*project, len(names))
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			mu.Lock()
			stop := firstErr != nil
			mu.Unlock()
			if stop {
				return
			}
			req, err := http.NewRequest("GET", SimpleURL+"/"+name+"/", nil)
			if err != nil {
				return
			}
			req.Header.Set("Accept", "application/vnd.pypi.simple.v1+json")
			resp, err := client.Do(req)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("PyPI unreachable: %w", err)
				}
				mu.Unlock()
				return
			}
			defer resp.Body.Close()
			switch resp.StatusCode {
			case 200:
				if p := decodeProject(resp.Body); p != nil {
					mu.Lock()
					out[name] = p
					mu.Unlock()
				}
			case 404:
				// not on PyPI: leave no entry
			default:
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("PyPI returned HTTP %d", resp.StatusCode)
				}
				mu.Unlock()
			}
		}(name)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func decodeProject(r io.Reader) *project {
	var doc struct {
		Files []struct {
			Filename   string          `json:"filename"`
			Provenance json.RawMessage `json:"provenance"`
			Yanked     json.RawMessage `json:"yanked"`
			UploadTime string          `json:"upload-time"`
		} `json:"files"`
		Versions      []string `json:"versions"`
		ProjectStatus struct {
			Status string `json:"status"`
		} `json:"project-status"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil
	}
	p := &project{versions: make(map[string]*verInfo, len(doc.Versions)), status: doc.ProjectStatus.Status}
	verSet := make(map[string]bool, len(doc.Versions))
	for _, v := range doc.Versions {
		p.versions[v] = &verInfo{}
		verSet[v] = true
	}
	for _, f := range doc.Files {
		v := versionOf(f.Filename, verSet)
		if v == "" {
			continue
		}
		info := p.versions[v]
		info.files++
		if s := string(f.Provenance); len(s) > 0 && s != "null" && s != `""` {
			info.provenanced++
		}
		if s := string(f.Yanked); len(s) > 0 && s != "null" && s != "false" {
			info.yankedFiles++
			if info.yankReason == "" {
				var reason string
				if json.Unmarshal(f.Yanked, &reason) == nil {
					info.yankReason = reason
				}
			}
		}
		if info.uploaded == "" || f.UploadTime < info.uploaded {
			info.uploaded = f.UploadTime
		}
	}
	return p
}

// versionOf extracts the version a distribution filename embeds, using
// the project's version list as ground truth. Modern filenames are
// normalized ({name}-{version}-…), so the second dash-field usually
// answers directly; older sdists with dashes in the project name fall
// back to a scan for any listed version bounded by dashes.
func versionOf(filename string, versions map[string]bool) string {
	base := filename
	for _, ext := range []string{".whl", ".tar.gz", ".zip", ".tar.bz2", ".egg", ".exe"} {
		if strings.HasSuffix(base, ext) {
			base = base[:len(base)-len(ext)]
			break
		}
	}
	if parts := strings.SplitN(base, "-", 3); len(parts) >= 2 && versions[parts[1]] {
		return parts[1]
	}
	for v := range versions {
		if strings.HasSuffix(base, "-"+v) || strings.Contains(base, "-"+v+"-") {
			return v
		}
	}
	return ""
}
