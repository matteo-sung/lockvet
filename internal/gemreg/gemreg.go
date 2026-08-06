// Package gemreg asks RubyGems.org what it knows about the versions a
// diff introduces:
//
//   - Sigstore provenance: RubyGems records attestations per release. A
//     bump that silently DROPS them where every previous release
//     attested is what publishing with a stolen gem-push token looks
//     like — a token thief can publish, but cannot make the project's
//     trusted-publishing pipeline attest. Same three gates as
//     npm/PyPI/crates.io: outgoing pin attested, practice established
//     right below the incoming version, and the release is young
//     (≤30 days) or too new to be indexed.
//   - The compact index re-verifies Unlisted flags set by the deps.dev
//     layer, which can lag RubyGems by days: a version the index serves
//     is not unlisted; a version RubyGems itself lacks keeps the flag.
//     Yanked gems vanish from the index entirely (RubyGems removes the
//     .gem file), so a bump onto a yanked or admin-deleted (malicious)
//     release is exactly what this flag catches.
//   - The index also carries authoritative created_at times, so release
//     ages and the ⏱ cooldown flag work even for versions deps.dev has
//     not indexed yet — brand-new releases are precisely the risky ones.
//
// One anonymous GET per changed gem against the compact index (the same
// Fastly-cached endpoint Bundler itself hammers), plus per-version
// attestation lookups only for the rare young provenance candidates.
// Neither endpoint sends CORS headers, so the browser (wasm) build skips
// this package and keeps its deps.dev-only behaviour for RubyGems.
package gemreg

import (
	"bufio"
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

// IndexURL is the compact-index base; a var so tests can fake it.
var IndexURL = "https://index.rubygems.org"

// APIURL is the RubyGems.org API base; a var so tests can fake it.
var APIURL = "https://rubygems.org/api/v1"

// provenanceMaxAgeDays: incoming versions older than this never get the
// provenance-dropped flag (see the age gate in Annotate).
const provenanceMaxAgeDays = 30

// maxAttestations caps per-gem attestation lookups (outgoing pins +
// practice window + incoming versions).
const maxAttestations = 8

var client = hcache.Client(20 * time.Second)

// Now is a var so tests can pin the clock.
var Now = time.Now

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

// gem is what lockvet keeps per RubyGems package: the compact index's
// listed versions (platform variants are distinct entries, exactly as
// Gemfile.lock pins them) with their creation times.
type gem struct {
	created map[string]string // version[-platform] → RFC3339 created_at
	order   []string          // index order (oldest first)
}

// Annotate fills RubyGems registry signals on the diffs; see the package
// comment for what it flags. Call it AFTER depsdev.Annotate (it
// re-verifies deps.dev-based Unlisted flags and backfills ages deps.dev
// lacks). freshDays mirrors the -fresh-days flag for the ⏱ backfill.
// Best-effort: network errors return an error but leave diffs usable.
func Annotate(diffs []diffx.FileDiff, freshDays int) error {
	type slot struct{ fd, ci int }
	byGem := map[string][]slot{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "RubyGems" || c.NonRegistry {
				continue
			}
			if len(c.New) == 0 && !c.Unlisted {
				continue // removals: nothing incoming to vet
			}
			byGem[c.Name] = append(byGem[c.Name], slot{i, j})
		}
	}
	if len(byGem) == 0 {
		return nil
	}

	names := make([]string, 0, len(byGem))
	for n := range byGem {
		names = append(names, n)
	}
	gems, err := fetchIndex(names)
	if err != nil {
		return err
	}

	for name, slots := range byGem {
		g, ok := gems[name]
		if !ok {
			continue // gem not on RubyGems at all, or fetch failed
		}
		for _, s := range slots {
			c := &diffs[s.fd].Changes[s.ci]

			// Unlisted verification: keep only versions the index
			// itself lacks. (A 404 for the whole gem keeps every flag —
			// the project is gone from RubyGems, which is worse.)
			if c.Unlisted {
				var still []string
				for _, v := range c.UnlistedVersions {
					if _, listed := g.created[v]; !listed {
						still = append(still, v)
					}
				}
				c.UnlistedVersions = still
				c.Unlisted = len(still) > 0
			}

			if len(c.New) == 0 {
				continue
			}

			// Age backfill: deps.dev can lag RubyGems by days, and a
			// release it has not indexed yet is exactly the kind the ⏱
			// cooldown flag exists for. The index's created_at is
			// authoritative; keep the newest incoming time.
			latest := c.PublishedAt
			for _, v := range c.New {
				if t, ok := g.created[v]; ok && t > latest {
					latest = t
				}
			}
			if latest != c.PublishedAt && latest != "" {
				if t, err := time.Parse(time.RFC3339, latest); err == nil {
					c.PublishedAt = t.UTC().Format(time.RFC3339)
					if age := int(Now().Sub(t).Hours() / 24); age >= 0 {
						c.AgeDays = age
						c.Fresh = freshDays > 0 && Now().Sub(t) < time.Duration(freshDays)*24*time.Hour
					}
				}
			}

			// Provenance: transitions only, so bumps only.
			if len(c.Old) == 0 {
				continue
			}
			annotateProvenance(c, name, g)
		}
	}
	return nil
}

// annotateProvenance applies the three gates and flags the change when a
// young incoming version drops an established attestation practice.
// Attestation lookups cost one GET each, so the gates run cheapest
// first: the age gate needs no extra requests at all.
func annotateProvenance(c *diffx.Change, name string, g *gem) {
	old := map[string]bool{}
	for _, v := range c.Old {
		old[v] = true
	}

	// Age gate first (free): at least one genuinely-incoming version
	// must be young or unknown to the index (unknown = brand new or
	// pulled; unlisted handles the latter).
	young := false
	var incoming []string
	for _, v := range c.New {
		if old[v] {
			continue
		}
		incoming = append(incoming, v)
		if t, ok := g.created[v]; ok {
			if ts, err := time.Parse(time.RFC3339, t); err == nil {
				young = young || Now().Sub(ts) <= provenanceMaxAgeDays*24*time.Hour
				continue
			}
		}
		young = true // not in the index / unparsable: treat as new
	}
	if !young || len(incoming) == 0 {
		return
	}

	f := &fetcher{budget: maxAttestations, memo: map[string]answer{}}

	// Outgoing pins must all be attested — otherwise there is no
	// practice to drop. Today this is the common early exit.
	for _, v := range c.Old {
		if _, listed := g.created[v]; !listed {
			return // outgoing not on the registry: unknowable
		}
		att, ok := f.attested(name, v)
		if !ok || !att {
			return
		}
	}

	// Practice established right below the incoming version: the
	// highest 3 stable ruby-platform releases strictly below it must
	// ALL be attested, and at least 2 such releases must exist.
	// (Outgoing pins in the window were just verified; the memo makes
	// re-asking free.)
	pivot := incoming[0]
	for _, v := range incoming[1:] {
		if vers.Compare(v, pivot) > 0 {
			pivot = v
		}
	}
	var below []string
	for _, v := range g.order {
		if isPrereleaseOrPlatform(v) {
			continue
		}
		if vers.Compare(v, pivot) < 0 {
			below = append(below, v)
		}
	}
	sort.Slice(below, func(i, j int) bool { return vers.Compare(below[i], below[j]) > 0 })
	if len(below) > 3 {
		below = below[:3]
	}
	if len(below) < 2 {
		return
	}
	for _, v := range below {
		att, ok := f.attested(name, v)
		if !ok || !att {
			return
		}
	}

	// Finally the incoming versions themselves: any listed, unattested
	// one trips the flag.
	var unattested []string
	for _, v := range incoming {
		if _, listed := g.created[v]; !listed {
			continue // unlisted handles that
		}
		att, ok := f.attested(name, v)
		if ok && !att {
			unattested = append(unattested, v)
		}
	}
	if len(unattested) > 0 {
		c.ProvenanceDropped = true
		c.UnattestedVersions = unattested
	}
}

// fetcher memoises attestation lookups under a per-gem request budget.
type answer struct{ att, ok bool }

type fetcher struct {
	budget int
	memo   map[string]answer
}

// attested asks the attestation endpoint about one release. full_name is
// {gem}-{version}[-{platform}] — exactly how Gemfile.lock pins platform
// gems, so the pinned string works as-is. ok=false means the answer is
// unknown (budget exhausted, network trouble, or 404) and callers must
// stay quiet.
func (f *fetcher) attested(name, version string) (att, ok bool) {
	if a, seen := f.memo[version]; seen {
		return a.att, a.ok
	}
	att, ok = fetchAttested(name, version, &f.budget)
	f.memo[version] = answer{att, ok}
	return att, ok
}

func fetchAttested(name, version string, budget *int) (att, ok bool) {
	if *budget <= 0 {
		return false, false
	}
	*budget--
	req, err := http.NewRequest("GET", APIURL+"/attestations/"+name+"-"+version+".json", nil)
	if err != nil {
		return false, false
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return false, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false, false
	}
	buf := make([]byte, 16)
	n, _ := io.ReadFull(resp.Body, buf)
	body := strings.TrimSpace(string(buf[:n]))
	return body != "" && body != "[]", true
}

// isPrereleaseOrPlatform reports whether a compact-index version entry
// is a prerelease (Ruby: any letter in the version, e.g. 1.0.0.rc1) or a
// platform variant (1.19.4-x86_64-linux). Only plain stable releases
// anchor the practice window.
var stableRE = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

func isPrereleaseOrPlatform(v string) bool { return !stableRE.MatchString(v) }

// fetchIndex downloads each gem's compact-index /info document a few at
// a time. 404s yield no entry; other HTTP failures abort with an error
// so callers can warn once.
func fetchIndex(names []string) (map[string]*gem, error) {
	out := make(map[string]*gem, len(names))
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
			req, err := http.NewRequest("GET", IndexURL+"/info/"+name, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", userAgent)
			resp, err := client.Do(req)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("RubyGems index unreachable: %w", err)
				}
				mu.Unlock()
				return
			}
			defer resp.Body.Close()
			switch resp.StatusCode {
			case 200:
				if g := decodeInfo(resp); g != nil {
					mu.Lock()
					out[name] = g
					mu.Unlock()
				}
			case 404:
				// not on RubyGems: leave no entry
			default:
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("RubyGems index returned HTTP %d", resp.StatusCode)
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

// decodeInfo parses a compact-index /info document: after a "---" header,
// one line per release — "VERSION[-PLATFORM] [dep,dep…]|attr,attr…" with
// created_at among the attributes.
func decodeInfo(resp *http.Response) *gem {
	g := &gem{created: map[string]string{}}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line == "---" {
			continue
		}
		version, rest, _ := strings.Cut(line, " ")
		if version == "" || version[0] < '0' || version[0] > '9' {
			continue
		}
		created := ""
		if _, attrs, ok := strings.Cut(rest, "|"); ok {
			for _, kv := range strings.Split(attrs, ",") {
				if v, found := strings.CutPrefix(kv, "created_at:"); found {
					created = v
					break
				}
			}
		}
		if _, dup := g.created[version]; !dup {
			g.order = append(g.order, version)
		}
		g.created[version] = created
	}
	if len(g.created) == 0 {
		return nil
	}
	return g
}
