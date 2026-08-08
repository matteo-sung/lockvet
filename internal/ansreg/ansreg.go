// Package ansreg asks Ansible Galaxy what it knows about the
// collections and roles a requirements.yml diff touches. There is no
// OSV.dev ecosystem and no deps.dev system for Ansible content, so —
// like Packagist, hex.pm, pub.dev, CRAN, the Bazel Central Registry
// and Helm chart repositories before it — this package IS the metadata
// layer, not a fallback:
//
//   - Release ages and the ⏱ cooldown flag, from each collection
//     version's created_at in the galaxy.ansible.com v3 index (the
//     exact API `ansible-galaxy collection install` resolves against)
//     and each role version's release_date in the classic v1 role
//     index. Note: versions published before the 2023 galaxy_ng
//     migration carry the migration date, so historical ages are
//     upper-bounded — fine for the cooldown window, never understated.
//   - Deprecated collections land in the deprecation lane: Galaxy's
//     own `deprecated` flag on the collection index.
//   - Registry-verified unlisted detection for collections: Galaxy
//     keeps every published version (removal is an admin/malware
//     action), so an incoming version the index answers 404 for —
//     while the collection itself IS listed — is what a pulled or
//     never-published release looks like. Absence is re-proven with an
//     uncached fetch before it is claimed. Roles are exempt: their
//     version list only updates when the owner re-imports, so absence
//     there proves lag, not malice.
//   - The upstream source repository from the collection version's own
//     metadata (or the role's GitHub coordinates), feeding verified
//     compare links and -changelogs.
//
// galaxy.ansible.com sends no CORS headers, so the browser (wasm)
// playground disables this layer; the CLI covers it fully.
package ansreg

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
	"github.com/matteo-sung/lockvet/internal/vers"
)

// Enabled gates the whole layer (the wasm playground turns it off:
// galaxy.ansible.com sends no CORS headers).
var Enabled = true

// BaseURL is the Galaxy API base; a var so tests can fake it.
var BaseURL = "https://galaxy.ansible.com"

// Now is a var so tests can pin the clock.
var Now = time.Now

var client = hcache.Client(20 * time.Second)

// uncachedClient re-proves absence evidence on every run, like every
// other unlisted path.
var uncachedClient = &http.Client{Timeout: 20 * time.Second}

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const maxConcurrent = 8

// collection is what lockvet keeps per changed collection.
type collection struct {
	known      bool // the index answers for this collection
	deprecated bool
	created    map[string]string // fetched version → RFC3339 created_at
	repo       map[string]string // fetched version → source repository
	missing    []string          // versions the index answered 404 for
}

// role is what lockvet keeps per changed classic role.
type role struct {
	known    bool
	released map[string]string // version → RFC3339 release date
	repo     string
}

// Annotate fills Ansible Galaxy metadata on the diffs; see the package
// comment for what it covers. The returned bool reports whether at
// least one collection or role was actually vetted against Galaxy.
// freshDays mirrors -fresh-days. Best-effort: per-package failures
// skip that package; only total failure returns an error.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	if !Enabled {
		return false, nil
	}
	type slot struct{ fd, ci int }
	colls := map[string][]slot{}
	roles := map[string][]slot{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.NonRegistry || !strings.Contains(c.Name, ".") {
				continue
			}
			switch c.Ecosystem {
			case "Ansible Galaxy":
				colls[c.Name] = append(colls[c.Name], slot{i, j})
			case "Ansible Galaxy role":
				roles[c.Name] = append(roles[c.Name], slot{i, j})
			}
		}
	}
	if len(colls) == 0 && len(roles) == 0 {
		return false, nil
	}

	wantedOf := func(m map[string][]slot, name string) []string {
		seen := map[string]bool{}
		var out []string
		for _, s := range m[name] {
			for _, v := range diffs[s.fd].Changes[s.ci].New {
				if !seen[v] {
					seen[v] = true
					out = append(out, v)
				}
			}
		}
		sort.Strings(out)
		return out
	}

	var mu sync.Mutex
	gotColl := map[string]*collection{}
	gotRole := map[string]*role{}
	collRole := map[string]*role{} // role fallback for ansible: specs naming a classic role
	var firstErr error
	failures, total := 0, 0
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for name := range colls {
		total++
		wg.Add(1)
		go func(name string, versions []string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			col, err := fetchCollection(name, versions)
			var rl *role
			if err == nil && !col.known {
				// Collections and classic roles share the dotted
				// namespace; an `ansible:` spec (or a collections:
				// entry) naming something only the v1 role index knows
				// still gets ages and links.
				rl, _ = fetchRole(name)
			}
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			gotColl[name] = col
			if rl != nil && rl.known {
				collRole[name] = rl
			}
		}(name, wantedOf(colls, name))
	}
	for name := range roles {
		total++
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			r, err := fetchRole(name)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures++
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			gotRole[name] = r
		}(name)
	}
	wg.Wait()
	if failures == total && firstErr != nil {
		return false, firstErr
	}

	checked := false
	for name, slots := range colls {
		col := gotColl[name]
		if col == nil || !col.known {
			if r := collRole[name]; r != nil {
				checked = true
				for _, s := range slots {
					annotateRole(&diffs[s.fd].Changes[s.ci], r, freshDays)
				}
			}
			continue // not on Galaxy at all, or fetch failed: no claims
		}
		checked = true
		for _, s := range slots {
			annotateCollection(&diffs[s.fd].Changes[s.ci], name, col, freshDays)
		}
	}
	for name, slots := range roles {
		r := gotRole[name]
		if r == nil || !r.known {
			continue
		}
		checked = true
		for _, s := range slots {
			annotateRole(&diffs[s.fd].Changes[s.ci], r, freshDays)
		}
	}
	return checked, nil
}

// applyAge folds published timestamps for the incoming versions into
// the change, deps.dev-layer style.
func applyAge(c *diffx.Change, stamps map[string]string, freshDays int) {
	latest := c.PublishedAt
	for _, v := range c.New {
		if ts, ok := stamps[v]; ok && ts != "" {
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
}

func annotateCollection(c *diffx.Change, name string, col *collection, freshDays int) {
	applyAge(c, col.created, freshDays)

	if col.deprecated && !c.Deprecated && len(c.New) > 0 {
		c.Deprecated = true
		if c.DeprecatedReason == "" {
			c.DeprecatedReason = "collection is marked deprecated on Ansible Galaxy"
		}
	}

	if c.SourceRepo == "" {
		for _, v := range c.New {
			if r := col.repo[v]; r != "" {
				c.SourceRepo = r
				break
			}
		}
	}

	// Registry-verified unlisted: the collection is listed, the
	// incoming version 404s, and an uncached re-fetch agrees.
	if len(col.missing) > 0 && !c.Unlisted {
		miss := map[string]bool{}
		for _, v := range col.missing {
			miss[v] = true
		}
		var still []string
		for _, v := range c.New {
			if miss[v] && reproveMissing(name, v) {
				still = append(still, v)
			}
		}
		if len(still) > 0 {
			c.Unlisted = true
			c.UnlistedVersions = append(c.UnlistedVersions, still...)
		}
	}
}

func annotateRole(c *diffx.Change, r *role, freshDays int) {
	applyAge(c, r.released, freshDays)
	if c.SourceRepo == "" && r.repo != "" {
		c.SourceRepo = r.repo
	}
	// No unlisted, no deprecation claims for roles: the v1 index only
	// updates when the owner re-imports, so absence proves lag.
}

func collectionURL(name string) (string, bool) {
	ns, coll, ok := strings.Cut(name, ".")
	if !ok || ns == "" || coll == "" {
		return "", false
	}
	return BaseURL + "/api/v3/plugin/ansible/content/published/collections/index/" + ns + "/" + coll + "/", true
}

// get performs one Galaxy API GET; ok=false means 404.
func get(cl *http.Client, url string, out any) (ok bool, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return false, fmt.Errorf("galaxy.ansible.com unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return false, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("galaxy.ansible.com answered %d", resp.StatusCode)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return false, fmt.Errorf("galaxy.ansible.com metadata: %w", err)
		}
	}
	return true, nil
}

type versionDoc struct {
	Version   string `json:"version"`
	CreatedAt string `json:"created_at"`
	Metadata  struct {
		Repository string `json:"repository"`
		Homepage   string `json:"homepage"`
	} `json:"metadata"`
}

func fetchCollection(name string, versions []string) (*collection, error) {
	base, ok := collectionURL(name)
	if !ok {
		return &collection{}, nil
	}
	var index struct {
		Deprecated bool `json:"deprecated"`
	}
	known, err := get(client, base, &index)
	if err != nil {
		return nil, err
	}
	if !known {
		return &collection{}, nil
	}
	col := &collection{known: true, deprecated: index.Deprecated,
		created: map[string]string{}, repo: map[string]string{}}
	for _, v := range versions {
		var doc versionDoc
		found, err := get(client, base+"versions/"+v+"/", &doc)
		if err != nil {
			// Best-effort per version: the index answered, so partial
			// data still helps; make no absence claims on errors.
			continue
		}
		if !found {
			col.missing = append(col.missing, v)
			continue
		}
		col.created[v] = doc.CreatedAt
		if r := forgeRepo(doc.Metadata.Repository); r != "" {
			col.repo[v] = r
		} else if r := forgeRepo(doc.Metadata.Homepage); r != "" {
			col.repo[v] = r
		}
	}
	return col, nil
}

// reproveMissing re-fetches one version uncached; true = still 404.
func reproveMissing(name, version string) bool {
	base, ok := collectionURL(name)
	if !ok {
		return false
	}
	found, err := get(uncachedClient, base+"versions/"+version+"/", nil)
	return err == nil && !found
}

func fetchRole(name string) (*role, error) {
	ns, rn, ok := strings.Cut(name, ".")
	if !ok || ns == "" || rn == "" {
		return &role{}, nil
	}
	var doc struct {
		Results []struct {
			ID            json.Number `json:"id"`
			GithubUser    string      `json:"github_user"`
			GithubRepo    string      `json:"github_repo"`
			SummaryFields struct {
				Versions []struct {
					Name        string `json:"name"`
					ReleaseDate string `json:"release_date"`
				} `json:"versions"`
			} `json:"summary_fields"`
		} `json:"results"`
	}
	found, err := get(client, BaseURL+"/api/v1/roles/?namespace="+ns+"&name="+rn, &doc)
	if err != nil {
		return nil, err
	}
	if !found || len(doc.Results) == 0 {
		return &role{}, nil
	}
	res := doc.Results[0]
	r := &role{known: true, released: map[string]string{}}
	record := func(name, ts string) {
		// The classic v1 API mixes RFC 3339 stamps with naive
		// (offset-free) ones; treat the latter as UTC.
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05", strings.SplitN(ts, ".", 2)[0])
		}
		if err == nil {
			stamp := t.UTC().Format(time.RFC3339)
			r.released[name] = stamp
			r.released[strings.TrimPrefix(name, "v")] = stamp
		}
	}
	// The search result's version summary is capped to the most recent
	// handful; the per-role versions endpoint lists them all with their
	// import date (when each became installable).
	if res.ID.String() != "" {
		var vdoc struct {
			Results []struct {
				Name    string `json:"name"`
				Created string `json:"created"`
			} `json:"results"`
		}
		if found, err := get(client, BaseURL+"/api/v1/roles/"+res.ID.String()+"/versions/", &vdoc); err == nil && found {
			for _, v := range vdoc.Results {
				record(v.Name, v.Created)
			}
		}
	}
	for _, v := range res.SummaryFields.Versions {
		if _, ok := r.released[v.Name]; !ok {
			record(v.Name, v.ReleaseDate)
		}
	}
	if res.GithubUser != "" && res.GithubRepo != "" {
		r.repo = "https://github.com/" + res.GithubUser + "/" + res.GithubRepo
	}
	return r, nil
}

// forgeRepo filters a metadata URL down to a forge repository root
// worth probing for tags (helmreg precedent).
func forgeRepo(u string) string {
	u = strings.TrimSpace(u)
	if !strings.HasPrefix(u, "https://") {
		return ""
	}
	rest := strings.TrimPrefix(u, "https://")
	host, path, ok := strings.Cut(rest, "/")
	if !ok || path == "" {
		return ""
	}
	h := strings.ToLower(host)
	if h != "github.com" && h != "gitlab.com" && h != "bitbucket.org" &&
		h != "codeberg.org" && !strings.HasPrefix(h, "git.") {
		return ""
	}
	segs := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(segs) < 2 {
		return ""
	}
	return "https://" + host + "/" + segs[0] + "/" + strings.TrimSuffix(segs[1], ".git")
}

// Latest resolves `lockvet pkg ansible:<name>`: the collection's
// highest_version from the v3 index, falling back to the classic role
// index (newest stable tag) when no collection by that name exists.
func Latest(name string) (string, error) {
	if base, ok := collectionURL(name); ok {
		var index struct {
			HighestVersion struct {
				Version string `json:"version"`
			} `json:"highest_version"`
		}
		known, err := get(client, base, &index)
		if err != nil {
			return "", err
		}
		if known && index.HighestVersion.Version != "" {
			return index.HighestVersion.Version, nil
		}
	}
	r, err := fetchRole(name)
	if err != nil {
		return "", err
	}
	if r.known {
		best := ""
		for v := range r.released {
			if strings.HasPrefix(v, "v") {
				continue // the stripped twin is present too
			}
			if strings.Contains(v, "-") {
				continue // prerelease tags only win when nothing else exists
			}
			if best == "" || vers.Compare(v, best) > 0 {
				best = v
			}
		}
		if best == "" {
			for v := range r.released {
				if best == "" || vers.Compare(v, best) > 0 {
					best = v
				}
			}
		}
		if best != "" {
			return best, nil
		}
	}
	return "", fmt.Errorf("Ansible Galaxy knows no collection or role named %q — collections and roles are <namespace>.<name>", name)
}
