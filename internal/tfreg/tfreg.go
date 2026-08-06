// Package tfreg asks the Terraform and OpenTofu registries what they
// know about the providers a .terraform.lock.hcl diff touches. Neither
// OSV.dev nor deps.dev has any Terraform system, so for infrastructure
// lockfiles this package IS the metadata layer, not a fallback:
//
//   - Release ages and the ⏱ cooldown flag, from each provider
//     version's published timestamp.
//   - Archived / delisted providers land in the deprecation lane:
//     registry.terraform.io carries an explicit warning for deprecated
//     providers, an `unlisted` flag for delisted ones, and HashiCorp's
//     archived providers say so in their description (kept verbatim,
//     replacement suggestion included — "Please use the templatefile
//     function or the Cloudinit provider instead"). Providers blocked
//     by the OpenTofu registry are reported with the block reason.
//   - Unlisted detection: an incoming provider version missing from
//     the registry's own version list — while the provider's other
//     versions ARE listed — is what a pulled release looks like.
//     Providers the registry does not know at all are never flagged.
//   - The upstream source repository, which the changelog layers turn
//     into verified tag-to-tag compare links and release notes
//     (provider repos tag vX.Y.Z, and the registry requires them to
//     live in public VCS).
//
// Routing follows the lockfile itself: providers pinned from the
// default registry.terraform.io host are asked about on
// registry.terraform.io (one GET per provider, the same v2 API the
// registry website uses); providers pinned as registry.opentofu.org/…
// are asked about on api.opentofu.org (one GET per provider). Custom
// or private registry hosts are left alone entirely.
//
// registry.terraform.io sends no CORS headers, so the browser (wasm)
// build cannot query it. There, default-host providers fall back to
// api.opentofu.org — which mirrors the same provider namespace and is
// CORS-open — for release ages and source links ONLY: the mirror can
// lag the primary registry, so the fallback never flags unlisted
// versions and never reports deprecations. The native build never uses
// the fallback.
package tfreg

import (
	"encoding/json"
	"fmt"
	"github.com/matteo-sung/lockvet/internal/hcache"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// TerraformBaseURL is the Terraform registry API base; a var so tests
// can point it at an httptest server.
var TerraformBaseURL = "https://registry.terraform.io"

// OpenTofuBaseURL is the OpenTofu registry-metadata API base; a var so
// tests can fake it.
var OpenTofuBaseURL = "https://api.opentofu.org"

// UseTerraformRegistry gates direct calls to registry.terraform.io.
// The browser (wasm) build sets it to false — the endpoint sends no
// CORS headers — which reroutes default-host providers to the
// CORS-open OpenTofu mirror in ages-and-links-only mode.
var UseTerraformRegistry = true

// Now is a var so tests can pin the clock.
var Now = time.Now

var client = hcache.Client(20 * time.Second)

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

const maxConcurrent = 6

// provider is what lockvet keeps per registry provider.
type provider struct {
	published map[string]string // version (no "v") → RFC3339 published
	missing   map[string]bool   // versions VERIFIED absent from the registry
	deprecato string            // deprecation-lane reason, "" if none
	source    string            // upstream repository URL, may be ""
	agesOnly  bool              // mirror fallback: no unlisted/deprecation claims
}

// target is one provider to look up and where.
type target struct {
	ns, name string
	opentofu bool // ask api.opentofu.org instead of registry.terraform.io
	agesOnly bool // wasm fallback: apply ages+source only
}

// Annotate fills Terraform/OpenTofu registry metadata on the diffs; see
// the package comment for what it covers. The returned bool reports
// whether at least one provider was actually vetted against a registry
// (deps.dev never covers Terraform, so callers use it to decide whether
// release metadata was checked at all). freshDays mirrors -fresh-days.
// Best-effort: per-provider failures skip that provider; only total
// failure returns an error.
func Annotate(diffs []diffx.FileDiff, freshDays int) (bool, error) {
	type slot struct{ fd, ci int }
	byName := map[string][]slot{}
	targets := map[string]target{}
	incoming := map[string][]string{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "Terraform" || c.NonRegistry {
				continue
			}
			t, ok := route(c.Name)
			if !ok {
				continue
			}
			byName[c.Name] = append(byName[c.Name], slot{i, j})
			targets[c.Name] = t
			incoming[c.Name] = append(incoming[c.Name], c.New...)
		}
	}
	if len(byName) == 0 {
		return false, nil
	}

	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)

	provs := make(map[string]*provider, len(names))
	var mu sync.Mutex
	var firstErr error
	failures := 0
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, name := range names {
		wg.Add(1)
		go func(name string, t target) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var p *provider
			var err error
			if t.opentofu {
				p, err = fetchOpenTofu(t, incoming[name])
			} else {
				p, err = fetchTerraform(t, incoming[name])
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
			if p != nil {
				provs[name] = p
			}
		}(name, targets[name])
	}
	wg.Wait()
	if failures == len(names) && firstErr != nil {
		return false, firstErr
	}

	checked := false
	for name, slots := range byName {
		p := provs[name]
		if p == nil {
			continue // registry does not know the provider: flag nothing
		}
		checked = true
		for _, s := range slots {
			annotateChange(&diffs[s.fd].Changes[s.ci], p, freshDays)
		}
	}
	return checked, nil
}

// route decides which registry to ask about a provider, from the name
// the lockfile pins. The parser strips the default registry.terraform.io
// host ("hashicorp/aws") and keeps every other host verbatim
// ("registry.opentofu.org/hashicorp/null", "tf.example.com/acme/x").
func route(name string) (target, bool) {
	parts := strings.Split(name, "/")
	if len(parts) == 2 && !strings.Contains(parts[0], ".") {
		if parts[0] == "" || parts[1] == "" {
			return target{}, false
		}
		if UseTerraformRegistry {
			return target{ns: parts[0], name: parts[1]}, true
		}
		// Browser build: CORS-open mirror, ages and source links only.
		return target{ns: parts[0], name: parts[1], opentofu: true, agesOnly: true}, true
	}
	if len(parts) == 3 && parts[0] == "registry.opentofu.org" && parts[1] != "" && parts[2] != "" {
		return target{ns: parts[1], name: parts[2], opentofu: true}, true
	}
	return target{}, false // custom/private registry host: leave alone
}

func annotateChange(c *diffx.Change, p *provider, freshDays int) {
	// Release age: keep the most recently published incoming version,
	// exactly like the deps.dev layer does elsewhere.
	latest := c.PublishedAt
	for _, v := range c.New {
		if ts, ok := p.published[v]; ok && ts != "" {
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

	// Upstream repository, for the changelog layers.
	if c.SourceRepo == "" && p.source != "" {
		c.SourceRepo = p.source
	}

	if p.agesOnly {
		return // mirror fallback: no deprecation or unlisted claims
	}

	// Deprecation lane: archived / delisted / registry-warned providers
	// taint every incoming version. Removals are good news; an existing
	// richer reason is never overwritten.
	if len(c.New) > 0 && p.deprecato != "" && c.DeprecatedReason == "" {
		c.Deprecated = true
		c.DeprecatedReason = p.deprecato
	}

	// Unlisted: incoming versions the registry itself no longer serves,
	// while the provider IS listed. For registry.terraform.io these were
	// verified per version (its list endpoints cap at 500 entries — the
	// real AWS provider has more, so list absence alone proves nothing).
	var missing []string
	for _, v := range c.New {
		if p.missing[v] {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		c.Unlisted = true
		c.UnlistedVersions = missing
	}
}

func get(url string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

// fetchTerraform returns nil, nil when registry.terraform.io does not
// know the provider (including fully removed providers — flag nothing).
// want lists the incoming versions the diff pins: any of them absent
// from the v2 version list — which the registry caps at 500 entries —
// is re-checked against the per-version v1 endpoint, so an unlisted
// claim is only ever made after the registry itself answered 404 for
// that exact version. HashiCorp really does pull releases: AWS provider
// 5.71.0 is tagged on GitHub but gone from the registry.
func fetchTerraform(t target, want []string) (*provider, error) {
	url := TerraformBaseURL + "/v2/providers/" + t.ns + "/" + t.name + "?include=provider-versions"
	status, body, err := get(url)
	if err != nil {
		return nil, fmt.Errorf("registry.terraform.io unreachable: %w", err)
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, nil
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("registry.terraform.io rate limit hit; retry in a minute")
	default:
		return nil, fmt.Errorf("registry.terraform.io answered %d for %s/%s", status, t.ns, t.name)
	}
	var doc struct {
		Data struct {
			Attributes struct {
				Description string `json:"description"`
				Source      string `json:"source"`
				Unlisted    bool   `json:"unlisted"`
				Warning     string `json:"warning"`
			} `json:"attributes"`
		} `json:"data"`
		Included []struct {
			Type       string `json:"type"`
			Attributes struct {
				Version     string `json:"version"`
				PublishedAt string `json:"published-at"`
			} `json:"attributes"`
		} `json:"included"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("registry.terraform.io metadata for %s/%s: %w", t.ns, t.name, err)
	}
	p := &provider{published: map[string]string{}, missing: map[string]bool{}}
	for _, inc := range doc.Included {
		if inc.Type != "provider-versions" || inc.Attributes.Version == "" {
			continue
		}
		p.published[inc.Attributes.Version] = inc.Attributes.PublishedAt
	}
	if len(p.published) == 0 {
		return nil, nil
	}
	seen := map[string]bool{}
	for _, v := range want {
		if _, ok := p.published[v]; ok || seen[v] || v == "" {
			continue
		}
		seen[v] = true
		status, body, err := get(TerraformBaseURL + "/v1/providers/" + t.ns + "/" + t.name + "/" + v)
		if err != nil {
			continue // uncertain: claim nothing
		}
		switch status {
		case http.StatusOK:
			var vdoc struct {
				PublishedAt string `json:"published_at"`
			}
			if json.Unmarshal(body, &vdoc) == nil {
				p.published[v] = vdoc.PublishedAt
			} else {
				p.published[v] = ""
			}
		case http.StatusNotFound:
			p.missing[v] = true
		}
	}
	a := doc.Data.Attributes
	if strings.HasPrefix(a.Source, "https://") {
		p.source = strings.TrimSuffix(a.Source, "/")
	}
	switch {
	case a.Warning != "":
		p.deprecato = clip(a.Warning)
	case a.Unlisted:
		p.deprecato = "provider delisted from registry.terraform.io"
	case strings.HasPrefix(a.Description, "This provider has been archived"):
		p.deprecato = clip(strings.TrimSuffix(strings.TrimSpace(
			strings.TrimSuffix(strings.TrimSpace(a.Description),
				"See documentation for more details.")), "."))
	}
	return p, nil
}

// fetchOpenTofu returns nil, nil when the OpenTofu registry does not
// know the provider.
func fetchOpenTofu(t target, want []string) (*provider, error) {
	url := OpenTofuBaseURL + "/registry/docs/providers/" + t.ns + "/" + t.name + "/index.json"
	status, body, err := get(url)
	if err != nil {
		return nil, fmt.Errorf("api.opentofu.org unreachable: %w", err)
	}
	switch status {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusForbidden:
		// The CDN answers 403 for unknown paths in some configurations.
		if status == http.StatusForbidden {
			return nil, fmt.Errorf("api.opentofu.org answered 403 for %s/%s", t.ns, t.name)
		}
		return nil, nil
	case http.StatusTooManyRequests:
		return nil, fmt.Errorf("api.opentofu.org rate limit hit; retry in a minute")
	default:
		return nil, fmt.Errorf("api.opentofu.org answered %d for %s/%s", status, t.ns, t.name)
	}
	var doc struct {
		Addr struct {
			Display string `json:"display"`
		} `json:"addr"`
		Versions []struct {
			ID        string `json:"id"` // "v3.2.0"
			Published string `json:"published"`
		} `json:"versions"`
		IsBlocked     bool   `json:"is_blocked"`
		BlockedReason string `json:"blocked_reason"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("api.opentofu.org metadata for %s/%s: %w", t.ns, t.name, err)
	}
	if len(doc.Versions) == 0 {
		return nil, nil
	}
	p := &provider{published: map[string]string{}, missing: map[string]bool{}, agesOnly: t.agesOnly}
	for _, v := range doc.Versions {
		p.published[strings.TrimPrefix(v.ID, "v")] = v.Published
	}
	if !t.agesOnly {
		// The docs index is the complete list OpenTofu resolves against
		// (511 AWS provider versions where the Terraform registry caps
		// at 500), so absence from it is meaningful — but never when we
		// are only a fallback mirror for default-host providers.
		for _, v := range want {
			if _, ok := p.published[v]; !ok && v != "" {
				p.missing[v] = true
			}
		}
	}
	// OpenTofu indexes providers straight from public GitHub repos;
	// addr.display is "org/terraform-provider-name".
	if d := doc.Addr.Display; strings.Count(d, "/") == 1 && !strings.ContainsAny(d, " \t") {
		p.source = "https://github.com/" + d
	}
	if doc.IsBlocked {
		reason := "provider blocked in the OpenTofu registry"
		if doc.BlockedReason != "" {
			reason += ": " + clip(doc.BlockedReason)
		}
		p.deprecato = reason
	}
	return p, nil
}

// clip keeps registry-supplied prose to one report-friendly line.
func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 220 {
		s = s[:220] + "…"
	}
	return s
}
