// Package npmreg asks the npm registry whether versions run install
// scripts (preinstall / install / postinstall). A bump that ADDS install
// scripts where the outgoing version ran none is how several real npm
// supply-chain attacks delivered their payload (Shai-Hulud's postinstall
// worm being the loudest), so lockvet flags that transition.
//
// One GET per changed package fetches the abbreviated metadata document
// (Accept: application/vnd.npm.install-v1+json), which carries a
// per-version hasInstallScript field. The endpoint answers with
// Access-Control-Allow-Origin: * and the Accept header is CORS-safelisted,
// so the wasm build can use it too.
package npmreg

import (
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// RegistryURL is a var so tests can point it at a fake server.
var RegistryURL = "https://registry.npmjs.org"

var client = &http.Client{Timeout: 20 * time.Second}

// Annotate does two npm-registry passes over the diffs, sharing one
// metadata download per package:
//
//   - It sets ScriptsAdded / ScriptedVersions on bumps whose incoming
//     version runs install scripts while no outgoing version did. Only
//     transitions are flagged: a brand-new dependency with install
//     scripts is ordinary (native builds), and a package that has always
//     had them tells you nothing new.
//   - It re-verifies Unlisted flags (set by the deps.dev layer, which can
//     lag npm by days) against the registry itself: a version npm serves
//     is not unlisted, no matter what deps.dev thinks. Versions the npm
//     registry confirms missing keep the flag — that is exactly what
//     unpublished malware looks like. Call it AFTER depsdev.Annotate.
//
// Best-effort: network errors return an error but leave diffs usable.
func Annotate(diffs []diffx.FileDiff) error {
	type slot struct{ fd, ci int }
	byPkg := map[string][]slot{}  // scripts pass: bumps per package name
	verify := map[string][]slot{} // unlisted pass: flagged changes per name
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "npm" || strings.HasPrefix(c.Name, "jsr:") {
				continue // jsr: deno.lock JSR entries are not npm packages
			}
			if c.Unlisted {
				verify[c.Name] = append(verify[c.Name], slot{i, j})
			}
			if c.NonRegistry || len(c.Old) == 0 || len(c.New) == 0 {
				continue // additions/removals: transitions only
			}
			byPkg[c.Name] = append(byPkg[c.Name], slot{i, j})
		}
	}
	if len(byPkg) == 0 && len(verify) == 0 {
		return nil
	}

	seen := map[string]bool{}
	var names []string
	for n := range byPkg {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	for n := range verify {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	scripts, err := fetchScripts(names)
	if err != nil {
		return err
	}

	for name, slots := range byPkg {
		known, ok := scripts[name]
		if !ok || len(known) == 0 {
			continue // package not on the registry, or fetch failed
		}
		for _, s := range slots {
			c := &diffs[s.fd].Changes[s.ci]
			oldSeen, oldScripted := false, false
			old := map[string]bool{}
			for _, v := range c.Old {
				v = cleanVersion(v)
				old[v] = true
				if has, ok := known[v]; ok {
					oldSeen = true
					oldScripted = oldScripted || has
				}
			}
			if !oldSeen || oldScripted {
				// Old side unknown (can't call it a transition) or the
				// package already ran scripts before this change.
				continue
			}
			var added []string
			for _, v := range c.New {
				v = cleanVersion(v)
				if old[v] {
					continue
				}
				if known[v] {
					added = append(added, v)
				}
			}
			if len(added) > 0 {
				c.ScriptsAdded = true
				c.ScriptedVersions = added
			}
		}
	}
	// Unlisted verification: keep only versions the npm registry itself
	// lacks. A 404 for the whole package (no doc entry) keeps every flag —
	// the package is gone from npm, which is worse.
	for name, slots := range verify {
		known, ok := scripts[name]
		if !ok || len(known) == 0 {
			continue
		}
		for _, s := range slots {
			c := &diffs[s.fd].Changes[s.ci]
			var still []string
			for _, v := range c.UnlistedVersions {
				if _, listed := known[cleanVersion(v)]; !listed {
					still = append(still, v)
				}
			}
			c.UnlistedVersions = still
			c.Unlisted = len(still) > 0
		}
	}
	return nil
}

// cleanVersion strips lockfile decoration (pnpm peer-dep suffixes like
// "1.2.3(react@18.0.0)") so versions match registry keys.
func cleanVersion(v string) string {
	if i := strings.IndexByte(v, '('); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

// fetchScripts downloads each package's abbreviated metadata a few at a
// time and returns version -> hasInstallScript per package. 404s (and
// undecodable answers) simply yield no entry; other HTTP failures abort
// with an error so callers can warn once.
func fetchScripts(names []string) (map[string]map[string]bool, error) {
	out := make(map[string]map[string]bool, len(names))
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
			req, err := http.NewRequest("GET", RegistryURL+"/"+neturl.PathEscape(name), nil)
			if err != nil {
				return
			}
			req.Header.Set("Accept", "application/vnd.npm.install-v1+json")
			resp, err := client.Do(req)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("npm registry unreachable: %w", err)
				}
				mu.Unlock()
				return
			}
			defer resp.Body.Close()
			switch resp.StatusCode {
			case 200:
				var doc struct {
					Versions map[string]struct {
						HasInstallScript bool `json:"hasInstallScript"`
					} `json:"versions"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
					return
				}
				set := make(map[string]bool, len(doc.Versions))
				for v, info := range doc.Versions {
					set[v] = info.HasInstallScript
				}
				mu.Lock()
				out[name] = set
				mu.Unlock()
			case 404:
				// not on the registry: leave no entry
			default:
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("npm registry returned HTTP %d", resp.StatusCode)
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
