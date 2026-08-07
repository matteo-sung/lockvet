// Package swiftreg verifies SwiftPM Package.resolved pins against the
// upstream repositories' real tags, fetched anonymously over git
// smart-HTTP (one GET per repository, no API rate limits — the same
// channel internal/taglink and internal/actreg use).
//
// SwiftPM has no registry in practice: a Package.resolved pin IS a git
// repository URL, a version, and the commit the version's tag resolved
// to. That makes two things checkable against the source of truth:
//
//   - the version's tag still exists upstream. Version pins can only
//     ever resolve from tags, so an incoming version with no matching
//     tag today means the tag was deleted or renamed after someone
//     resolved it — the unlisted flag;
//   - the pinned commit is what the upstream tag points at TODAY.
//     Released tags are supposed to be immutable. A mismatch means the
//     tag has been re-pointed since resolution (how the tj-actions
//     attack shipped) or the lockfile was edited to fetch a different
//     commit while displaying an innocent version — the tag-mismatch
//     flag.
//
// Repositories that cannot be fetched anonymously (private, moved,
// SSH-only) produce no claims at all.
package swiftreg

import (
	"fmt"
	"strings"
	"sync"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/taglink"
)

// Enabled gates the whole layer; the browser (wasm) build sets it to
// false — git smart-HTTP endpoints send no CORS headers.
var Enabled = true

// Concurrency bounds parallel ref fetches.
var Concurrency = 8

// Annotate verifies Swift package pins in place. ok reports whether at
// least one repository's refs were checked.
func Annotate(diffs []diffx.FileDiff) (bool, error) {
	if !Enabled {
		return false, nil
	}
	repos := map[string]bool{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if wants(c) {
				repos[c.Name] = true
			}
		}
	}
	if len(repos) == 0 {
		return false, nil
	}

	refs := fetchAll(repos)
	if len(refs) == 0 {
		return false, nil
	}

	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			rr, ok := refs[c.Name]
			if !wants(c) || !ok {
				continue
			}
			annotateChange(c, rr)
		}
	}
	return true, nil
}

// wants reports whether the change is a Swift package pin this layer can
// check: a host/org/repo name whose first segment looks like a hostname.
func wants(c *diffx.Change) bool {
	if lock.Ecosystem(c.Ecosystem) != lock.SwiftURL || c.NonRegistry {
		return false
	}
	if len(c.New) == 0 {
		return false // nothing incoming to verify
	}
	parts := strings.SplitN(c.Name, "/", 2)
	return len(parts) == 2 && strings.Contains(parts[0], ".") &&
		strings.Contains(parts[1], "/")
}

type repoRefs struct {
	tags map[string]string
}

func fetchAll(repos map[string]bool) map[string]repoRefs {
	sem := make(chan struct{}, Concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	out := map[string]repoRefs{}
	for name := range repos {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			tags, _, err := taglink.Refs("https://" + name)
			if err != nil || len(tags) == 0 {
				return // no ref data: make no claims about this repo
			}
			mu.Lock()
			out[name] = repoRefs{tags: tags}
			mu.Unlock()
		}(name)
	}
	wg.Wait()
	return out
}

func annotateChange(c *diffx.Change, rr repoRefs) {
	if c.SourceRepo == "" {
		// Enables verified compare links and -changelogs downstream.
		c.SourceRepo = "https://" + c.Name
	}
	for _, v := range c.New {
		tag, sha, ok := matchTag(rr.tags, v)
		if !ok {
			// Version pins only ever resolve from tags; no tag today
			// means it was deleted or renamed since this was resolved.
			c.Unlisted = true
			c.UnlistedVersions = append(c.UnlistedVersions, v)
			continue
		}
		pin, okPin := strings.CutPrefix(c.NewPins[v], "commit:")
		if !okPin || pin == "" || sha == "" {
			continue
		}
		if !strings.EqualFold(pin, sha) {
			c.TagMismatch = true
			c.TagMismatches = append(c.TagMismatches, fmt.Sprintf(
				"%s pinned at %.12s, upstream tag %s is at %.12s",
				v, pin, tag, sha))
		}
	}
}

// matchTag finds the tag for a resolved version. Package.resolved stores
// versions without the v-prefix; upstream may tag either way.
func matchTag(tags map[string]string, v string) (tag, sha string, ok bool) {
	if s, found := tags[v]; found {
		return v, s, true
	}
	if s, found := tags["v"+v]; found {
		return "v" + v, s, true
	}
	return "", "", false
}
