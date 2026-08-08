// Package actreg resolves GitHub Actions workflow pins against the action
// repositories' real tag lists, fetched anonymously over git smart-HTTP
// (one GET per repository, no API rate limits — the same channel
// internal/taglink uses).
//
// What it settles:
//   - a commit-SHA pin that equals a release tag is displayed as that
//     release ("8f4b7f8… (=v4.2.2)") and vulnerability-matched as it;
//   - a floating major tag (v4) is resolved to the concrete release it
//     currently points at, so advisories fixed inside the major don't
//     false-positive;
//   - a SHA that matches NO tag, or a version-shaped ref that is not a
//     tag in the repo, raises the unlisted flag: release tags are how
//     actions ship, and the March-2025 tj-actions/changed-files attack
//     pinned users to exactly such commits.
package actreg

import (
	"strings"
	"sync"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/taglink"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// Enabled gates the whole layer; the browser (wasm) build sets it to
// false — git smart-HTTP endpoints send no CORS headers.
var Enabled = true

// Concurrency bounds parallel tag fetches.
var Concurrency = 8

// Annotate resolves workflow and pre-commit pins in place. ok reports
// whether at least one repository's tags were checked.
func Annotate(diffs []diffx.FileDiff) (bool, error) {
	if !Enabled {
		return false, nil
	}
	repos := map[string]bool{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if u := repoURL(c); u != "" {
				repos[u] = true
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
		fd := &diffs[i]
		touched := false
		for j := range fd.Changes {
			c := &fd.Changes[j]
			rr, ok := refs[repoURL(c)]
			if !ok {
				continue
			}
			annotateChange(c, rr)
			touched = true
		}
		if touched {
			fd.Sort()
		}
	}
	return true, nil
}

// repoURL returns the repository URL behind a pin this layer can check —
// a GitHub Actions `uses:` name (owner/repo, hosted by workflow convention
// on github.com) or a pre-commit hook repository (host/path, any forge) —
// or "" for changes that are not tag-verifiable pins.
func repoURL(c *diffx.Change) string {
	if c.NonRegistry {
		return ""
	}
	switch lock.Ecosystem(c.Ecosystem) {
	case lock.GitHubActions:
		if strings.Count(c.Name, "/") == 1 {
			return "https://github.com/" + c.Name
		}
	case lock.PreCommit:
		if host, path, ok := strings.Cut(c.Name, "/"); ok &&
			strings.Contains(host, ".") && path != "" {
			return "https://" + c.Name
		}
	}
	return ""
}

// repoRefs is one repository's ref advertisement: its release tags and
// branch heads.
type repoRefs struct {
	tags, heads map[string]string
}

func fetchAll(repos map[string]bool) map[string]repoRefs {
	sem := make(chan struct{}, Concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	out := map[string]repoRefs{}
	for u := range repos {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			tags, heads, err := taglink.Refs(u)
			if err != nil || len(tags)+len(heads) == 0 {
				return // no ref data: make no claims about this repo
			}
			mu.Lock()
			out[u] = repoRefs{tags: tags, heads: heads}
			mu.Unlock()
		}(u)
	}
	wg.Wait()
	return out
}

func annotateChange(c *diffx.Change, rr repoRefs) {
	c.SourceRepo = repoURL(c)
	tags := rr.tags

	resolve := func(ref string) string {
		if sha := shaOf(ref); sha != "" {
			t, _ := tagForSHA(tags, sha)
			return t
		}
		canon := ref
		sha, ok := tags[ref]
		if !ok {
			// Tolerate the v-prefix going either way: `lockvet pkg
			// actions:x/y@45.0.7` means the release v45.0.7.
			if s2, ok2 := tags[vSwap(ref)]; ok2 {
				canon, sha, ok = vSwap(ref), s2, true
			}
		}
		if !ok {
			// Actions accept branch pins too — some actions track their
			// major line as a branch, not a tag.
			sha, ok = rr.heads[ref]
		}
		if ok {
			// The ref is real. If a more version-specific tag points at
			// the same commit (v4 alongside v4.2.2), resolve to it —
			// preferring a tag on the ref's own line (v4 → v4.x.y) over
			// an equally-valid alias from another line (codecov tagged
			// the v6.0.2 commit as v7).
			best := ""
			for t, s := range tags {
				if s == sha && t != canon && strings.HasPrefix(t, canon+".") && VersionLike(t) {
					if best == "" || moreSpecific(t, best) {
						best = t
					}
				}
			}
			if best != "" {
				return best
			}
			// Cross-line aliases (another tag on the same commit) are
			// only worth reporting for floating refs like v4: a full
			// version tag IS the release, even when the repo tagged the
			// same commit twice.
			fullVersion := VersionLike(canon) && strings.Count(canon, ".") >= 2
			if !fullVersion {
				if t, ok := tagForSHA(tags, sha); ok && t != canon && moreSpecific(t, canon) {
					return t
				}
			}
			if canon != ref {
				return canon // v-swapped tag with nothing more specific
			}
		}
		return ""
	}

	for _, side := range [][]string{c.Old, c.New} {
		for _, v := range side {
			if tag := resolve(v); tag != "" {
				if c.ResolvedRefs == nil {
					c.ResolvedRefs = map[string]string{}
				}
				c.ResolvedRefs[v] = tag
			}
		}
	}

	// Unlisted: an incoming pin that is neither a tag nor any tag's
	// commit. Branch-name refs (main, master) are a deliberate choice and
	// stay quiet; version-shaped refs and SHAs are how releases are
	// pinned, so "not in the tag list" is a real signal there.
	for _, v := range c.New {
		if _, isTag := tags[v]; isTag {
			continue
		}
		if _, isHead := rr.heads[v]; isHead {
			continue // a real branch: resolvable, just not a release
		}
		if sha := shaOf(v); sha != "" && headSHA(rr.heads, sha) {
			continue // the current head of a branch: pinned latest, not a release — but real
		}
		if _, ok := c.ResolvedRefs[v]; ok {
			continue
		}
		if shaOf(v) == "" && !VersionLike(v) {
			continue
		}
		c.Unlisted = true
		c.UnlistedVersions = append(c.UnlistedVersions, v)
	}

	// With pins resolved to releases, classify the jump properly. When a
	// side cannot be resolved to any release (an orphan SHA, a branch),
	// the direction and size of the jump are unknowable: say "changed",
	// not "downgrade" — the raw-string comparison diffx had to fall back
	// on means nothing between a tag and a commit hash.
	if len(c.Old) == 1 && len(c.New) == 1 {
		effOld, effNew := Effective(c, c.Old[0]), Effective(c, c.New[0])
		if VersionLike(effOld) && VersionLike(effNew) {
			switch cmp := vers.Compare(effOld, effNew); {
			case cmp < 0:
				c.Kind = diffx.Upgraded
				c.Level = vers.Delta(effOld, effNew)
				c.LevelString = c.Level.String()
			case cmp > 0:
				c.Kind = diffx.Downgraded
				c.Level = vers.Delta(effOld, effNew)
				c.LevelString = c.Level.String()
			default:
				c.Level = vers.None
				c.LevelString = ""
			}
		} else {
			c.Kind = diffx.Changed
			c.Level = vers.Unknown
			c.LevelString = c.Level.String()
		}
	}
}

// vSwap flips the v-prefix: v1.2.3 <-> 1.2.3.
func vSwap(ref string) string {
	if strings.HasPrefix(ref, "v") {
		return ref[1:]
	}
	return "v" + ref
}

// Effective returns the version a pinned ref stands for: the resolved
// release tag when the repository's tags settled it, the raw ref otherwise.
func Effective(c *diffx.Change, ref string) string {
	if c.ResolvedRefs != nil {
		if t, ok := c.ResolvedRefs[ref]; ok {
			return t
		}
	}
	return ref
}

// VersionLike reports whether a ref is shaped like a release version
// (v4, 4.2.2, v1.2.3-rc1) rather than a branch name or SHA.
func VersionLike(ref string) bool {
	s := strings.TrimPrefix(ref, "v")
	if s == "" || s[0] < '0' || s[0] > '9' {
		return false
	}
	if shaOf(ref) != "" {
		return false // all-hex: a commit, not a version
	}
	for i := 0; i < len(s); i++ {
		switch b := s[i]; {
		case b >= '0' && b <= '9', b == '.':
		case b == '-' || b == '+':
			return true // numeric prefix with a pre-release/build suffix
		default:
			return false
		}
	}
	return true
}

// shaOf returns the lowercase hex commit prefix if ref looks like an
// (abbreviated) git SHA, else "".
func shaOf(ref string) string {
	if len(ref) < 7 || len(ref) > 40 {
		return ""
	}
	allDigit := true
	for i := 0; i < len(ref); i++ {
		b := ref[i]
		switch {
		case b >= '0' && b <= '9':
		case b >= 'a' && b <= 'f', b >= 'A' && b <= 'F':
			allDigit = false
		default:
			return ""
		}
	}
	if allDigit && len(ref) < 40 {
		return "" // "20230101" is a date-ish version, not a SHA
	}
	return strings.ToLower(ref)
}

// tagForSHA finds the tag whose commit matches the (possibly abbreviated)
// SHA, preferring the most version-specific name when several tags point
// at the same commit.
func tagForSHA(tags map[string]string, sha string) (string, bool) {
	best := ""
	for t, s := range tags {
		if !strings.HasPrefix(s, sha) {
			continue
		}
		if best == "" || moreSpecific(t, best) {
			best = t
		}
	}
	return best, best != ""
}

// moreSpecific prefers version-like tags with more numeric segments:
// v4.2.2 beats v4.2 beats v4 beats "latest".
func moreSpecific(a, b string) bool {
	av, bv := VersionLike(a), VersionLike(b)
	if av != bv {
		return av
	}
	as, bs := strings.Count(a, "."), strings.Count(b, ".")
	if as != bs {
		return as > bs
	}
	return a < b
}

// headSHA reports whether the (abbreviated) SHA is some branch's current
// head.
func headSHA(heads map[string]string, sha string) bool {
	for _, s := range heads {
		if strings.HasPrefix(s, sha) {
			return true
		}
	}
	return false
}
