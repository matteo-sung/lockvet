// Package taglink turns version bumps into verified upstream links: it
// fetches each source repository's tag list over git's smart-HTTP protocol
// (one anonymous GET per repo, no API tokens, no rate limits) and, when the
// old and new versions match real tags, builds compare / release-notes URLs
// that are guaranteed not to 404.
package taglink

import (
	"bufio"
	"fmt"
	"github.com/matteo-sung/lockvet/internal/hcache"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// Concurrency is the number of repositories fetched in parallel.
var Concurrency = 12

var client = hcache.Client(10 * time.Second)

// forge styles determine how compare / tag URLs are written.
type forge int

const (
	forgeNone forge = iota
	forgeGitHub
	forgeGitLab
	forgeBitbucket
	forgeGitea
	forgeGitiles
)

func forgeOf(host string) forge {
	switch {
	case host == "github.com":
		return forgeGitHub
	case host == "gitlab.com" || strings.Contains(host, "gitlab"):
		return forgeGitLab
	case host == "bitbucket.org":
		return forgeBitbucket
	case host == "codeberg.org" || host == "gitea.com":
		return forgeGitea
	case strings.HasSuffix(host, ".googlesource.com"):
		return forgeGitiles // golang.org/x/* live here
	}
	return forgeNone
}

// NormalizeRepoURL canonicalises the many shapes registries use for a
// source-repo reference ("git+https://…​.git", "git@github.com:o/r.git",
// "git://…", trailing /tree/… paths) into a plain https URL, or "" when it
// can't be made canonical.
func NormalizeRepoURL(raw string) string {
	s := strings.TrimSpace(raw)
	s = strings.TrimPrefix(s, "git+")
	if m := scpLike.FindStringSubmatch(s); m != nil {
		s = "https://" + m[1] + "/" + m[2]
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	switch u.Scheme {
	case "http", "https", "git", "ssh":
	default:
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if !strings.Contains(host, ".") {
		return ""
	}
	path := strings.Trim(u.Path, "/")
	path = strings.TrimSuffix(path, ".git")
	// Monorepo sub-paths point inside the repo, not at it.
	if i := strings.Index(path, "/-/"); i >= 0 {
		path = path[:i] // GitLab in-repo path
	}
	if i := strings.Index(path, "/tree/"); i >= 0 {
		path = path[:i]
	}
	segs := strings.Split(path, "/")
	f := forgeOf(host)
	// Gitiles repo paths can be a single segment (go.googlesource.com/exp).
	minSegs := 2
	if f == forgeGitiles {
		minSegs = 1
	}
	if len(segs) < minSegs || segs[0] == "" {
		return ""
	}
	// GitHub / Bitbucket / Gitea repos are exactly owner/name; GitLab
	// allows subgroups and Gitiles arbitrary paths, so keep those whole.
	if len(segs) >= 2 && f != forgeGitLab && f != forgeGitiles && f != forgeNone {
		path = segs[0] + "/" + segs[1]
	}
	return "https://" + host + "/" + path
}

var scpLike = regexp.MustCompile(`^(?:ssh://)?git@([^:/]+)[:/](.+)$`)

// Annotate fills CompareURL / ReleaseURL on changes whose SourceRepo is on a
// known forge, verifying tag names against the repository's real tag list.
// Best-effort and silent: unreachable repos or unmatched tags simply leave
// the fields empty.
func Annotate(diffs []diffx.FileDiff) {
	type work struct {
		repo    string
		changes []*diffx.Change
	}
	byRepo := map[string]*work{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.SourceRepo == "" || c.Kind == diffx.Removed || len(c.New) != 1 {
				continue
			}
			if c.Ecosystem == "Nix" {
				// Flake pins are commit revisions: links need no tag
				// verification (internal/flakereg writes them without
				// fetching anything).
				continue
			}
			u, err := url.Parse(c.SourceRepo)
			if err != nil || forgeOf(u.Hostname()) == forgeNone {
				continue
			}
			w := byRepo[c.SourceRepo]
			if w == nil {
				w = &work{repo: c.SourceRepo}
				byRepo[c.SourceRepo] = w
			}
			w.changes = append(w.changes, c)
		}
	}
	if len(byRepo) == 0 {
		return
	}

	jobs := make(chan *work)
	var wg sync.WaitGroup
	for n := 0; n < Concurrency; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range jobs {
				tags, err := Tags(w.repo)
				if err != nil {
					continue
				}
				for _, c := range w.changes {
					link(c, tags)
				}
			}
		}()
	}
	for _, w := range byRepo {
		jobs <- w
	}
	close(jobs)
	wg.Wait()
}

// link fills CompareURL / ReleaseURL for one change from a verified tag set.
func link(c *diffx.Change, tags map[string]bool) {
	u, _ := url.Parse(c.SourceRepo)
	f := forgeOf(u.Hostname())

	newRef, newIsTag := resolveRef(c, c.New[0], tags)
	if newRef == "" {
		return
	}
	if newIsTag {
		c.ReleaseURL = tagURL(f, c.SourceRepo, newRef)
	}
	if len(c.Old) != 1 {
		return
	}
	oldRef, _ := resolveRef(c, c.Old[0], tags)
	if oldRef == "" || oldRef == newRef {
		return
	}
	c.CompareURL = compareURL(f, c.SourceRepo, oldRef, newRef)
}

// resolveRef finds something the forge can address for a version: a real
// tag (in one of the naming conventions registries use) or, for Go
// pseudo-versions, the bare commit hash.
func resolveRef(c *diffx.Change, ver string, tags map[string]bool) (ref string, isTag bool) {
	// A workflow pin actreg already resolved (SHA or floating tag → the
	// release it points at) is addressed by that tag.
	if t, ok := c.ResolvedRefs[ver]; ok && tags[t] {
		return t, true
	}
	if c.Ecosystem == "GitHub Actions" && tags[ver] {
		// Workflow pins name tags verbatim (v4, v4.2.2).
		return ver, true
	}
	for _, cand := range candidates(c, ver) {
		if tags[cand] {
			return cand, true
		}
	}
	if c.Ecosystem == "Go" {
		if sha := pseudoVersionSHA(ver); sha != "" {
			return sha, false
		}
	}
	return "", false
}

// Candidates lists tag names that could mark this version of a package,
// most likely first (exported for relnotes' no-taglink fallback, which
// resolves versions against a repository's release list instead of its
// tag advertisement).
func Candidates(c *diffx.Change, ver string) []string { return candidates(c, ver) }

// candidates lists tag names that could mark this version, most likely
// first: v-prefixed, bare, npm-monorepo (name@ver), release-please
// (name-vver), cargo-workspace (name-ver), and Go submodule (dir/vver).
func candidates(c *diffx.Change, ver string) []string {
	ver = strings.TrimSuffix(ver, "+incompatible")
	name := c.Name
	base := name
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	var out []string
	if c.Ecosystem == "Go" {
		// Module inside a bigger repo: tags look like sub/dir/v1.2.3.
		repoPath := strings.TrimPrefix(c.SourceRepo, "https://")
		if strings.HasPrefix(name, repoPath+"/") {
			out = append(out, name[len(repoPath)+1:]+"/v"+ver)
		}
	}
	out = append(out, "v"+ver, ver, name+"@"+ver)
	if base != name {
		out = append(out, base+"@"+ver)
	}
	out = append(out, name+"-v"+ver, name+"-"+ver)
	if base != name {
		out = append(out, base+"-v"+ver, base+"-"+ver)
	}
	return out
}

// pseudoVersionSHA extracts the commit hash from a Go pseudo-version like
// 0.0.0-20240101000000-abcdef123456.
func pseudoVersionSHA(ver string) string {
	i := strings.LastIndex(ver, "-")
	if i < 0 {
		return ""
	}
	sha := ver[i+1:]
	if len(sha) != 12 {
		return ""
	}
	for _, r := range sha {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return ""
		}
	}
	// The middle segment must be a 14-digit timestamp.
	rest := ver[:i]
	j := strings.LastIndex(rest, "-")
	if j < 0 || len(rest)-j-1 != 14 {
		return ""
	}
	for _, r := range rest[j+1:] {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return sha
}

// CompareRevsURL writes a forge compare link between two commit revisions
// verbatim — a revision addresses itself, so unlike tag links nothing needs
// verifying against the repository. "" when the forge is unknown.
func CompareRevsURL(repo, oldRev, newRev string) string {
	u, err := url.Parse(repo)
	if err != nil {
		return ""
	}
	f := forgeOf(u.Hostname())
	if f == forgeNone {
		return ""
	}
	return compareURL(f, repo, oldRev, newRev)
}

func compareURL(f forge, repo, old, new string) string {
	switch f {
	case forgeGitHub, forgeGitea:
		return repo + "/compare/" + escapeRef(old) + "..." + escapeRef(new)
	case forgeGitLab:
		return repo + "/-/compare/" + escapeRef(old) + "..." + escapeRef(new)
	case forgeBitbucket:
		// Bitbucket compares "source..destination" (changes in source
		// that destination lacks).
		return repo + "/branches/compare/" + escapeRef(new) + ".." + escapeRef(old)
	case forgeGitiles:
		return repo + "/+/" + escapeRef(old) + ".." + escapeRef(new)
	}
	return ""
}

func tagURL(f forge, repo, tag string) string {
	switch f {
	case forgeGitHub, forgeGitea:
		return repo + "/releases/tag/" + escapeRef(tag)
	case forgeGitLab:
		return repo + "/-/tags/" + escapeRef(tag)
	case forgeBitbucket:
		return repo + "/src/" + escapeRef(tag)
	case forgeGitiles:
		return repo + "/+/refs/tags/" + escapeRef(tag)
	}
	return ""
}

// escapeRef escapes the few characters that would break a ref inside a URL
// path while leaving '/' (Go submodule tags) and '@' (npm tags) readable.
var escapeRef = strings.NewReplacer(
	"%", "%25", "#", "%23", "?", "%3F", " ", "%20", "\"", "%22",
).Replace

// refsURL builds the smart-HTTP ref advertisement URL.
func refsURL(repo string) string {
	return repo + ".git/info/refs?service=git-upload-pack"
}

// Transport rewires requests in tests.
var Transport = func(req *http.Request) (*http.Response, error) { return client.Do(req) }

// Tags fetches the tag names of a repository via git's smart-HTTP ref
// advertisement: a single anonymous GET understood by every major forge.
func Tags(repo string) (map[string]bool, error) {
	shas, err := TagSHAs(repo)
	if err != nil {
		return nil, err
	}
	tags := make(map[string]bool, len(shas))
	for t := range shas {
		tags[t] = true
	}
	return tags, nil
}

// TagSHAs fetches tag name -> commit SHA from the same advertisement.
// Annotated tags collapse onto their peeled (^{}) commit.
func TagSHAs(repo string) (map[string]string, error) {
	tags, _, err := Refs(repo)
	return tags, err
}

// Refs fetches tag name -> commit SHA and branch name -> head SHA from
// one smart-HTTP ref advertisement. Annotated tags collapse onto their
// peeled (^{}) commit.
func Refs(repo string) (tags, heads map[string]string, err error) {
	req, err := http.NewRequest("GET", refsURL(repo), nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "git/2.43.0 (lockvet)")
	resp, err := Transport(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("%s: HTTP %d", repo, resp.StatusCode)
	}
	return parseAdvertisement(io.LimitReader(resp.Body, 16<<20))
}

// parseAdvertisement reads pkt-line framing and collects refs/tags/* names
// (peeled ^{} entries collapse onto the tag itself).
func parseAdvertisement(r io.Reader) (tags, heads map[string]string, err error) {
	br := bufio.NewReader(r)
	tags, heads = map[string]string{}, map[string]string{}
	for {
		head := make([]byte, 4)
		if _, err := io.ReadFull(br, head); err != nil {
			if err == io.EOF {
				return tags, heads, nil
			}
			return nil, nil, err
		}
		var n int
		if _, err := fmt.Sscanf(string(head), "%04x", &n); err != nil {
			return nil, nil, fmt.Errorf("bad pkt-line length %q", head)
		}
		if n == 0 {
			continue // flush-pkt
		}
		if n < 4 {
			return nil, nil, fmt.Errorf("bad pkt-line length %d", n)
		}
		payload := make([]byte, n-4)
		if _, err := io.ReadFull(br, payload); err != nil {
			return nil, nil, err
		}
		line := strings.TrimSuffix(string(payload), "\n")
		if strings.HasPrefix(line, "#") {
			continue // "# service=git-upload-pack"
		}
		if i := strings.IndexByte(line, 0); i >= 0 {
			line = line[:i] // capability list on the first ref line
		}
		sp := strings.IndexByte(line, ' ')
		if sp < 0 {
			continue
		}
		sha, ref := line[:sp], line[sp+1:]
		if h := strings.TrimPrefix(ref, "refs/heads/"); h != ref {
			heads[h] = sha
			continue
		}
		if !strings.HasPrefix(ref, "refs/tags/") {
			continue
		}
		name := strings.TrimPrefix(ref, "refs/tags/")
		if peeled := strings.TrimSuffix(name, "^{}"); peeled != name {
			// The peeled entry carries the commit an annotated tag
			// points at — always prefer it.
			tags[peeled] = sha
		} else if _, seen := tags[name]; !seen {
			tags[name] = sha
		}
	}
}
