// Package relnotes fetches upstream release notes for bumped packages.
// It builds on the taglink layer: a change whose ReleaseURL points at a
// verified GitHub release tag gets the notes for that release — and, when
// the bump skips versions, the notes for every release in between (one
// GitHub API call per repository, opt-in via -changelogs).
package relnotes

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// Concurrency is the number of repositories fetched in parallel.
var Concurrency = 8

// MaxRepos caps how many distinct repositories one run will query, to
// stay well inside unauthenticated API rate limits.
var MaxRepos = 40

// maxNotesPerChange caps how many releases a single multi-version jump
// reports; the compare link already covers the full span.
const maxNotesPerChange = 5

const (
	maxExcerptLines = 12
	maxExcerptChars = 900
)

// APIBase is swappable for tests.
var APIBase = "https://api.github.com"

var client = &http.Client{Timeout: 15 * time.Second}

type release struct {
	TagName    string `json:"tag_name"`
	Name       string `json:"name"`
	Body       string `json:"body"`
	HTMLURL    string `json:"html_url"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

// Annotate fills ReleaseNotes on changes whose ReleaseURL is a GitHub
// release-tag link. Best-effort: unreachable repos are skipped; the only
// surfaced warning is a rate-limit hint. token may be empty.
func Annotate(diffs []diffx.FileDiff, token string) (warnings []string) {
	type work struct {
		owner, repo string
		changes     []*diffx.Change
		tags        []string // the verified new-version tag per change
	}
	byRepo := map[string]*work{}
	var order []string
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			owner, repo, tag := parseReleaseURL(c.ReleaseURL)
			if owner == "" {
				continue
			}
			key := owner + "/" + repo
			w := byRepo[key]
			if w == nil {
				if len(byRepo) >= MaxRepos {
					continue
				}
				w = &work{owner: owner, repo: repo}
				byRepo[key] = w
				order = append(order, key)
			}
			w.changes = append(w.changes, c)
			w.tags = append(w.tags, tag)
		}
	}
	if len(byRepo) == 0 {
		return nil
	}

	var (
		mu          sync.Mutex
		rateLimited bool
	)
	jobs := make(chan *work)
	var wg sync.WaitGroup
	for n := 0; n < Concurrency; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range jobs {
				rels, limited, err := fetchReleases(w.owner, w.repo, token)
				if limited {
					mu.Lock()
					rateLimited = true
					mu.Unlock()
				}
				if err != nil || len(rels) == 0 {
					continue
				}
				for k, c := range w.changes {
					c.ReleaseNotes = notesFor(c, w.tags[k], rels)
				}
			}
		}()
	}
	for _, key := range order {
		jobs <- byRepo[key]
	}
	close(jobs)
	wg.Wait()

	if rateLimited {
		warnings = append(warnings,
			"release notes incomplete: GitHub API rate limit hit — set GITHUB_TOKEN to raise it")
	}
	return warnings
}

// parseReleaseURL recognises the GitHub release-tag links taglink writes:
// https://github.com/OWNER/REPO/releases/tag/TAG
func parseReleaseURL(raw string) (owner, repo, tag string) {
	if raw == "" {
		return "", "", ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() != "github.com" {
		return "", "", ""
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) < 5 || segs[2] != "releases" || segs[3] != "tag" {
		return "", "", ""
	}
	// Go submodule tags contain '/' and span the remaining segments.
	t, err := url.PathUnescape(strings.Join(segs[4:], "/"))
	if err != nil {
		return "", "", ""
	}
	return segs[0], segs[1], t
}

// fetchReleases lists a repository's most recent releases (one call).
func fetchReleases(owner, repo, token string) (rels []release, rateLimited bool, err error) {
	req, err := http.NewRequest("GET",
		fmt.Sprintf("%s/repos/%s/%s/releases?per_page=100", APIBase, url.PathEscape(owner), url.PathEscape(repo)), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "lockvet (+https://github.com/matteo-sung/lockvet)")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		if resp.Header.Get("X-RateLimit-Remaining") == "0" || resp.StatusCode == http.StatusTooManyRequests {
			return nil, true, fmt.Errorf("rate limited")
		}
		return nil, false, fmt.Errorf("forbidden")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
	if err != nil {
		return nil, false, err
	}
	if err := json.Unmarshal(body, &rels); err != nil {
		return nil, false, err
	}
	return rels, false, nil
}

// notesFor picks the releases a bump pulls in: the new version's release
// and, when old → new skips versions, everything in between (matched by
// sharing the new tag's naming prefix), newest first.
func notesFor(c *diffx.Change, newTag string, rels []release) []diffx.ReleaseNote {
	byTag := map[string]release{}
	for _, r := range rels {
		if !r.Draft {
			byTag[r.TagName] = r
		}
	}

	var picked []release
	seen := map[string]bool{}
	if r, ok := byTag[newTag]; ok {
		picked = append(picked, r)
		seen[newTag] = true
	}

	// Intermediates: only when the tag embeds the version verbatim
	// (v1.2.3, 1.2.3, pkg@1.2.3, pkg-v1.2.3, dir/v1.2.3 — all taglink
	// conventions end with the version) and the old side is a single
	// comparable version.
	if len(c.New) == 1 && len(c.Old) == 1 && strings.HasSuffix(newTag, c.New[0]) {
		prefix := strings.TrimSuffix(newTag, c.New[0])
		oldV, newV := c.Old[0], c.New[0]
		if vers.Compare(oldV, newV) < 0 { // upgrades only
			for tag, r := range byTag {
				if seen[tag] || !strings.HasPrefix(tag, prefix) {
					continue
				}
				v := tag[len(prefix):]
				if v == "" || v[0] < '0' || v[0] > '9' {
					continue
				}
				if vers.Compare(oldV, v) < 0 && vers.Compare(v, newV) < 0 {
					picked = append(picked, r)
					seen[tag] = true
				}
			}
		}
	}
	if len(picked) == 0 {
		return nil
	}

	// Newest first, by the version embedded in the tag when comparable.
	prefix := ""
	if len(c.New) == 1 && strings.HasSuffix(newTag, c.New[0]) {
		prefix = strings.TrimSuffix(newTag, c.New[0])
	}
	verOf := func(tag string) string { return strings.TrimPrefix(tag, prefix) }
	sort.SliceStable(picked, func(i, j int) bool {
		return vers.Compare(verOf(picked[i].TagName), verOf(picked[j].TagName)) > 0
	})
	if len(picked) > maxNotesPerChange {
		picked = picked[:maxNotesPerChange]
	}

	notes := make([]diffx.ReleaseNote, 0, len(picked))
	for _, r := range picked {
		title := strings.TrimSpace(r.Name)
		if title == r.TagName || "v"+title == r.TagName || title == "v"+r.TagName {
			title = "" // redundant
		}
		notes = append(notes, diffx.ReleaseNote{
			Tag:     r.TagName,
			Title:   sanitize(title),
			URL:     r.HTMLURL,
			Excerpt: Excerpt(r.Body),
		})
	}
	return notes
}

var (
	htmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)
	ansiSeq     = regexp.MustCompile(`\x1b(\[[0-9;?]*[a-zA-Z]|\][^\x07\x1b]*(\x07|\x1b\\)?)`)
)

// Excerpt trims a release body down to a short, terminal-safe extract.
func Excerpt(body string) string {
	s := strings.ReplaceAll(body, "\r\n", "\n")
	s = htmlComment.ReplaceAllString(s, "")
	s = sanitize(s)

	var lines []string
	blank := false
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimRight(ln, " \t")
		if strings.TrimSpace(ln) == "" {
			blank = len(lines) > 0
			continue
		}
		if blank {
			lines = append(lines, "")
			blank = false
		}
		lines = append(lines, ln)
	}

	truncated := false
	if len(lines) > maxExcerptLines {
		lines, truncated = lines[:maxExcerptLines], true
	}
	out := strings.Join(lines, "\n")
	if len(out) > maxExcerptChars {
		cut := out[:maxExcerptChars]
		if i := strings.LastIndexByte(cut, '\n'); i > maxExcerptChars/2 {
			cut = cut[:i]
		}
		out, truncated = strings.TrimRight(cut, " \t\n"), true
	}
	if truncated && out != "" {
		out += "\n…"
	}
	return out
}

// sanitize strips ANSI escape sequences and control characters that
// upstream release bodies must not be able to smuggle into terminal output.
func sanitize(s string) string {
	if strings.ContainsRune(s, 0x1b) {
		s = ansiSeq.ReplaceAllString(s, "")
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
