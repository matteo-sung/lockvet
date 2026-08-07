// Changelog-file fallback: many projects never publish GitHub Releases
// (Phoenix stopped at v1.5.3; most GitLab-, Codeberg- and Bitbucket-hosted
// projects never started) but keep a CHANGELOG.md at the repository root.
// When the release-list path yields nothing for a change, we fetch the
// repo's changelog file at the verified tag via the forge's raw endpoint
// and extract the sections covering (old, new] — same excerpting, same
// caps, same sanitizing as release bodies.
package relnotes

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/vers"
)

type clForge int

const (
	clNone clForge = iota
	clGitHub
	clGitLab
	clGitea
	clBitbucket
)

// changelogNames are tried in order; the first file that both exists and
// parses into version sections wins.
var changelogNames = []string{"CHANGELOG.md", "CHANGES.md", "NEWS.md", "HISTORY.md", "CHANGELOG"}

// RawGitHub is swappable for tests.
var RawGitHub = "https://raw.githubusercontent.com"

// parseTagURL recognises every tag-page shape taglink writes and returns
// the forge, the repository base URL and the verified tag.
//
//	github.com/O/R/releases/tag/TAG      (GitHub)
//	HOST/O/R/-/tags/TAG                  (GitLab, incl. subgroups)
//	HOST/O/R/releases/tag/TAG            (Gitea/Forgejo/Codeberg)
//	bitbucket.org/O/R/src/TAG            (Bitbucket)
func parseTagURL(raw string) (f clForge, repoURL, tag string) {
	if raw == "" {
		return clNone, "", ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return clNone, "", ""
	}
	host := u.Hostname()
	base := u.Scheme + "://" + u.Host
	path := strings.Trim(u.Path, "/")

	// GitLab's /-/ separator is unambiguous across hosts.
	if repo, rest, ok := cutSegs(path, "/-/tags/"); ok {
		return clGitLab, base + "/" + repo, unescape(rest)
	}
	segs := strings.Split(path, "/")
	if len(segs) >= 5 && segs[2] == "releases" && segs[3] == "tag" {
		f := clGitea
		if host == "github.com" {
			f = clGitHub
		}
		return f, base + "/" + segs[0] + "/" + segs[1], unescape(strings.Join(segs[4:], "/"))
	}
	if host == "bitbucket.org" && len(segs) >= 4 && segs[2] == "src" {
		return clBitbucket, base + "/" + segs[0] + "/" + segs[1], unescape(strings.Join(segs[3:], "/"))
	}
	return clNone, "", ""
}

func cutSegs(path, sep string) (before, after string, ok bool) {
	i := strings.Index(path, sep)
	if i < 0 {
		return "", "", false
	}
	return path[:i], path[i+len(sep):], true
}

func unescape(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// rawFileURL builds the forge's raw-content URL for a file at a ref.
func rawFileURL(f clForge, repoURL, ref, name string) string {
	switch f {
	case clGitHub:
		u, err := url.Parse(repoURL)
		if err != nil {
			return ""
		}
		return RawGitHub + u.Path + "/" + escapeRef(ref) + "/" + name
	case clGitLab:
		return repoURL + "/-/raw/" + escapeRef(ref) + "/" + name
	case clGitea:
		return repoURL + "/raw/tag/" + escapeRef(ref) + "/" + name
	case clBitbucket:
		return repoURL + "/raw/" + escapeRef(ref) + "/" + name
	}
	return ""
}

// blobFileURL builds the human page for the same file (used as the note URL).
func blobFileURL(f clForge, repoURL, ref, name string) string {
	switch f {
	case clGitHub:
		return repoURL + "/blob/" + escapeRef(ref) + "/" + name
	case clGitLab:
		return repoURL + "/-/blob/" + escapeRef(ref) + "/" + name
	case clGitea:
		return repoURL + "/src/tag/" + escapeRef(ref) + "/" + name
	case clBitbucket:
		return repoURL + "/src/" + escapeRef(ref) + "/" + name
	}
	return ""
}

var escapeRef = strings.NewReplacer(
	"%", "%25", "#", "%23", "?", "%3F", " ", "%20", "\"", "%22",
).Replace

// clSection is one version's slice of a changelog file.
type clSection struct {
	version string // normalized: no leading v/V
	display string // the version token as written (keeps its v)
	title   string // heading remainder (usually the date)
	body    string
}

// fetchChangelog tries the well-known changelog filenames at a ref and
// returns the parsed sections of the first one that yields any.
func fetchChangelog(f clForge, repoURL, ref string, prefixes []string) (secs []clSection, fileURL string) {
	for _, name := range changelogNames {
		raw := rawFileURL(f, repoURL, ref, name)
		if raw == "" {
			return nil, ""
		}
		body, err := fetchRaw(raw)
		if err != nil || len(body) == 0 {
			continue
		}
		if secs = parseChangelog(string(body), prefixes); len(secs) > 0 {
			return secs, blobFileURL(f, repoURL, ref, name)
		}
	}
	return nil, ""
}

func fetchRaw(rawURL string) ([]byte, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "lockvet (+https://github.com/matteo-sung/lockvet)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 4<<20))
}

// verToken matches a dotted version with optional pre-release/build suffix.
var verToken = regexp.MustCompile(`^[vV]?(\d+\.\d+(?:\.\d+)*(?:(?:a|b|c|rc|alpha|beta|post|dev)[0-9]+)?(?:[.+~_-][0-9A-Za-z.+~_-]*)?)`)

// linkRef matches markdown link-reference lines ([1.2.3]: https://…).
var linkRef = regexp.MustCompile(`^\[[^\]]+\]:\s+\S+$`)

// parseChangelog splits a changelog file into per-version sections.
// A version heading is either an ATX heading (#…###### text) or a setext
// heading (text underlined with === / ---) whose text starts — after an
// optional "[", an optional "version"/"release" word or one of the extra
// allowed prefixes (the repo/package name) — with a version number.
func parseChangelog(text string, prefixes []string) []clSection {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	type mark struct {
		idx     int
		display string
		version string
		title   string
	}
	var marks []mark
	for i := 0; i < len(lines); i++ {
		var text string
		bodyAt := i + 1
		if t, ok := atxHeading(lines[i]); ok {
			text = t
		} else if i+1 < len(lines) && isUnderline(lines[i+1]) && strings.TrimSpace(lines[i]) != "" {
			text, bodyAt = strings.TrimSpace(lines[i]), i+2
		} else {
			continue
		}
		display, version, title, ok := versionHeading(text, prefixes)
		if !ok {
			continue
		}
		marks = append(marks, mark{idx: i, display: display, version: version, title: title})
		i = bodyAt - 1
	}
	if len(marks) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var secs []clSection
	for k, m := range marks {
		if seen[m.version] {
			continue
		}
		seen[m.version] = true
		start := m.idx + 1
		if start < len(lines) && isUnderline(lines[start]) {
			start++
		}
		end := len(lines)
		if k+1 < len(marks) {
			end = marks[k+1].idx
		}
		var body []string
		for _, ln := range lines[start:end] {
			if linkRef.MatchString(strings.TrimSpace(ln)) {
				continue
			}
			body = append(body, ln)
		}
		secs = append(secs, clSection{
			version: m.version,
			display: m.display,
			title:   m.title,
			body:    strings.Join(body, "\n"),
		})
	}
	return secs
}

func atxHeading(line string) (text string, ok bool) {
	s := strings.TrimSpace(line)
	n := 0
	for n < len(s) && s[n] == '#' {
		n++
	}
	if n == 0 || n > 6 || n == len(s) || (s[n] != ' ' && s[n] != '\t') {
		return "", false
	}
	return strings.TrimSpace(strings.TrimRight(strings.TrimSpace(s[n:]), "#")), true
}

func isUnderline(line string) bool {
	s := strings.TrimSpace(line)
	if len(s) < 3 {
		return false
	}
	c := s[0]
	if c != '=' && c != '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != c {
			return false
		}
	}
	return true
}

// versionHeading decides whether a heading names a version and splits it.
func versionHeading(text string, prefixes []string) (display, version, title string, ok bool) {
	s := strings.TrimSpace(text)
	s = strings.TrimPrefix(s, "[")
	// Optional single leading word: "Version", "Release" or the
	// repo/package name ("Rails 7.1.2").
	if i := strings.IndexAny(s, " \t"); i > 0 && !strings.ContainsAny(s[:i], "0123456789") {
		w := strings.ToLower(strings.Trim(s[:i], ":"))
		allowed := w == "version" || w == "release"
		for _, p := range prefixes {
			if !allowed && p != "" && w == strings.ToLower(p) {
				allowed = true
			}
		}
		if allowed {
			s = strings.TrimSpace(s[i:])
			s = strings.TrimPrefix(s, "[")
		}
	}
	m := verToken.FindString(s)
	if m == "" {
		return "", "", "", false
	}
	rest := s[len(m):]
	// The token must end the "name part" of the heading: what follows may
	// only be a bracket close, separator or parenthesised remainder.
	if rest != "" && !strings.ContainsAny(rest[:1], "]) (-–—:,\t") {
		return "", "", "", false
	}
	title = strings.TrimLeft(rest, "]) (-–—:,\t")
	title = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(title), ")"))
	return m, strings.TrimLeft(m, "vV"), title, true
}

// annotateFromChangelog fills ReleaseNotes on the changes of one repository
// that the release-list path left empty. Only single-package tag conventions
// (1.2.3 / v1.2.3) qualify: a monorepo's root changelog describes one
// package, and matching another package's version against it would attach
// the wrong notes. One file fetch per repository, at the newest tag among
// the pending changes (older sections are still present there).
func annotateFromChangelog(f clForge, repoURL string, changes []*diffx.Change, tags []string) {
	if f == clNone || repoURL == "" {
		return
	}
	var (
		pending  []int
		ref      string
		bestVer  string
		headOnly = true
		names    = map[string]bool{}
	)
	for k, c := range changes {
		if len(c.ReleaseNotes) > 0 || len(c.New) != 1 || c.Kind == diffx.Removed {
			continue
		}
		ver := c.New[0]
		if tag := tags[k]; tag != "" {
			if tag != ver && tag != "v"+ver && "v"+tag != ver {
				continue // monorepo-style tag (pkg@1.2.3, pkg-v1.2.3, dir/v1.2.3)
			}
			headOnly = false
			v := strings.TrimLeft(tag, "vV")
			if ref == "" || vers.Compare(v, bestVer) > 0 {
				ref, bestVer = tag, v
			}
		} else if !(Fallback && f == clGitHub) {
			continue // no verified tag to fetch at
		}
		pending = append(pending, k)
		names[c.Name] = true
	}
	if len(pending) == 0 {
		return
	}
	if ref == "" {
		// Fallback (browser) path without a verified tag: read the file at
		// HEAD, but only when the repo maps to a single package — without a
		// tag convention to inspect we can't rule out a monorepo otherwise.
		if headOnly && len(names) > 1 {
			return
		}
		ref = "HEAD"
	}
	prefixes := []string{lastSeg(repoURL)}
	for name := range names {
		prefixes = append(prefixes, lastSeg(name))
	}
	secs, fileURL := fetchChangelog(f, repoURL, ref, prefixes)
	if len(secs) == 0 {
		return
	}
	for _, k := range pending {
		changes[k].ReleaseNotes = clNotesFor(changes[k], secs, fileURL)
	}
}

func lastSeg(s string) string {
	if i := strings.LastIndexByte(strings.TrimRight(s, "/"), '/'); i >= 0 {
		return strings.TrimRight(s, "/")[i+1:]
	}
	return s
}

// clNotesFor builds release notes for one change from parsed sections:
// the new version's section plus intermediates in (old, new), newest first.
func clNotesFor(c *diffx.Change, secs []clSection, fileURL string) []diffx.ReleaseNote {
	if len(c.New) != 1 {
		return nil
	}
	newV := strings.TrimLeft(c.New[0], "vV")
	byVer := map[string]clSection{}
	for _, s := range secs {
		if _, dup := byVer[s.version]; !dup {
			byVer[s.version] = s
		}
	}
	newSec, ok := byVer[newV]
	if !ok {
		return nil // never guess: no section for the version we pulled in
	}
	picked := []clSection{newSec}
	if len(c.Old) == 1 {
		oldV := strings.TrimLeft(c.Old[0], "vV")
		if vers.Compare(oldV, newV) < 0 {
			for v, s := range byVer {
				if v != newV && vers.Compare(oldV, v) < 0 && vers.Compare(v, newV) < 0 {
					picked = append(picked, s)
				}
			}
		}
	}
	sort.SliceStable(picked, func(i, j int) bool {
		return vers.Compare(picked[i].version, picked[j].version) > 0
	})
	if len(picked) > maxNotesPerChange {
		picked = picked[:maxNotesPerChange]
	}
	notes := make([]diffx.ReleaseNote, 0, len(picked))
	for _, s := range picked {
		excerpt := Excerpt(s.body)
		if excerpt == "" {
			continue
		}
		notes = append(notes, diffx.ReleaseNote{
			Tag:     s.display,
			Title:   sanitize(s.title),
			URL:     fileURL,
			Excerpt: excerpt,
		})
	}
	return notes
}
