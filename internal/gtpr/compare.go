package gtpr

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/matteo-sung/lockvet/internal/ghpr"
)

// CmpRef identifies a comparison between two revisions of a repository on
// a Gitea/Forgejo host.
type CmpRef struct {
	Host  string // e.g. "codeberg.org"
	Owner string
	Repo  string
	Base  string
	Head  string
}

func (r CmpRef) String() string {
	return fmt.Sprintf("%s/%s/%s %s...%s", r.Host, r.Owner, r.Repo, r.Base, r.Head)
}

// https://HOST/OWNER/REPO/compare/BASE...HEAD — same shape as GitHub's, so
// github.com (and the other forges lockvet handles elsewhere) are excluded
// by foreignHost. GitLab compare URLs use /-/compare/ and never match.
var cmpURLRe = regexp.MustCompile(`^(?:https?://)?([A-Za-z0-9._-]+\.[A-Za-z0-9._-]+(?::\d+)?)/([^/\s]+)/([^/\s]+)/compare/(.+)$`)

// ParseCompare recognises a Gitea/Forgejo compare URL:
//
//	https://codeberg.org/OWNER/REPO/compare/BASE...HEAD
//
// BASE and HEAD may be branches (slashes ok), tags, or SHAs. A trailing
// .diff / .patch, ?query, or #fragment is ignored.
func ParseCompare(s string) (CmpRef, bool) {
	m := cmpURLRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil || foreignHost(m[1]) {
		return CmpRef{}, false
	}
	basehead := m[4]
	if i := strings.IndexAny(basehead, "?#"); i >= 0 {
		basehead = basehead[:i]
	}
	basehead = strings.TrimSuffix(strings.TrimSuffix(basehead, ".diff"), ".patch")
	base, head, ok := ghpr.SplitBasehead(basehead)
	if !ok {
		return CmpRef{}, false
	}
	return CmpRef{Host: m[1], Owner: m[2], Repo: m[3], Base: base, Head: head}, true
}

// FetchCompare downloads the file changes between two revisions via the
// Gitea compare API and returns the before/after contents of every changed
// file isLockfile accepts. The changed-file set is the union of the files
// touched by the commits on the head side (three-dot semantics, like a PR
// diff); contents are read at BASE and HEAD themselves, so each file's
// before/after is the direct diff of the two revisions.
func FetchCompare(ref CmpRef, isLockfile func(path string) bool) (*ghpr.Result, error) {
	return newClient(ref.Host).fetchCompare(ref, isLockfile)
}

func (c *client) fetchCompare(ref CmpRef, isLockfile func(path string) bool) (*ghpr.Result, error) {
	// Large compares take the server a while to assemble — the response
	// carries a file list for every commit in the range (Codeberg needs
	// ~30s for a 600-commit range) — so allow well over the default 30s.
	c.http = &http.Client{Timeout: 3 * time.Minute}

	rp := url.PathEscape(ref.Owner) + "/" + url.PathEscape(ref.Repo)

	var cmp struct {
		TotalCommits int `json:"total_commits"`
		Commits      []struct {
			Files []struct {
				Filename string `json:"filename"`
			} `json:"files"`
		} `json:"commits"`
	}
	if err := c.getJSON(fmt.Sprintf("repos/%s/compare/%s...%s",
		rp, ref.Base, ref.Head), &cmp); err != nil {
		if errors.Is(err, errNotFound) {
			return nil, fmt.Errorf("cannot compare %s: %w — do both revisions exist?", ref, err)
		}
		return nil, err
	}

	res := &ghpr.Result{
		BaseLabel: fmt.Sprintf("%s/%s@%s", ref.Owner, ref.Repo, ref.Base),
		HeadLabel: ref.Head,
	}
	if len(cmp.Commits) == 0 {
		// Identical revisions, or head is already contained in base.
		return res, nil
	}
	if cmp.TotalCommits > len(cmp.Commits) {
		fmt.Fprintf(os.Stderr, "lockvet: warning: %s: API returned %d of %d commits; results may be incomplete\n",
			ref, len(cmp.Commits), cmp.TotalCommits)
	}

	seen := make(map[string]bool)
	var paths []string
	for _, commit := range cmp.Commits {
		for _, f := range commit.Files {
			if !seen[f.Filename] && isLockfile(f.Filename) {
				seen[f.Filename] = true
				paths = append(paths, f.Filename)
			}
		}
	}
	sort.Strings(paths)

	for _, p := range paths {
		oldData, oldOK, err := c.rawFileMaybe(rp, ref.Base, p)
		if err != nil {
			return nil, fmt.Errorf("%s (base side): %w", p, err)
		}
		newData, newOK, err := c.rawFileMaybe(rp, ref.Head, p)
		if err != nil {
			return nil, fmt.Errorf("%s (head side): %w", p, err)
		}
		if !oldOK && !newOK {
			continue // added and removed again within the range
		}
		if oldOK && newOK && bytes.Equal(oldData, newData) {
			continue // touched by some commit, but identical at the endpoints
		}
		cf := ghpr.ChangedFile{Path: p}
		if oldOK {
			cf.Old = oldData
		}
		if newOK {
			cf.New = newData
		}
		res.Files = append(res.Files, cf)
	}
	return res, nil
}

// rawFileMaybe is rawFile, except a missing file (404) reports ok=false
// instead of an error — a lockfile may not exist on one side of a compare.
func (c *client) rawFileMaybe(rp, ref, path string) (data []byte, ok bool, err error) {
	data, err = c.rawFile(rp, ref, path)
	if errors.Is(err, errNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}
