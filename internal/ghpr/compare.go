package ghpr

import (
	"fmt"
	"regexp"
	"strings"
)

// CmpRef identifies a comparison between two revisions of a repository.
// Head may use GitHub's fork syntax ("user:branch" or "user:repo:branch").
type CmpRef struct {
	Owner string
	Repo  string
	Base  string
	Head  string
}

func (r CmpRef) String() string {
	return fmt.Sprintf("%s/%s %s...%s", r.Owner, r.Repo, r.Base, r.Head)
}

var (
	compareRe = regexp.MustCompile(`^(?:https?://)?(?:www\.)?github\.com/([^/\s]+)/([^/\s]+)/compare/(.+)$`)
	commitRe  = regexp.MustCompile(`^(?:https?://)?(?:www\.)?github\.com/([^/\s]+)/([^/\s]+)/commits?/([0-9a-fA-F]{7,40})(?:[/?#].*)?$`)
)

// ParseCompare recognises a GitHub compare URL:
//
//	https://github.com/OWNER/REPO/compare/BASE...HEAD
//
// BASE and HEAD may be branches (slashes ok), tags, or SHAs; HEAD may use
// fork syntax (user:branch). Trailing ?query or #fragment is ignored.
func ParseCompare(s string) (CmpRef, bool) {
	m := compareRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return CmpRef{}, false
	}
	basehead := m[3]
	if i := strings.IndexAny(basehead, "?#"); i >= 0 {
		basehead = basehead[:i]
	}
	base, head, ok := SplitBasehead(basehead)
	if !ok {
		return CmpRef{}, false
	}
	return CmpRef{Owner: m[1], Repo: m[2], Base: base, Head: head}, true
}

// ParseCommit recognises a GitHub commit URL:
//
//	https://github.com/OWNER/REPO/commit/SHA
func ParseCommit(s string) (owner, repo, sha string, ok bool) {
	m := commitRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}

// SplitBasehead splits "BASE...HEAD" (or "BASE..HEAD") into its two sides.
func SplitBasehead(s string) (base, head string, ok bool) {
	sep := "..."
	i := strings.Index(s, sep)
	if i < 0 {
		sep = ".."
		i = strings.Index(s, sep)
	}
	if i <= 0 || i+len(sep) >= len(s) {
		return "", "", false
	}
	return s[:i], s[i+len(sep):], true
}

// headRepoRef resolves GitHub fork syntax in a compare head.
// "branch" → (baseRepo, "branch"); "user:branch" → ("user/<repo>", "branch");
// "user:repo:branch" → ("user/repo", "branch").
func headRepoRef(ref CmpRef) (repo, rev string) {
	parts := strings.SplitN(ref.Head, ":", 3)
	switch len(parts) {
	case 2:
		return parts[0] + "/" + ref.Repo, parts[1]
	case 3:
		return parts[0] + "/" + parts[1], parts[2]
	default:
		return ref.Owner + "/" + ref.Repo, ref.Head
	}
}

// ResolveCommit turns OWNER/REPO + SHA into the CmpRef parent...sha, so a
// single commit can be vetted with FetchCompare.
func ResolveCommit(owner, repo, sha string) (CmpRef, error) {
	c := newClient()
	var commit struct {
		SHA     string `json:"sha"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
	}
	if err := c.getJSON(fmt.Sprintf("repos/%s/%s/commits/%s", owner, repo, sha), &commit); err != nil {
		return CmpRef{}, err
	}
	if len(commit.Parents) == 0 {
		return CmpRef{}, fmt.Errorf("commit %s has no parent (root commit) — nothing to compare against", sha)
	}
	// Parents[0] follows the usual git convention: for merge commits this
	// compares against the branch the merge landed on.
	return CmpRef{Owner: owner, Repo: repo, Base: commit.Parents[0].SHA, Head: commit.SHA}, nil
}

// FetchCompare downloads the file changes between two revisions via the
// GitHub compare API (three-dot semantics: changes are relative to the merge
// base, exactly like a PR diff) and returns the before/after contents of
// every changed file isLockfile accepts.
func FetchCompare(ref CmpRef, isLockfile func(path string) bool) (*Result, error) {
	c := newClient()

	baseRepo := ref.Owner + "/" + ref.Repo
	headRepo, headRev := headRepoRef(ref)

	var cmp struct {
		MergeBaseCommit struct {
			SHA string `json:"sha"`
		} `json:"merge_base_commit"`
		Files []struct {
			Filename         string `json:"filename"`
			Status           string `json:"status"`
			PreviousFilename string `json:"previous_filename"`
		} `json:"files"`
	}
	if err := c.getJSON(fmt.Sprintf("repos/%s/compare/%s...%s",
		baseRepo, ref.Base, ref.Head), &cmp); err != nil {
		return nil, err
	}
	if cmp.MergeBaseCommit.SHA == "" {
		return nil, fmt.Errorf("cannot compare %s: no merge base found", ref)
	}

	res := &Result{
		BaseLabel: fmt.Sprintf("%s@%s", baseRepo, ref.Base),
		HeadLabel: ref.Head,
	}
	if len(cmp.Files) == 300 {
		res.Warnings = append(res.Warnings,
			"the GitHub compare API lists at most 300 files — lockfiles beyond that are not seen")
	}
	for _, f := range cmp.Files {
		if !isLockfile(f.Filename) {
			continue
		}
		cf := ChangedFile{Path: f.Filename}
		oldPath := f.Filename
		if f.Status == "renamed" && f.PreviousFilename != "" {
			oldPath = f.PreviousFilename
		}
		if f.Status != "added" {
			data, err := c.rawContents(baseRepo, cmp.MergeBaseCommit.SHA, oldPath)
			if err != nil {
				return nil, fmt.Errorf("%s (base side): %w", f.Filename, err)
			}
			cf.Old = data
		}
		if f.Status != "removed" {
			data, err := c.rawContents(headRepo, headRev, f.Filename)
			if err != nil {
				return nil, fmt.Errorf("%s (head side): %w", f.Filename, err)
			}
			cf.New = data
		}
		res.Files = append(res.Files, cf)
	}
	return res, nil
}
