// Package glmr fetches the lockfile changes of a GitLab merge request (or
// comparison / commit) via the REST API, so it can be vetted without cloning
// the repository. Works with gitlab.com and self-hosted instances.
package glmr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/matteo-sung/lockvet/internal/ghpr"
)

// Ref identifies a merge request.
type Ref struct {
	Host    string // e.g. "gitlab.com"
	Project string // full path, subgroups included: "group/sub/project"
	IID     int
}

func (r Ref) String() string {
	if r.Host == "" || r.Host == "gitlab.com" {
		return fmt.Sprintf("%s!%d", r.Project, r.IID)
	}
	return fmt.Sprintf("%s/%s!%d", r.Host, r.Project, r.IID)
}

// CmpRef identifies a comparison between two revisions of a GitLab project.
type CmpRef struct {
	Host    string
	Project string
	Base    string
	Head    string
}

func (r CmpRef) String() string {
	p := r.Project
	if r.Host != "" && r.Host != "gitlab.com" {
		p = r.Host + "/" + r.Project
	}
	return fmt.Sprintf("%s %s...%s", p, r.Base, r.Head)
}

var (
	// https://HOST/GROUP[/SUBGROUP...]/PROJECT/-/merge_requests/123
	mrURLRe = regexp.MustCompile(`^(?:https?://)?([A-Za-z0-9._-]+(?::\d+)?)/((?:[^/\s]+/)+[^/\s]+)/-/merge_requests/(\d+)(?:[/?#].*)?$`)
	// group/project!123 (subgroups ok) — gitlab.com assumed
	mrShortRe = regexp.MustCompile(`^((?:[A-Za-z0-9._-]+/)+[A-Za-z0-9._-]+)!(\d+)$`)
	// https://HOST/PATH/-/compare/BASE...HEAD
	cmpURLRe = regexp.MustCompile(`^(?:https?://)?([A-Za-z0-9._-]+(?::\d+)?)/((?:[^/\s]+/)+[^/\s]+)/-/compare/(.+)$`)
	// https://HOST/PATH/-/commit/SHA
	commitURLRe = regexp.MustCompile(`^(?:https?://)?([A-Za-z0-9._-]+(?::\d+)?)/((?:[^/\s]+/)+[^/\s]+)/-/commit/([0-9a-fA-F]{7,40})(?:[/?#].*)?$`)
)

// ParseMR recognises a merge request reference in either form:
//
//	https://gitlab.com/GROUP/PROJECT/-/merge_requests/123  (any host)
//	GROUP/PROJECT!123                                      (gitlab.com)
func ParseMR(s string) (Ref, bool) {
	s = strings.TrimSpace(s)
	if m := mrURLRe.FindStringSubmatch(s); m != nil {
		n, err := strconv.Atoi(m[3])
		if err != nil || n <= 0 {
			return Ref{}, false
		}
		return Ref{Host: m[1], Project: strings.TrimSuffix(m[2], "/"), IID: n}, true
	}
	if m := mrShortRe.FindStringSubmatch(s); m != nil {
		n, err := strconv.Atoi(m[2])
		if err != nil || n <= 0 {
			return Ref{}, false
		}
		return Ref{Host: "gitlab.com", Project: m[1], IID: n}, true
	}
	return Ref{}, false
}

// ParseCompare recognises a GitLab compare URL:
//
//	https://gitlab.com/GROUP/PROJECT/-/compare/BASE...HEAD
func ParseCompare(s string) (CmpRef, bool) {
	m := cmpURLRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return CmpRef{}, false
	}
	basehead := m[3]
	if i := strings.IndexAny(basehead, "?#"); i >= 0 {
		basehead = basehead[:i]
	}
	base, head, ok := ghpr.SplitBasehead(basehead)
	if !ok {
		return CmpRef{}, false
	}
	// compare URLs are percent-encoded (slashes in branch names etc.)
	if b, err := url.PathUnescape(base); err == nil {
		base = b
	}
	if h, err := url.PathUnescape(head); err == nil {
		head = h
	}
	return CmpRef{Host: m[1], Project: strings.TrimSuffix(m[2], "/"), Base: base, Head: head}, true
}

// ParseCommit recognises a GitLab commit URL:
//
//	https://gitlab.com/GROUP/PROJECT/-/commit/SHA
func ParseCommit(s string) (host, project, sha string, ok bool) {
	m := commitURLRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", "", "", false
	}
	return m[1], strings.TrimSuffix(m[2], "/"), m[3], true
}

type client struct {
	http     *http.Client
	base     string // e.g. "https://gitlab.com/api/v4/"
	token    string // personal / project access token → PRIVATE-TOKEN
	jobToken string // GitLab CI job token → JOB-TOKEN
}

func newClient(host string) *client {
	if host == "" {
		host = "gitlab.com"
	}
	return &client{
		http:     &http.Client{Timeout: 30 * time.Second},
		base:     "https://" + host + "/api/v4/",
		token:    firstEnv("GITLAB_TOKEN", "GL_TOKEN"),
		jobToken: os.Getenv("CI_JOB_TOKEN"),
	}
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

// Fetch downloads the MR metadata and the before/after contents of every
// changed file isLockfile accepts. Both sides are read from the target
// project: GitLab keeps MR head commits reachable there even for fork MRs.
// Authenticates with GITLAB_TOKEN / GL_TOKEN (or CI_JOB_TOKEN inside GitLab
// CI) when set; works unauthenticated on public projects.
func Fetch(ref Ref, isLockfile func(path string) bool) (*ghpr.Result, error) {
	c := newClient(ref.Host)
	proj := url.PathEscape(ref.Project)

	// 1. MR metadata: title, branches, and diff_refs (base_sha is the
	// merge base — the diff list is relative to it).
	var mr struct {
		Title        string `json:"title"`
		SourceBranch string `json:"source_branch"`
		TargetBranch string `json:"target_branch"`
		DiffRefs     struct {
			BaseSHA string `json:"base_sha"`
			HeadSHA string `json:"head_sha"`
		} `json:"diff_refs"`
	}
	if err := c.getJSON(fmt.Sprintf("projects/%s/merge_requests/%d", proj, ref.IID), &mr); err != nil {
		return nil, err
	}
	if mr.DiffRefs.HeadSHA == "" {
		return nil, fmt.Errorf("%s: MR has no diff yet", ref)
	}

	// 2. Changed files (paginated).
	type mrDiff struct {
		OldPath     string `json:"old_path"`
		NewPath     string `json:"new_path"`
		NewFile     bool   `json:"new_file"`
		RenamedFile bool   `json:"renamed_file"`
		DeletedFile bool   `json:"deleted_file"`
	}
	var matched []mrDiff
	for page := 1; page <= 30; page++ {
		var diffs []mrDiff
		if err := c.getJSON(fmt.Sprintf("projects/%s/merge_requests/%d/diffs?per_page=100&page=%d",
			proj, ref.IID, page), &diffs); err != nil {
			return nil, err
		}
		for _, d := range diffs {
			if isLockfile(d.NewPath) || (d.DeletedFile && isLockfile(d.OldPath)) {
				matched = append(matched, d)
			}
		}
		if len(diffs) < 100 {
			break
		}
	}

	// 3. Contents on both sides.
	res := &ghpr.Result{
		BaseLabel: fmt.Sprintf("%s@%s", ref.Project, mr.TargetBranch),
		HeadLabel: fmt.Sprintf("MR !%d (%s)", ref.IID, mr.SourceBranch),
		Title:     mr.Title,
	}
	for _, d := range matched {
		cf := ghpr.ChangedFile{Path: d.NewPath}
		if d.DeletedFile {
			cf.Path = d.OldPath
		}
		if !d.NewFile {
			data, err := c.rawFile(proj, mr.DiffRefs.BaseSHA, d.OldPath)
			if err != nil {
				return nil, fmt.Errorf("%s (base side): %w", d.OldPath, err)
			}
			cf.Old = data
		}
		if !d.DeletedFile {
			data, err := c.rawFile(proj, mr.DiffRefs.HeadSHA, d.NewPath)
			if err != nil {
				return nil, fmt.Errorf("%s (MR side): %w", d.NewPath, err)
			}
			cf.New = data
		}
		res.Files = append(res.Files, cf)
	}
	return res, nil
}

// ResolveCommit turns HOST/PROJECT + SHA into the CmpRef parent...sha, so a
// single commit can be vetted with FetchCompare.
func ResolveCommit(host, project, sha string) (CmpRef, error) {
	c := newClient(host)
	var commit struct {
		ID        string   `json:"id"`
		ParentIDs []string `json:"parent_ids"`
	}
	if err := c.getJSON(fmt.Sprintf("projects/%s/repository/commits/%s",
		url.PathEscape(project), url.PathEscape(sha)), &commit); err != nil {
		return CmpRef{}, err
	}
	if len(commit.ParentIDs) == 0 {
		return CmpRef{}, fmt.Errorf("commit %s has no parent (root commit) — nothing to compare against", sha)
	}
	// ParentIDs[0] follows the usual git convention: for merge commits this
	// compares against the branch the merge landed on.
	return CmpRef{Host: host, Project: project, Base: commit.ParentIDs[0], Head: commit.ID}, nil
}

// FetchCompare downloads the file changes between two revisions via the
// GitLab compare API (merge-base semantics by default, like an MR diff) and
// returns the before/after contents of every changed file isLockfile accepts.
func FetchCompare(ref CmpRef, isLockfile func(path string) bool) (*ghpr.Result, error) {
	c := newClient(ref.Host)
	proj := url.PathEscape(ref.Project)

	var cmp struct {
		Diffs []struct {
			OldPath     string `json:"old_path"`
			NewPath     string `json:"new_path"`
			NewFile     bool   `json:"new_file"`
			RenamedFile bool   `json:"renamed_file"`
			DeletedFile bool   `json:"deleted_file"`
		} `json:"diffs"`
	}
	if err := c.getJSON(fmt.Sprintf("projects/%s/repository/compare?from=%s&to=%s",
		proj, url.QueryEscape(ref.Base), url.QueryEscape(ref.Head)), &cmp); err != nil {
		return nil, err
	}

	// The diff list is relative to the merge base of from/to.
	baseSHA := ref.Base
	var mb struct {
		ID string `json:"id"`
	}
	if err := c.getJSON(fmt.Sprintf("projects/%s/repository/merge_base?refs[]=%s&refs[]=%s",
		proj, url.QueryEscape(ref.Base), url.QueryEscape(ref.Head)), &mb); err == nil && mb.ID != "" {
		baseSHA = mb.ID
	}

	res := &ghpr.Result{
		BaseLabel: fmt.Sprintf("%s@%s", ref.Project, ref.Base),
		HeadLabel: ref.Head,
	}
	for _, d := range cmp.Diffs {
		if !(isLockfile(d.NewPath) || (d.DeletedFile && isLockfile(d.OldPath))) {
			continue
		}
		cf := ghpr.ChangedFile{Path: d.NewPath}
		if d.DeletedFile {
			cf.Path = d.OldPath
		}
		if !d.NewFile {
			data, err := c.rawFile(proj, baseSHA, d.OldPath)
			if err != nil {
				return nil, fmt.Errorf("%s (base side): %w", d.OldPath, err)
			}
			cf.Old = data
		}
		if !d.DeletedFile {
			data, err := c.rawFile(proj, ref.Head, d.NewPath)
			if err != nil {
				return nil, fmt.Errorf("%s (head side): %w", d.NewPath, err)
			}
			cf.New = data
		}
		res.Files = append(res.Files, cf)
	}
	return res, nil
}

func (c *client) do(path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", c.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "lockvet (+https://github.com/matteo-sung/lockvet)")
	switch {
	case c.token != "":
		req.Header.Set("PRIVATE-TOKEN", c.token)
	case c.jobToken != "":
		req.Header.Set("JOB-TOKEN", c.jobToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp, nil
	case http.StatusNotFound, http.StatusUnauthorized:
		resp.Body.Close()
		hint := ""
		if c.token == "" && c.jobToken == "" {
			hint = " — private project? set GITLAB_TOKEN"
		}
		return nil, fmt.Errorf("GitLab API: %s: %s%s", resp.Status, path, hint)
	case http.StatusForbidden, http.StatusTooManyRequests:
		resp.Body.Close()
		hint := "rate limited?"
		if c.token == "" && c.jobToken == "" {
			hint = "rate limited — set GITLAB_TOKEN to raise the limit"
		}
		return nil, fmt.Errorf("GitLab API: %s: %s (%s)", resp.Status, path, hint)
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("GitLab API: %s: %s", resp.Status, path)
	}
}

func (c *client) getJSON(path string, v any) error {
	resp, err := c.do(path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
}

// rawFile fetches a file's raw bytes at a specific ref. proj must already be
// path-escaped.
func (c *client) rawFile(proj, ref, path string) ([]byte, error) {
	p := fmt.Sprintf("projects/%s/repository/files/%s/raw?ref=%s",
		proj, url.PathEscape(path), url.QueryEscape(ref))
	resp, err := c.do(p)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}
