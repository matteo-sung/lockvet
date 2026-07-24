// Package gtpr fetches the lockfile changes of a Gitea / Forgejo pull
// request (or a single commit) via the REST API, so it can be vetted
// without cloning the repository. Works with codeberg.org, gitea.com, and
// any self-hosted Gitea or Forgejo instance — the host comes from the URL.
package gtpr

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

// Ref identifies a pull request on a Gitea/Forgejo host.
type Ref struct {
	Host  string // e.g. "codeberg.org"
	Owner string
	Repo  string
	Index int
}

func (r Ref) String() string {
	return fmt.Sprintf("%s/%s/%s#%d", r.Host, r.Owner, r.Repo, r.Index)
}

// CommitRef identifies a single commit on a Gitea/Forgejo host.
type CommitRef struct {
	Host  string
	Owner string
	Repo  string
	SHA   string
}

func (r CommitRef) String() string {
	sha := r.SHA
	if len(sha) > 12 {
		sha = sha[:12]
	}
	return fmt.Sprintf("%s/%s/%s@%s", r.Host, r.Owner, r.Repo, sha)
}

var (
	// https://HOST/OWNER/REPO/pulls/123 — Gitea/Forgejo use plural "pulls"
	// (GitHub uses singular /pull/, GitLab /-/merge_requests/, Bitbucket
	// /pull-requests/), so the path shape alone identifies the forge.
	prURLRe = regexp.MustCompile(`^(?:https?://)?([A-Za-z0-9._-]+\.[A-Za-z0-9._-]+(?::\d+)?)/([^/\s]+)/([^/\s]+)/pulls/(\d+)(?:[/?#].*)?$`)
	// https://HOST/OWNER/REPO/commit/SHA
	commitURLRe = regexp.MustCompile(`^(?:https?://)?([A-Za-z0-9._-]+\.[A-Za-z0-9._-]+(?::\d+)?)/([^/\s]+)/([^/\s]+)/commit/([0-9a-fA-F]{7,40})(?:[/?#].*)?$`)
)

// foreignHost reports hosts that use the same URL shapes but belong to
// other forges lockvet already handles elsewhere.
func foreignHost(host string) bool {
	h := strings.ToLower(strings.TrimPrefix(host, "www."))
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	switch h {
	case "github.com", "gitlab.com", "bitbucket.org":
		return true
	}
	return false
}

// Parse recognises a Gitea/Forgejo pull request URL:
//
//	https://codeberg.org/OWNER/REPO/pulls/123   (any Gitea/Forgejo host)
func Parse(s string) (Ref, bool) {
	m := prURLRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil || foreignHost(m[1]) {
		return Ref{}, false
	}
	n, err := strconv.Atoi(m[4])
	if err != nil || n <= 0 {
		return Ref{}, false
	}
	return Ref{Host: m[1], Owner: m[2], Repo: m[3], Index: n}, true
}

// ParseCommit recognises a Gitea/Forgejo commit URL:
//
//	https://codeberg.org/OWNER/REPO/commit/SHA
//
// github.com is excluded (handled by the GitHub path), as are gitlab.com
// and bitbucket.org, whose commit URLs use different shapes anyway.
func ParseCommit(s string) (CommitRef, bool) {
	m := commitURLRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil || foreignHost(m[1]) {
		return CommitRef{}, false
	}
	return CommitRef{Host: m[1], Owner: m[2], Repo: m[3], SHA: m[4]}, true
}

type client struct {
	http  *http.Client
	base  string // e.g. "https://codeberg.org/api/v1/"
	token string
}

func newClient(host string) *client {
	return &client{
		http:  &http.Client{Timeout: 30 * time.Second},
		base:  "https://" + host + "/api/v1/",
		token: firstEnv("GITEA_TOKEN", "FORGEJO_TOKEN", "CODEBERG_TOKEN"),
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

// Fetch downloads the PR metadata and the before/after contents of every
// changed file isLockfile accepts. Both sides are read from the base
// repository: Gitea keeps PR head commits reachable there even for fork
// PRs. Authenticates with GITEA_TOKEN / FORGEJO_TOKEN / CODEBERG_TOKEN
// when set; works unauthenticated on public repositories.
func Fetch(ref Ref, isLockfile func(path string) bool) (*ghpr.Result, error) {
	return newClient(ref.Host).fetch(ref, isLockfile)
}

func (c *client) fetch(ref Ref, isLockfile func(path string) bool) (*ghpr.Result, error) {
	rp := url.PathEscape(ref.Owner) + "/" + url.PathEscape(ref.Repo)

	// 1. PR metadata: title, branches, head SHA, and the merge base the
	// PR diff is relative to.
	var pr struct {
		Title     string `json:"title"`
		MergeBase string `json:"merge_base"`
		Head      struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	}
	if err := c.getJSON(fmt.Sprintf("repos/%s/pulls/%d", rp, ref.Index), &pr); err != nil {
		return nil, err
	}
	if pr.Head.SHA == "" || pr.MergeBase == "" {
		return nil, fmt.Errorf("%s: PR has no diff yet", ref)
	}

	// 2. Changed files (paginated).
	type prFile struct {
		Filename         string `json:"filename"`
		PreviousFilename string `json:"previous_filename"`
		Status           string `json:"status"`
	}
	var matched []prFile
	for page := 1; page <= 30; page++ {
		var fs []prFile
		if err := c.getJSON(fmt.Sprintf("repos/%s/pulls/%d/files?limit=50&page=%d",
			rp, ref.Index, page), &fs); err != nil {
			return nil, err
		}
		for _, f := range fs {
			old := f.Filename
			if f.PreviousFilename != "" {
				old = f.PreviousFilename
			}
			if isLockfile(f.Filename) || (deleted(f.Status) && isLockfile(old)) {
				matched = append(matched, f)
			}
		}
		if len(fs) < 50 {
			break
		}
	}

	// 3. Contents on both sides.
	res := &ghpr.Result{
		BaseLabel: fmt.Sprintf("%s/%s@%s", ref.Owner, ref.Repo, pr.Base.Ref),
		HeadLabel: fmt.Sprintf("PR #%d (%s)", ref.Index, pr.Head.Ref),
		Title:     pr.Title,
	}
	for _, f := range matched {
		cf := ghpr.ChangedFile{Path: f.Filename}
		oldPath := f.Filename
		if f.PreviousFilename != "" {
			oldPath = f.PreviousFilename
		}
		if f.Status != "added" {
			data, err := c.rawFile(rp, pr.MergeBase, oldPath)
			if err != nil {
				return nil, fmt.Errorf("%s (base side): %w", oldPath, err)
			}
			cf.Old = data
		}
		if !deleted(f.Status) {
			data, err := c.rawFile(rp, pr.Head.SHA, f.Filename)
			if err != nil {
				return nil, fmt.Errorf("%s (PR side): %w", f.Filename, err)
			}
			cf.New = data
		}
		res.Files = append(res.Files, cf)
	}
	return res, nil
}

func deleted(status string) bool { return status == "deleted" || status == "removed" }

// FetchCommit downloads the file changes a single commit makes relative to
// its first parent, and returns the before/after contents of every changed
// file isLockfile accepts.
func FetchCommit(ref CommitRef, isLockfile func(path string) bool) (*ghpr.Result, error) {
	return newClient(ref.Host).fetchCommit(ref, isLockfile)
}

func (c *client) fetchCommit(ref CommitRef, isLockfile func(path string) bool) (*ghpr.Result, error) {
	rp := url.PathEscape(ref.Owner) + "/" + url.PathEscape(ref.Repo)

	var commit struct {
		SHA     string `json:"sha"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
		Files []struct {
			Filename string `json:"filename"`
			Status   string `json:"status"`
		} `json:"files"`
	}
	if err := c.getJSON(fmt.Sprintf("repos/%s/git/commits/%s?stat=false&verification=false",
		rp, url.PathEscape(ref.SHA)), &commit); err != nil {
		return nil, err
	}
	if len(commit.Parents) == 0 {
		return nil, fmt.Errorf("commit %s has no parent (root commit) — nothing to compare against", ref.SHA)
	}
	// Parents[0] follows the usual git convention: for merge commits this
	// compares against the branch the merge landed on.
	parent := commit.Parents[0].SHA

	short := func(s string) string {
		if len(s) > 12 {
			return s[:12]
		}
		return s
	}
	res := &ghpr.Result{
		BaseLabel: fmt.Sprintf("%s/%s@%s", ref.Owner, ref.Repo, short(parent)),
		HeadLabel: short(commit.SHA),
	}
	for _, f := range commit.Files {
		if !isLockfile(f.Filename) {
			continue
		}
		cf := ghpr.ChangedFile{Path: f.Filename}
		if f.Status != "added" {
			data, err := c.rawFile(rp, parent, f.Filename)
			if err != nil {
				return nil, fmt.Errorf("%s (parent side): %w", f.Filename, err)
			}
			cf.Old = data
		}
		if !deleted(f.Status) {
			data, err := c.rawFile(rp, commit.SHA, f.Filename)
			if err != nil {
				return nil, fmt.Errorf("%s (commit side): %w", f.Filename, err)
			}
			cf.New = data
		}
		res.Files = append(res.Files, cf)
	}
	return res, nil
}

func (c *client) doReq(method, path string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = strings.NewReader(string(body))
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("User-Agent", "lockvet (+https://github.com/matteo-sung/lockvet)")
	if c.token != "" {
		req.Header.Set("Authorization", "token "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return resp, nil
	case http.StatusNotFound, http.StatusUnauthorized:
		resp.Body.Close()
		hint := ""
		if c.token == "" {
			hint = " — private repository? set GITEA_TOKEN (or CODEBERG_TOKEN)"
		}
		return nil, fmt.Errorf("Gitea API: %s: %s%s", resp.Status, path, hint)
	case http.StatusForbidden, http.StatusTooManyRequests:
		resp.Body.Close()
		hint := "rate limited?"
		if c.token == "" {
			hint = "rate limited — set GITEA_TOKEN (or CODEBERG_TOKEN) to raise the limit"
		}
		return nil, fmt.Errorf("Gitea API: %s: %s (%s)", resp.Status, path, hint)
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("Gitea API: %s: %s", resp.Status, path)
	}
}

func (c *client) getJSON(path string, v any) error {
	resp, err := c.doReq("GET", path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
}

// sendJSON issues a mutating request with a JSON body and decodes the reply.
func (c *client) sendJSON(method, path string, body []byte, v any) error {
	resp, err := c.doReq(method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if v == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
}

// rawFile fetches a file's raw bytes at a specific ref. rp must already be
// path-escaped. Path segments are escaped individually — Gitea's raw
// endpoint takes the path as URL segments, not a single encoded parameter.
func (c *client) rawFile(rp, ref, path string) ([]byte, error) {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	p := fmt.Sprintf("repos/%s/raw/%s?ref=%s", rp, strings.Join(segs, "/"), url.QueryEscape(ref))
	resp, err := c.doReq("GET", p, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}
