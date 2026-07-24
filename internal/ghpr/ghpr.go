// Package ghpr fetches the lockfile changes of a GitHub pull request via
// the REST API, so a PR can be vetted without cloning the repository.
package ghpr

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Ref identifies a pull request.
type Ref struct {
	Owner  string
	Repo   string
	Number int
}

func (r Ref) String() string { return fmt.Sprintf("%s/%s#%d", r.Owner, r.Repo, r.Number) }

var (
	urlRe   = regexp.MustCompile(`^(?:https?://)?(?:www\.)?github\.com/([^/\s]+)/([^/\s]+)/pull/(\d+)(?:[/?#].*)?$`)
	shortRe = regexp.MustCompile(`^([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)/([A-Za-z0-9._-]+)#(\d+)$`)
)

// Parse recognises a PR reference in either form:
//
//	https://github.com/OWNER/REPO/pull/123   (with or without scheme/suffix)
//	OWNER/REPO#123
func Parse(s string) (Ref, bool) {
	for _, re := range []*regexp.Regexp{urlRe, shortRe} {
		if m := re.FindStringSubmatch(strings.TrimSpace(s)); m != nil {
			n, err := strconv.Atoi(m[3])
			if err != nil || n <= 0 {
				return Ref{}, false
			}
			return Ref{Owner: m[1], Repo: m[2], Number: n}, true
		}
	}
	return Ref{}, false
}

// ChangedFile is one lockfile touched by the PR, with contents on both sides.
// Old is nil for added files, New is nil for removed ones.
type ChangedFile struct {
	Path string
	Old  []byte
	New  []byte
}

// Result is everything needed to diff and label a PR or comparison.
type Result struct {
	Files     []ChangedFile
	BaseLabel string // e.g. "main"
	HeadLabel string // e.g. "PR #123 (dependabot/cargo/jiff-0.1.14)"
	Title     string
	Warnings  []string
}

type client struct {
	http  *http.Client
	api   string // "https://api.github.com/" (overridable in tests)
	token string
}

func newClient() *client {
	return &client{
		http:  &http.Client{Timeout: 30 * time.Second},
		api:   "https://api.github.com/",
		token: findToken(),
	}
}

// Fetch downloads the PR metadata and the before/after contents of every
// changed file whose basename isLockfile accepts. It authenticates with
// GITHUB_TOKEN / GH_TOKEN when set (or a logged-in `gh` CLI), and works
// unauthenticated on public repos otherwise.
func Fetch(ref Ref, isLockfile func(path string) bool) (*Result, error) {
	c := newClient()

	// 1. PR metadata: head/base SHAs and repos.
	var pr struct {
		Title string `json:"title"`
		Base  struct {
			Ref  string `json:"ref"`
			SHA  string `json:"sha"`
			Repo struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"base"`
		Head struct {
			Ref  string `json:"ref"`
			SHA  string `json:"sha"`
			Repo *struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
	}
	if err := c.getJSON(fmt.Sprintf("repos/%s/%s/pulls/%d", ref.Owner, ref.Repo, ref.Number), &pr); err != nil {
		return nil, err
	}
	baseRepo := pr.Base.Repo.FullName
	headRepo := baseRepo // fork deleted: head commits stay reachable in base repo
	if pr.Head.Repo != nil && pr.Head.Repo.FullName != "" {
		headRepo = pr.Head.Repo.FullName
	}

	// 2. Merge base — the PR file list is relative to it, not to the
	// current tip of the base branch.
	var cmp struct {
		MergeBaseCommit struct {
			SHA string `json:"sha"`
		} `json:"merge_base_commit"`
	}
	mergeBase := pr.Base.SHA
	if err := c.getJSON(fmt.Sprintf("repos/%s/compare/%s...%s?per_page=1",
		baseRepo, pr.Base.SHA, pr.Head.SHA), &cmp); err == nil && cmp.MergeBaseCommit.SHA != "" {
		mergeBase = cmp.MergeBaseCommit.SHA
	}

	// 3. Changed files (paginated).
	type prFile struct {
		Filename         string `json:"filename"`
		Status           string `json:"status"`
		PreviousFilename string `json:"previous_filename"`
	}
	var matched []prFile
	for page := 1; page <= 30; page++ {
		var files []prFile
		if err := c.getJSON(fmt.Sprintf("repos/%s/%s/pulls/%d/files?per_page=100&page=%d",
			ref.Owner, ref.Repo, ref.Number, page), &files); err != nil {
			return nil, err
		}
		for _, f := range files {
			if isLockfile(f.Filename) {
				matched = append(matched, f)
			}
		}
		if len(files) < 100 {
			break
		}
	}

	// 4. Contents on both sides.
	res := &Result{
		BaseLabel: fmt.Sprintf("%s@%s", baseRepo, pr.Base.Ref),
		HeadLabel: fmt.Sprintf("PR #%d (%s)", ref.Number, pr.Head.Ref),
		Title:     pr.Title,
	}
	for _, f := range matched {
		cf := ChangedFile{Path: f.Filename}
		oldPath := f.Filename
		if f.Status == "renamed" && f.PreviousFilename != "" {
			oldPath = f.PreviousFilename
		}
		if f.Status != "added" {
			data, err := c.rawContents(baseRepo, mergeBase, oldPath)
			if err != nil {
				return nil, fmt.Errorf("%s (base side): %w", f.Filename, err)
			}
			cf.Old = data
		}
		if f.Status != "removed" {
			data, err := c.rawContents(headRepo, pr.Head.SHA, f.Filename)
			if err != nil {
				return nil, fmt.Errorf("%s (PR side): %w", f.Filename, err)
			}
			cf.New = data
		}
		res.Files = append(res.Files, cf)
	}
	return res, nil
}

// findToken looks for a GitHub token in the conventional env vars, then
// falls back to a logged-in gh CLI. Empty string means unauthenticated.
func findToken() string {
	for _, k := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	if path, err := exec.LookPath("gh"); err == nil {
		if out, err := exec.Command(path, "auth", "token").Output(); err == nil {
			return strings.TrimSpace(string(out))
		}
	}
	return ""
}

func (c *client) do(path, accept string) (*http.Response, error) {
	return c.doReq("GET", path, accept, nil)
}

func (c *client) doReq(method, path, accept string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = strings.NewReader(string(body))
	}
	req, err := http.NewRequest(method, c.api+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "lockvet (+https://github.com/matteo-sung/lockvet)")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
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
			hint = " — private repo? set GITHUB_TOKEN"
		}
		return nil, fmt.Errorf("GitHub API: %s: %s%s", resp.Status, path, hint)
	case http.StatusForbidden, http.StatusTooManyRequests:
		resp.Body.Close()
		hint := "rate limited?"
		if c.token == "" {
			hint = "rate limited — set GITHUB_TOKEN to raise the limit"
		}
		return nil, fmt.Errorf("GitHub API: %s: %s (%s)", resp.Status, path, hint)
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("GitHub API: %s: %s", resp.Status, path)
	}
}

func (c *client) getJSON(path string, v any) error {
	resp, err := c.do(path, "application/vnd.github+json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
}

// sendJSON issues a mutating request with a JSON body and decodes the reply.
func (c *client) sendJSON(method, path string, body []byte, v any) error {
	resp, err := c.doReq(method, path, "application/vnd.github+json", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if v == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
}

// rawContents fetches a file's raw bytes at a specific commit.
func (c *client) rawContents(repo, sha, path string) ([]byte, error) {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	p := fmt.Sprintf("repos/%s/contents/%s?ref=%s", repo, strings.Join(segs, "/"), url.QueryEscape(sha))
	resp, err := c.do(p, "application/vnd.github.raw+json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}
