// Package bbpr fetches the lockfile changes of a Bitbucket Cloud pull
// request (or comparison / commit) via the REST API, so it can be vetted
// without cloning the repository.
package bbpr

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

// Ref identifies a Bitbucket Cloud pull request.
type Ref struct {
	Workspace string
	Repo      string
	ID        int
}

func (r Ref) String() string {
	return fmt.Sprintf("bitbucket.org/%s/%s PR #%d", r.Workspace, r.Repo, r.ID)
}

// CmpRef identifies a comparison between two revisions of a Bitbucket repo.
// Base and Head follow lockvet's usual meaning: the diff explains how Head
// differs from Base (merge-base semantics, like a PR).
type CmpRef struct {
	Workspace string
	Repo      string
	Base      string
	Head      string
}

func (r CmpRef) String() string {
	return fmt.Sprintf("bitbucket.org/%s/%s %s...%s", r.Workspace, r.Repo, r.Base, r.Head)
}

var (
	// https://bitbucket.org/WORKSPACE/REPO/pull-requests/123
	prURLRe = regexp.MustCompile(`^(?:https?://)?(?:www\.)?bitbucket\.org/([^/\s]+)/([^/\s]+)/pull-requests/(\d+)(?:[/?#].*)?$`)
	// https://bitbucket.org/WORKSPACE/REPO/branches/compare/SOURCE..DEST
	// (Bitbucket's native order: source first, destination second; the two
	// revisions may also be separated by an encoded \r, as Bitbucket's own
	// UI links do.)
	cmpURLRe = regexp.MustCompile(`^(?:https?://)?(?:www\.)?bitbucket\.org/([^/\s]+)/([^/\s]+)/branches/compare/([^?#\s]+)(?:[?#].*)?$`)
	// https://bitbucket.org/WORKSPACE/REPO/commits/SHA
	commitURLRe = regexp.MustCompile(`^(?:https?://)?(?:www\.)?bitbucket\.org/([^/\s]+)/([^/\s]+)/commits/([0-9a-fA-F]{7,40})(?:[/?#].*)?$`)
)

// Parse recognises a Bitbucket pull request URL:
//
//	https://bitbucket.org/WORKSPACE/REPO/pull-requests/123
func Parse(s string) (Ref, bool) {
	m := prURLRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Ref{}, false
	}
	n, err := strconv.Atoi(m[3])
	if err != nil || n <= 0 {
		return Ref{}, false
	}
	return Ref{Workspace: m[1], Repo: m[2], ID: n}, true
}

// ParseCompare recognises a Bitbucket branch-compare URL:
//
//	https://bitbucket.org/WORKSPACE/REPO/branches/compare/HEAD..BASE
//
// Bitbucket's compare pages put the source (head) first and the destination
// (base) second — the reverse of GitHub. ParseCompare converts to lockvet's
// base/head convention, so a pasted URL means what the page showed.
func ParseCompare(s string) (CmpRef, bool) {
	m := cmpURLRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return CmpRef{}, false
	}
	spec := m[3]
	if u, err := url.PathUnescape(spec); err == nil {
		spec = u
	}
	var head, base string
	if i := strings.Index(spec, ".."); i >= 0 {
		head, base = spec[:i], spec[i+2:]
	} else if i := strings.IndexAny(spec, "\r\n"); i >= 0 { // %0D separator
		head, base = spec[:i], strings.TrimLeft(spec[i:], "\r\n")
	} else {
		return CmpRef{}, false
	}
	head, base = strings.TrimSpace(head), strings.TrimSpace(base)
	if head == "" || base == "" {
		return CmpRef{}, false
	}
	return CmpRef{Workspace: m[1], Repo: m[2], Base: base, Head: head}, true
}

// ParseCommit recognises a Bitbucket commit URL:
//
//	https://bitbucket.org/WORKSPACE/REPO/commits/SHA
func ParseCommit(s string) (workspace, repo, sha string, ok bool) {
	m := commitURLRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}

type client struct {
	http *http.Client
	api  string // "https://api.bitbucket.org/2.0/" (overridable in tests)

	token   string // workspace / repo access token → Bearer
	user    string // app password pair → Basic
	appPass string
}

func newClient() *client {
	return &client{
		http:    &http.Client{Timeout: 30 * time.Second},
		api:     "https://api.bitbucket.org/2.0/",
		token:   firstEnv("BITBUCKET_TOKEN", "BB_TOKEN"),
		user:    firstEnv("BITBUCKET_USERNAME"),
		appPass: firstEnv("BITBUCKET_APP_PASSWORD"),
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

func (c *client) authed() bool { return c.token != "" || (c.user != "" && c.appPass != "") }

// diffstat mirrors the fields lockvet needs from Bitbucket's diffstat
// entries. The old/new links point straight at the raw file contents on the
// correct commit of the correct repository — Bitbucket resolves merge bases
// and fork repositories for us.
type diffstat struct {
	Status string `json:"status"`
	Old    *struct {
		Path  string `json:"path"`
		Links struct {
			Self struct {
				Href string `json:"href"`
			} `json:"self"`
		} `json:"links"`
	} `json:"old"`
	New *struct {
		Path  string `json:"path"`
		Links struct {
			Self struct {
				Href string `json:"href"`
			} `json:"self"`
		} `json:"links"`
	} `json:"new"`
}

// Fetch downloads the PR metadata and the before/after contents of every
// changed file isLockfile accepts. It authenticates with BITBUCKET_TOKEN
// (access token) or BITBUCKET_USERNAME + BITBUCKET_APP_PASSWORD when set,
// and works unauthenticated on public repositories otherwise.
func Fetch(ref Ref, isLockfile func(path string) bool) (*ghpr.Result, error) {
	c := newClient()

	// 1. PR metadata.
	var pr struct {
		Title  string `json:"title"`
		Source struct {
			Branch struct {
				Name string `json:"name"`
			} `json:"branch"`
		} `json:"source"`
		Destination struct {
			Branch struct {
				Name string `json:"name"`
			} `json:"branch"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		} `json:"destination"`
	}
	if err := c.getJSON(fmt.Sprintf("repositories/%s/%s/pullrequests/%d",
		ref.Workspace, ref.Repo, ref.ID), &pr); err != nil {
		return nil, err
	}

	baseRepo := pr.Destination.Repository.FullName
	if baseRepo == "" {
		baseRepo = ref.Workspace + "/" + ref.Repo
	}
	res := &ghpr.Result{
		BaseLabel: fmt.Sprintf("%s@%s", baseRepo, pr.Destination.Branch.Name),
		HeadLabel: fmt.Sprintf("PR #%d (%s)", ref.ID, pr.Source.Branch.Name),
		Title:     pr.Title,
	}

	// 2. Changed files (paginated), 3. contents of both sides.
	stats, err := c.allDiffstats(fmt.Sprintf("repositories/%s/%s/pullrequests/%d/diffstat?pagelen=100",
		ref.Workspace, ref.Repo, ref.ID))
	if err != nil {
		return nil, err
	}
	return c.fill(res, stats, isLockfile)
}

// ResolveCommit turns WORKSPACE/REPO + SHA into the CmpRef parent...sha, so
// a single commit can be vetted with FetchCompare.
func ResolveCommit(workspace, repo, sha string) (CmpRef, error) {
	c := newClient()
	var commit struct {
		Hash    string `json:"hash"`
		Parents []struct {
			Hash string `json:"hash"`
		} `json:"parents"`
	}
	if err := c.getJSON(fmt.Sprintf("repositories/%s/%s/commit/%s",
		workspace, repo, url.PathEscape(sha)), &commit); err != nil {
		return CmpRef{}, err
	}
	if len(commit.Parents) == 0 {
		return CmpRef{}, fmt.Errorf("commit %s has no parent (root commit) — nothing to compare against", sha)
	}
	// Parents[0] follows the usual git convention: for merge commits this
	// compares against the branch the merge landed on.
	return CmpRef{Workspace: workspace, Repo: repo, Base: commit.Parents[0].Hash, Head: commit.Hash}, nil
}

// FetchCompare downloads the file changes between two revisions via the
// Bitbucket diffstat API (merge-base semantics, like a PR diff) and returns
// the before/after contents of every changed file isLockfile accepts.
func FetchCompare(ref CmpRef, isLockfile func(path string) bool) (*ghpr.Result, error) {
	c := newClient()

	// Bitbucket diffstat specs are SOURCE..DESTINATION (head..base).
	spec := url.PathEscape(ref.Head) + ".." + url.PathEscape(ref.Base)
	stats, err := c.allDiffstats(fmt.Sprintf("repositories/%s/%s/diffstat/%s?pagelen=100",
		ref.Workspace, ref.Repo, spec))
	if err != nil {
		return nil, err
	}
	res := &ghpr.Result{
		BaseLabel: fmt.Sprintf("%s/%s@%s", ref.Workspace, ref.Repo, ref.Base),
		HeadLabel: ref.Head,
	}
	return c.fill(res, stats, isLockfile)
}

// allDiffstats pages through a diffstat listing, following the API's own
// "next" links (the first request is usually answered with a redirect, which
// net/http follows transparently).
func (c *client) allDiffstats(path string) ([]diffstat, error) {
	next := c.api + path
	var all []diffstat
	for i := 0; i < 30 && next != ""; i++ {
		if !strings.HasPrefix(next, c.api) {
			return nil, fmt.Errorf("Bitbucket API returned an unexpected page URL: %s", next)
		}
		var page struct {
			Values []diffstat `json:"values"`
			Next   string     `json:"next"`
		}
		if err := c.getJSONURL(next, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Values...)
		next = page.Next
	}
	return all, nil
}

// fill downloads both sides of every matched lockfile straight from the
// hrefs Bitbucket put in the diffstat (correct commit, correct repository —
// fork PRs included).
func (c *client) fill(res *ghpr.Result, stats []diffstat, isLockfile func(path string) bool) (*ghpr.Result, error) {
	for _, st := range stats {
		var oldHref, newHref, oldPath, newPath string
		if st.Old != nil {
			oldPath, oldHref = st.Old.Path, st.Old.Links.Self.Href
		}
		if st.New != nil {
			newPath, newHref = st.New.Path, st.New.Links.Self.Href
		}
		path := newPath
		if path == "" {
			path = oldPath
		}
		if path == "" || !isLockfile(path) {
			continue
		}
		cf := ghpr.ChangedFile{Path: path}
		if oldHref != "" {
			data, err := c.raw(oldHref)
			if err != nil {
				return nil, fmt.Errorf("%s (base side): %w", oldPath, err)
			}
			cf.Old = data
		}
		if newHref != "" {
			data, err := c.raw(newHref)
			if err != nil {
				return nil, fmt.Errorf("%s (head side): %w", newPath, err)
			}
			cf.New = data
		}
		res.Files = append(res.Files, cf)
	}
	return res, nil
}

func (c *client) do(method, absURL string, body []byte) (*http.Response, error) {
	var rd io.Reader
	if body != nil {
		rd = strings.NewReader(string(body))
	}
	req, err := http.NewRequest(method, absURL, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "lockvet (+https://github.com/matteo-sung/lockvet)")
	switch {
	case c.token != "":
		req.Header.Set("Authorization", "Bearer "+c.token)
	case c.user != "" && c.appPass != "":
		req.SetBasicAuth(c.user, c.appPass)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return resp, nil
	case http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden:
		resp.Body.Close()
		hint := ""
		if !c.authed() {
			hint = " — private repo? set BITBUCKET_TOKEN (or BITBUCKET_USERNAME + BITBUCKET_APP_PASSWORD)"
		}
		return nil, fmt.Errorf("Bitbucket API: %s: %s%s", resp.Status, absURL, hint)
	case http.StatusTooManyRequests:
		resp.Body.Close()
		hint := "rate limited?"
		if !c.authed() {
			hint = "rate limited — authenticate to raise the limit"
		}
		return nil, fmt.Errorf("Bitbucket API: %s: %s (%s)", resp.Status, absURL, hint)
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("Bitbucket API: %s: %s", resp.Status, absURL)
	}
}

func (c *client) getJSON(path string, v any) error {
	return c.getJSONURL(c.api+path, v)
}

func (c *client) getJSONURL(absURL string, v any) error {
	resp, err := c.do("GET", absURL, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
}

// sendJSON issues a mutating request with a JSON body and decodes the reply.
func (c *client) sendJSON(method, path string, body []byte, v any) error {
	resp, err := c.do(method, c.api+path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if v == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
}

// raw fetches a file's raw bytes from a diffstat href.
func (c *client) raw(href string) ([]byte, error) {
	if !strings.HasPrefix(href, c.api) {
		return nil, fmt.Errorf("Bitbucket API returned an unexpected file URL: %s", href)
	}
	resp, err := c.do("GET", href, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}
