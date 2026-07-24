// Package adopr fetches the lockfile changes of an Azure DevOps pull
// request (or comparison / commit) via the REST API, so it can be vetted
// without cloning the repository. dev.azure.com, *.visualstudio.com and
// self-hosted Azure DevOps Server instances all work — the /_git/ URL
// shape is unique to Azure DevOps, so any host is recognised.
package adopr

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

// Ref identifies an Azure DevOps pull request.
type Ref struct {
	Instance string // e.g. "https://dev.azure.com/fabrikam" (org URL, no trailing slash)
	Project  string // URL path segment, may be percent-encoded
	Repo     string // URL path segment, may be percent-encoded
	ID       int
}

func (r Ref) String() string {
	return fmt.Sprintf("%s/%s/%s PR #%d", strings.TrimPrefix(strings.TrimPrefix(r.Instance, "https://"), "http://"),
		pathLabel(r.Project), pathLabel(r.Repo), r.ID)
}

// CmpRef identifies a comparison between two revisions of an Azure DevOps
// repository. Base and Head follow lockvet's usual meaning: the diff
// explains how Head differs from Base (merge-base semantics, like a PR).
// BaseType / HeadType are "branch", "commit" or "tag".
type CmpRef struct {
	Instance string
	Project  string
	Repo     string
	Base     string
	BaseType string
	Head     string
	HeadType string
}

func (r CmpRef) String() string {
	return fmt.Sprintf("%s/%s/%s %s...%s", strings.TrimPrefix(strings.TrimPrefix(r.Instance, "https://"), "http://"),
		pathLabel(r.Project), pathLabel(r.Repo), r.Base, r.Head)
}

func pathLabel(seg string) string {
	if u, err := url.PathUnescape(seg); err == nil {
		return u
	}
	return seg
}

var (
	// https://dev.azure.com/ORG/PROJECT/_git/REPO/pullrequest/123
	// https://ORG.visualstudio.com/PROJECT/_git/REPO/pullrequest/123
	// https://tfs.example.com/tfs/COLLECTION/PROJECT/_git/REPO/pullrequest/123
	prURLRe = regexp.MustCompile(`^(?:(https?)://)?([^/\s]+(?:/[^/\s]+)*)/([^/\s]+)/_git/([^/\s]+)/pullrequest/(\d+)(?:[/?#].*)?$`)
	// .../PROJECT/_git/REPO/commit/SHA
	commitURLRe = regexp.MustCompile(`^(?:(https?)://)?([^/\s]+(?:/[^/\s]+)*)/([^/\s]+)/_git/([^/\s]+)/commit/([0-9a-fA-F]{7,40})(?:[/?#].*)?$`)
	// .../PROJECT/_git/REPO/branchCompare?baseVersion=GBmain&targetVersion=GBfeature
	cmpURLRe = regexp.MustCompile(`^(?:(https?)://)?([^/\s]+(?:/[^/\s]+)*)/([^/\s]+)/_git/([^/\s]+)/branchCompare\?([^#\s]+)(?:#.*)?$`)
)

// Parse recognises an Azure DevOps pull request URL:
//
//	https://dev.azure.com/ORG/PROJECT/_git/REPO/pullrequest/123
//
// *.visualstudio.com and self-hosted Azure DevOps Server URLs (with
// collection prefixes) are recognised too — the /_git/…/pullrequest/N
// shape is unique to Azure DevOps.
func Parse(s string) (Ref, bool) {
	m := prURLRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Ref{}, false
	}
	n, err := strconv.Atoi(m[5])
	if err != nil || n <= 0 {
		return Ref{}, false
	}
	inst, ok := instanceURL(m[1], m[2])
	if !ok {
		return Ref{}, false
	}
	return Ref{Instance: inst, Project: m[3], Repo: m[4], ID: n}, true
}

// ParseCommit recognises an Azure DevOps commit URL:
//
//	https://dev.azure.com/ORG/PROJECT/_git/REPO/commit/SHA
func ParseCommit(s string) (instance, project, repo, sha string, ok bool) {
	m := commitURLRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", "", "", "", false
	}
	inst, ok := instanceURL(m[1], m[2])
	if !ok {
		return "", "", "", "", false
	}
	return inst, m[3], m[4], m[5], true
}

// ParseCompare recognises an Azure DevOps branch-compare URL:
//
//	https://dev.azure.com/ORG/PROJECT/_git/REPO/branchCompare?baseVersion=GBmain&targetVersion=GBfeature
//
// The GB / GC / GT prefixes Azure DevOps puts on the two versions select
// branch, commit and tag respectively.
func ParseCompare(s string) (CmpRef, bool) {
	m := cmpURLRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return CmpRef{}, false
	}
	inst, ok := instanceURL(m[1], m[2])
	if !ok {
		return CmpRef{}, false
	}
	q, err := url.ParseQuery(m[5])
	if err != nil {
		return CmpRef{}, false
	}
	base, baseType, okB := splitVersion(q.Get("baseVersion"))
	head, headType, okH := splitVersion(q.Get("targetVersion"))
	if !okB || !okH {
		return CmpRef{}, false
	}
	return CmpRef{Instance: inst, Project: m[3], Repo: m[4],
		Base: base, BaseType: baseType, Head: head, HeadType: headType}, true
}

// splitVersion decodes an Azure DevOps version spec (GBmain, GC1a2b3c…,
// GTv1.0.0) into the plain name and its API versionType.
func splitVersion(spec string) (name, typ string, ok bool) {
	if len(spec) < 3 {
		return "", "", false
	}
	switch spec[:2] {
	case "GB":
		return spec[2:], "branch", true
	case "GC":
		return spec[2:], "commit", true
	case "GT":
		return spec[2:], "tag", true
	}
	return "", "", false
}

// instanceURL rebuilds the organization / collection base URL from the
// scheme and host+path prefix a URL regexp captured. It rejects hosts of
// the other forges lockvet knows, so bare-argument routing stays sound.
func instanceURL(scheme, hostPath string) (string, bool) {
	if scheme == "" {
		scheme = "https"
	}
	host := hostPath
	if i := strings.IndexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	if !strings.Contains(host, ".") && host != "localhost" && !strings.Contains(host, ":") {
		return "", false
	}
	switch strings.ToLower(host) {
	case "github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "gitea.com":
		return "", false
	}
	return scheme + "://" + hostPath, true
}

type client struct {
	http    *http.Client
	apiBase string // "<instance>/<project>/_apis/git/" (overridable in tests)
	token   string
}

func newClient(instance, project string) *client {
	return &client{
		http: &http.Client{
			Timeout: 60 * time.Second,
			// Azure DevOps answers unauthenticated requests for private
			// resources with a 302 to its sign-in page. Surface that as an
			// auth error instead of following it.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		apiBase: instance + "/" + project + "/_apis/git/",
		token:   firstEnv("AZURE_DEVOPS_TOKEN", "AZURE_DEVOPS_EXT_PAT", "ADO_TOKEN", "SYSTEM_ACCESSTOKEN"),
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

// diffChange mirrors the fields lockvet needs from the diffs API.
type diffChange struct {
	ChangeType string `json:"changeType"`
	Item       struct {
		Path          string `json:"path"`
		GitObjectType string `json:"gitObjectType"`
	} `json:"item"`
	SourceServerItem string `json:"sourceServerItem"` // old path on renames
}

type diffResult struct {
	AllChangesIncluded bool         `json:"allChangesIncluded"`
	Changes            []diffChange `json:"changes"`
	CommonCommit       string       `json:"commonCommit"`
	BaseCommit         string       `json:"baseCommit"`
	TargetCommit       string       `json:"targetCommit"`
}

// Fetch downloads the PR metadata and the before/after contents of every
// changed file isLockfile accepts. It authenticates with AZURE_DEVOPS_TOKEN
// / AZURE_DEVOPS_EXT_PAT (a personal access token) or SYSTEM_ACCESSTOKEN
// (Azure Pipelines) when set, and works unauthenticated on public projects.
func Fetch(ref Ref, isLockfile func(path string) bool) (*ghpr.Result, error) {
	c := newClient(ref.Instance, ref.Project)

	// 1. PR metadata.
	var pr struct {
		Title                 string `json:"title"`
		SourceRefName         string `json:"sourceRefName"`
		TargetRefName         string `json:"targetRefName"`
		LastMergeSourceCommit struct {
			CommitID string `json:"commitId"`
		} `json:"lastMergeSourceCommit"`
		LastMergeTargetCommit struct {
			CommitID string `json:"commitId"`
		} `json:"lastMergeTargetCommit"`
	}
	if err := c.getJSON(fmt.Sprintf("repositories/%s/pullRequests/%d?api-version=7.1", ref.Repo, ref.ID), &pr); err != nil {
		return nil, err
	}
	head, target := pr.LastMergeSourceCommit.CommitID, pr.LastMergeTargetCommit.CommitID
	if head == "" || target == "" {
		return nil, fmt.Errorf("PR #%d has no merge commits recorded yet (still computing, or in conflict?)", ref.ID)
	}

	// 2. Changed files vs the merge base (diffCommonCommit resolves it).
	diff, err := c.diff(ref.Repo, target, "commit", head, "commit")
	if err != nil {
		return nil, err
	}

	res := &ghpr.Result{
		BaseLabel: fmt.Sprintf("%s/%s@%s", pathLabel(ref.Project), pathLabel(ref.Repo), shortRef(pr.TargetRefName)),
		HeadLabel: fmt.Sprintf("PR #%d (%s)", ref.ID, shortRef(pr.SourceRefName)),
		Title:     pr.Title,
	}
	return c.fill(res, ref.Repo, diff, head, isLockfile)
}

// ResolveCommit turns a commit URL's parts into the CmpRef parent...sha, so
// a single commit can be vetted with FetchCompare.
func ResolveCommit(instance, project, repo, sha string) (CmpRef, error) {
	c := newClient(instance, project)
	var commit struct {
		CommitID string   `json:"commitId"`
		Parents  []string `json:"parents"`
	}
	if err := c.getJSON(fmt.Sprintf("repositories/%s/commits/%s?api-version=7.1", repo, url.PathEscape(sha)), &commit); err != nil {
		return CmpRef{}, err
	}
	if len(commit.Parents) == 0 {
		return CmpRef{}, fmt.Errorf("commit %s has no parent (root commit) — nothing to compare against", sha)
	}
	// Parents[0] follows the usual git convention: for merge commits this
	// compares against the branch the merge landed on.
	return CmpRef{Instance: instance, Project: project, Repo: repo,
		Base: commit.Parents[0], BaseType: "commit", Head: commit.CommitID, HeadType: "commit"}, nil
}

// FetchCompare downloads the file changes between two revisions (merge-base
// semantics, like a PR diff) and returns the before/after contents of every
// changed file isLockfile accepts.
func FetchCompare(ref CmpRef, isLockfile func(path string) bool) (*ghpr.Result, error) {
	c := newClient(ref.Instance, ref.Project)
	diff, err := c.diff(ref.Repo, ref.Base, ref.BaseType, ref.Head, ref.HeadType)
	if err != nil {
		return nil, err
	}
	res := &ghpr.Result{
		BaseLabel: fmt.Sprintf("%s/%s@%s", pathLabel(ref.Project), pathLabel(ref.Repo), ref.Base),
		HeadLabel: ref.Head,
	}
	return c.fill(res, ref.Repo, diff, diff.TargetCommit, isLockfile)
}

// diff pages through the diffs API with merge-base semantics.
func (c *client) diff(repo, base, baseType, head, headType string) (*diffResult, error) {
	out := &diffResult{}
	const page = 1000
	for skip := 0; ; {
		var d diffResult
		p := fmt.Sprintf("repositories/%s/diffs/commits?baseVersion=%s&baseVersionType=%s&targetVersion=%s&targetVersionType=%s&diffCommonCommit=true&%%24top=%d&%%24skip=%d&api-version=7.1",
			repo, url.QueryEscape(base), baseType, url.QueryEscape(head), headType, page, skip)
		if err := c.getJSON(p, &d); err != nil {
			return nil, err
		}
		if out.CommonCommit == "" {
			out.CommonCommit, out.BaseCommit, out.TargetCommit = d.CommonCommit, d.BaseCommit, d.TargetCommit
		}
		out.Changes = append(out.Changes, d.Changes...)
		if d.AllChangesIncluded || len(d.Changes) == 0 || skip > 100*page {
			break
		}
		skip += len(d.Changes)
	}
	return out, nil
}

// fill downloads both sides of every matched lockfile: the old side at the
// merge-base commit, the new side at the head commit.
func (c *client) fill(res *ghpr.Result, repo string, diff *diffResult, head string, isLockfile func(path string) bool) (*ghpr.Result, error) {
	for _, ch := range diff.Changes {
		if ch.Item.GitObjectType != "" && ch.Item.GitObjectType != "blob" {
			continue
		}
		path := strings.TrimPrefix(ch.Item.Path, "/")
		if path == "" || !isLockfile(path) {
			continue
		}
		typ := strings.ToLower(ch.ChangeType)
		oldPath := ch.Item.Path
		if ch.SourceServerItem != "" {
			oldPath = ch.SourceServerItem
		}
		cf := ghpr.ChangedFile{Path: path}
		if !strings.Contains(typ, "add") {
			data, err := c.item(repo, oldPath, diff.CommonCommit)
			if err != nil {
				return nil, fmt.Errorf("%s (base side): %w", path, err)
			}
			cf.Old = data
		}
		if !strings.Contains(typ, "delete") {
			data, err := c.item(repo, ch.Item.Path, head)
			if err != nil {
				return nil, fmt.Errorf("%s (head side): %w", path, err)
			}
			cf.New = data
		}
		res.Files = append(res.Files, cf)
	}
	return res, nil
}

// item fetches a file's raw bytes at a commit.
func (c *client) item(repo, path, commit string) ([]byte, error) {
	p := fmt.Sprintf("repositories/%s/items?path=%s&versionDescriptor.version=%s&versionDescriptor.versionType=commit&download=true&api-version=7.1",
		repo, url.QueryEscape(path), url.QueryEscape(commit))
	resp, err := c.do("GET", c.apiBase+p, nil, "*/*")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

func (c *client) authed() bool { return c.token != "" }

func (c *client) do(method, absURL string, body []byte, accept string) (*http.Response, error) {
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
	req.Header.Set("Accept", accept)
	req.Header.Set("User-Agent", "lockvet (+https://github.com/matteo-sung/lockvet)")
	if c.token != "" {
		if strings.Contains(c.token, ".") {
			// OAuth / System.AccessToken JWTs go in a Bearer header…
			req.Header.Set("Authorization", "Bearer "+c.token)
		} else {
			// …personal access tokens ride as a basic-auth password.
			req.SetBasicAuth("", c.token)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	authHint := " — private project? set AZURE_DEVOPS_TOKEN to a personal access token (Code: Read)"
	if c.authed() {
		authHint = " — does the token have Code: Read scope and access to this project?"
	}
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated:
		// Azure DevOps signals "sign in required" with an HTML page on an
		// otherwise-OK status for some routes; catch that when JSON was asked.
		if accept == "application/json" && !strings.Contains(resp.Header.Get("Content-Type"), "json") {
			resp.Body.Close()
			return nil, fmt.Errorf("Azure DevOps API: got a sign-in page for %s%s", absURL, authHint)
		}
		return resp, nil
	case resp.StatusCode == http.StatusNonAuthoritativeInfo, // 203: sign-in page
		resp.StatusCode == http.StatusFound, resp.StatusCode == http.StatusMovedPermanently,
		resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		resp.Body.Close()
		return nil, fmt.Errorf("Azure DevOps API: %s: %s%s", resp.Status, absURL, authHint)
	case resp.StatusCode == http.StatusNotFound:
		resp.Body.Close()
		return nil, fmt.Errorf("Azure DevOps API: %s: %s — check the organization, project, repository and number%s", resp.Status, absURL, authHint)
	case resp.StatusCode == http.StatusTooManyRequests:
		resp.Body.Close()
		hint := "rate limited?"
		if !c.authed() {
			hint = "rate limited — authenticate to raise the limit"
		}
		return nil, fmt.Errorf("Azure DevOps API: %s: %s (%s)", resp.Status, absURL, hint)
	default:
		defer resp.Body.Close()
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		var apiErr struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(msg, &apiErr) == nil && apiErr.Message != "" {
			return nil, fmt.Errorf("Azure DevOps API: %s: %s: %s", resp.Status, absURL, apiErr.Message)
		}
		return nil, fmt.Errorf("Azure DevOps API: %s: %s", resp.Status, absURL)
	}
}

func (c *client) getJSON(path string, v any) error {
	resp, err := c.do("GET", c.apiBase+path, nil, "application/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
}

// sendJSON issues a mutating request with a JSON body and decodes the reply.
func (c *client) sendJSON(method, path string, body []byte, v any) error {
	resp, err := c.do(method, c.apiBase+path, body, "application/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if v == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(v)
}

func shortRef(ref string) string {
	ref = strings.TrimPrefix(ref, "refs/heads/")
	return strings.TrimPrefix(ref, "refs/tags/")
}
