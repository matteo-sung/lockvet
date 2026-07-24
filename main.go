// lockvet — explain any lockfile change: what bumped, what's breaking,
// what's newly vulnerable. https://github.com/matteo-sung/lockvet
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/bbpr"
	"github.com/matteo-sung/lockvet/internal/depsdev"
	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/ghpr"
	"github.com/matteo-sung/lockvet/internal/gitx"
	"github.com/matteo-sung/lockvet/internal/glmr"
	"github.com/matteo-sung/lockvet/internal/gtpr"
	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/osv"
	"github.com/matteo-sung/lockvet/internal/render"
	"github.com/matteo-sung/lockvet/internal/taglink"
	"github.com/matteo-sung/lockvet/internal/vers"
)

var version = "dev" // set via -ldflags at release time

// effectiveVersion falls back to the module version recorded by `go install`
// when the binary wasn't built with release ldflags.
func effectiveVersion() string {
	if version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

var usage = `lockvet — explain any lockfile change before you merge it.

USAGE
  lockvet [flags] [<base> [<target>]]

  lockvet                 working tree vs HEAD
  lockvet HEAD~5          working tree vs HEAD~5
  lockvet main my-branch  branch vs branch (or any two revisions)

  lockvet pr <owner>/<repo>#<n>       vet a GitHub pull request — no clone
  lockvet <github PR url>             needed (e.g. a Dependabot PR). Uses
                                      GITHUB_TOKEN / gh auth if available.

  lockvet mr <group>/<project>!<n>    vet a GitLab merge request (gitlab.com
  lockvet <gitlab MR url>             or self-hosted; e.g. a Renovate MR).
                                      Uses GITLAB_TOKEN / CI_JOB_TOKEN.

  lockvet pr <bitbucket PR url>       vet a Bitbucket Cloud pull request.
                                      Uses BITBUCKET_TOKEN or app passwords.

  lockvet compare <o>/<r> <a>...<b>   vet any two revisions of a GitHub,
  lockvet <compare url>               GitLab, Bitbucket, or Gitea/Forgejo
  lockvet <commit url>                repo, or a single commit, w/o cloning.

  lockvet queue <owner>               triage EVERY open Dependabot/Renovate
  lockvet queue <owner>/<repo>        PR of a GitHub user, org, or repo in
                                      one table: which introduce
                                      vulnerabilities, which are major or
                                      brand-new bumps, which look routine.

  lockvet queue <gitlab group url>    same for a GitLab group or project
  lockvet queue <gitlab project url>  (gitlab.com or self-hosted), e.g.
                                      lockvet queue gitlab.com/gitlab-org.
                                      Bot usernames vary on GitLab — pass
                                      -author <username> for custom bots.

  lockvet queue <gitea owner url>     same for a Gitea/Forgejo user, org, or
  lockvet queue <gitea repo url>      repo (codeberg.org, gitea.com, or
                                      self-hosted), e.g. lockvet queue
                                      codeberg.org/forgejo. Bot usernames
                                      vary here too: -author <username>.

FLAGS
  -md            markdown output (for PR comments)
  -json          JSON output
  -sarif         SARIF 2.1.0 output (GitHub Code Scanning: vulnerable,
                 unresolved, and deprecated incoming versions become alerts
                 on the exact lockfile line)
  -no-vulns      skip the OSV.dev vulnerability check
  -no-meta       skip the deps.dev metadata check (release age, deprecations)
                 and upstream changelog/diff links
  -offline       no network calls at all (= -no-vulns -no-meta)
  -fresh-days N  flag versions published fewer than N days ago (default 7;
                 0 shows ages but never flags)
  -only PAT      show one package's story: only changes whose name — or any
                 package in their "via" chain — matches PAT. Glob, case-
                 insensitive, comma list ok: -only jiff, -only "@babel/*"
  -comment       (pr / mr modes) post the report as a comment on the pull or
                 merge request — reruns update the same comment in place.
                 Needs GITHUB_TOKEN / gh login, GITLAB_TOKEN (api scope), or
                 BITBUCKET_TOKEN / app password (pullrequest:write).
  -fail-on X     exit 1 if the diff contains X: "major", "vuln", "downgrade",
                 "fresh", or "deprecated"
                 (repeatable as comma list: -fail-on major,vuln,fresh)
  -author LIST   (queue mode) bot accounts to search for, comma list
                 (GitHub default "app/dependabot,app/renovate"; GitLab and
                 Gitea/Forgejo default "renovate-bot,dependabot"; "any" =
                 every open PR/MR that touches a lockfile)
  -limit N       (queue mode) vet at most N pull/merge requests (default 30)
  -C dir         run as if started in dir
  -no-color      disable colors (also respects NO_COLOR)
  -version       print version

SUPPORTED LOCKFILES
  ` + strings.Join(lock.KnownBasenames(), ", ") + `

Every ecosystem in one binary.
Data: https://osv.dev (vulnerabilities) · https://deps.dev (release metadata)
`

func main() {
	var (
		md        = flag.Bool("md", false, "")
		jsonOut   = flag.Bool("json", false, "")
		sarifOut  = flag.Bool("sarif", false, "")
		noVulns   = flag.Bool("no-vulns", false, "")
		noMeta    = flag.Bool("no-meta", false, "")
		offline   = flag.Bool("offline", false, "")
		freshDays = flag.Int("fresh-days", 7, "")
		only      = flag.String("only", "", "")
		author    = flag.String("author", "", "")
		limit     = flag.Int("limit", 30, "")
		comment   = flag.Bool("comment", false, "")
		failOn    = flag.String("fail-on", "", "")
		dir       = flag.String("C", ".", "")
		noColor   = flag.Bool("no-color", false, "")
		showVer   = flag.Bool("version", false, "")
	)
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.CommandLine.Parse(reorderArgs(os.Args[1:]))

	if *showVer {
		fmt.Println("lockvet", effectiveVersion())
		return
	}
	if *offline {
		*noVulns = true
		*noMeta = true
	}

	args := flag.Args()

	// GitHub remote modes: `lockvet pr owner/repo#123`, `lockvet compare
	// owner/repo base...head`, or a bare PR / compare / commit URL.
	var (
		remoteFetch func(func(string) bool) (*ghpr.Result, error)
		remoteWhat  string                                  // for the "no lockfile changes" message
		remotePost  func(body string) (string, bool, error) // -comment target (pr/mr only)
	)
	setPR := func(ref ghpr.Ref) {
		remoteFetch = func(f func(string) bool) (*ghpr.Result, error) { return ghpr.Fetch(ref, f) }
		remoteWhat = ref.String()
		remotePost = func(body string) (string, bool, error) { return ghpr.PostComment(ref, body) }
	}
	setCmp := func(ref ghpr.CmpRef) {
		remoteFetch = func(f func(string) bool) (*ghpr.Result, error) { return ghpr.FetchCompare(ref, f) }
		remoteWhat = ref.String()
	}
	setMR := func(ref glmr.Ref) {
		remoteFetch = func(f func(string) bool) (*ghpr.Result, error) { return glmr.Fetch(ref, f) }
		remoteWhat = ref.String()
		remotePost = func(body string) (string, bool, error) { return glmr.PostComment(ref, body) }
	}
	setGLCmp := func(ref glmr.CmpRef) {
		remoteFetch = func(f func(string) bool) (*ghpr.Result, error) { return glmr.FetchCompare(ref, f) }
		remoteWhat = ref.String()
	}
	setBB := func(ref bbpr.Ref) {
		remoteFetch = func(f func(string) bool) (*ghpr.Result, error) { return bbpr.Fetch(ref, f) }
		remoteWhat = ref.String()
		remotePost = func(body string) (string, bool, error) { return bbpr.PostComment(ref, body) }
	}
	setBBCmp := func(ref bbpr.CmpRef) {
		remoteFetch = func(f func(string) bool) (*ghpr.Result, error) { return bbpr.FetchCompare(ref, f) }
		remoteWhat = ref.String()
	}
	setGT := func(ref gtpr.Ref) {
		remoteFetch = func(f func(string) bool) (*ghpr.Result, error) { return gtpr.Fetch(ref, f) }
		remoteWhat = ref.String()
		remotePost = func(body string) (string, bool, error) { return gtpr.PostComment(ref, body) }
	}
	setGTCommit := func(ref gtpr.CommitRef) {
		remoteFetch = func(f func(string) bool) (*ghpr.Result, error) { return gtpr.FetchCommit(ref, f) }
		remoteWhat = ref.String()
	}
	setGTCmp := func(ref gtpr.CmpRef) {
		remoteFetch = func(f func(string) bool) (*ghpr.Result, error) { return gtpr.FetchCompare(ref, f) }
		remoteWhat = ref.String()
	}
	switch {
	case len(args) > 0 && args[0] == "queue":
		if len(args) != 2 {
			fatal("usage: lockvet queue <owner | owner/repo | gitlab group/project URL>   (e.g. lockvet queue grafana)")
		}
		if *comment {
			fatal("-comment is not available in queue mode — it needs a single PR (lockvet pr … -comment)")
		}
		if *sarifOut {
			fatal("-sarif is not available in queue mode — run lockvet pr <url> -sarif per PR")
		}
		runQueue(args[1], queueOpts{
			author: *author, limit: *limit,
			md: *md, jsonOut: *jsonOut,
			noVulns: *noVulns, noMeta: *noMeta, freshDays: *freshDays,
			only: *only, failOn: *failOn, noColor: *noColor,
		})
		return
	case len(args) > 0 && (args[0] == "pr" || args[0] == "mr"):
		if len(args) != 2 {
			fatal("usage: lockvet " + args[0] + " <owner/repo#N | group/project!N | PR or MR url>")
		}
		if ref, ok := bbpr.Parse(args[1]); ok {
			setBB(ref)
		} else if ref, ok := ghpr.Parse(args[1]); ok {
			setPR(ref)
		} else if ref, ok := glmr.ParseMR(args[1]); ok {
			setMR(ref)
		} else if ref, ok := gtpr.Parse(args[1]); ok {
			setGT(ref)
		} else {
			fatal(fmt.Sprintf("cannot parse %q as a pull/merge request (want owner/repo#N, group/project!N, or a GitHub/GitLab/Bitbucket/Gitea url)", args[1]))
		}
	case len(args) > 0 && args[0] == "compare":
		switch len(args) {
		case 2: // lockvet compare <compare-or-commit url>
			if ref, ok := ghpr.ParseCompare(args[1]); ok {
				setCmp(ref)
			} else if o, r, sha, ok := ghpr.ParseCommit(args[1]); ok {
				ref, err := ghpr.ResolveCommit(o, r, sha)
				check(err)
				setCmp(ref)
			} else if ref, ok := glmr.ParseCompare(args[1]); ok {
				setGLCmp(ref)
			} else if h, p, sha, ok := glmr.ParseCommit(args[1]); ok {
				ref, err := glmr.ResolveCommit(h, p, sha)
				check(err)
				setGLCmp(ref)
			} else if ref, ok := bbpr.ParseCompare(args[1]); ok {
				setBBCmp(ref)
			} else if w, r, sha, ok := bbpr.ParseCommit(args[1]); ok {
				ref, err := bbpr.ResolveCommit(w, r, sha)
				check(err)
				setBBCmp(ref)
			} else if ref, ok := gtpr.ParseCommit(args[1]); ok {
				setGTCommit(ref)
			} else if ref, ok := gtpr.ParseCompare(args[1]); ok {
				setGTCmp(ref)
			} else {
				fatal(fmt.Sprintf("cannot parse %q (want a GitHub/GitLab/Bitbucket/Gitea compare/commit url, or: lockvet compare owner/repo base...head)", args[1]))
			}
		case 3: // lockvet compare owner/repo base...head
			owner, repo, okRepo := strings.Cut(args[1], "/")
			b, h, okRange := ghpr.SplitBasehead(args[2])
			if !okRepo || owner == "" || repo == "" || !okRange {
				fatal(fmt.Sprintf("cannot parse %q %q (want: lockvet compare owner/repo base...head)", args[1], args[2]))
			}
			setCmp(ghpr.CmpRef{Owner: owner, Repo: repo, Base: b, Head: h})
		default:
			fatal("usage: lockvet compare <owner/repo base...head | github compare/commit url>")
		}
	case len(args) == 1 && strings.Contains(args[0], "github.com/"):
		if ref, ok := ghpr.Parse(args[0]); ok {
			setPR(ref)
		} else if ref, ok := ghpr.ParseCompare(args[0]); ok {
			setCmp(ref)
		} else if o, r, sha, ok := ghpr.ParseCommit(args[0]); ok {
			ref, err := ghpr.ResolveCommit(o, r, sha)
			check(err)
			setCmp(ref)
		}
	case len(args) == 1 && strings.Contains(args[0], "bitbucket.org/"):
		if ref, ok := bbpr.Parse(args[0]); ok {
			setBB(ref)
		} else if ref, ok := bbpr.ParseCompare(args[0]); ok {
			setBBCmp(ref)
		} else if w, r, sha, ok := bbpr.ParseCommit(args[0]); ok {
			ref, err := bbpr.ResolveCommit(w, r, sha)
			check(err)
			setBBCmp(ref)
		}
	case len(args) == 1 && strings.Contains(args[0], "/-/"):
		// GitLab web URLs (gitlab.com or self-hosted) all use the /-/
		// separator: .../-/merge_requests/N, /-/compare/a...b, /-/commit/sha.
		if ref, ok := glmr.ParseMR(args[0]); ok {
			setMR(ref)
		} else if ref, ok := glmr.ParseCompare(args[0]); ok {
			setGLCmp(ref)
		} else if h, p, sha, ok := glmr.ParseCommit(args[0]); ok {
			ref, err := glmr.ResolveCommit(h, p, sha)
			check(err)
			setGLCmp(ref)
		}
	case len(args) == 1:
		// Gitea/Forgejo web URLs (codeberg.org or self-hosted): the
		// /pulls/N path shape is unique to them, so any host works.
		if ref, ok := gtpr.Parse(args[0]); ok {
			setGT(ref)
		} else if ref, ok := gtpr.ParseCommit(args[0]); ok {
			setGTCommit(ref)
		} else if ref, ok := gtpr.ParseCompare(args[0]); ok {
			setGTCmp(ref)
		}
	}

	if *comment && remotePost == nil {
		fatal("-comment needs a pull or merge request to comment on — use it with `lockvet pr …` or `lockvet mr …`")
	}

	var (
		diffs        []diffx.FileDiff
		base, target string

		// New-side raw bytes per lockfile path, kept so SARIF output can
		// point results at the exact line that names the package.
		newContents = map[string][]byte{}
	)
	if remoteFetch != nil {
		res, err := remoteFetch(func(p string) bool { return lock.ByBasename(p) != nil })
		check(err)
		for _, w := range res.Warnings {
			fmt.Fprintf(os.Stderr, "lockvet: warning: %s\n", w)
		}
		base, target = res.BaseLabel, res.HeadLabel
		for _, cf := range res.Files {
			parser := lock.ByBasename(cf.Path)
			oldF := parseOrNil(parser, cf.Path, cf.Old)
			newF := parseOrNil(parser, cf.Path, cf.New)
			if oldF == nil && newF == nil {
				continue
			}
			fd := diffx.Diff(oldF, newF)
			if len(fd.Changes) > 0 {
				diffs = append(diffs, fd)
				newContents[cf.Path] = cf.New
			}
		}
		if len(diffs) == 0 {
			msg := remoteWhat
			if res.Title != "" {
				msg = fmt.Sprintf("%s (%q)", remoteWhat, res.Title)
			}
			fmt.Fprintf(os.Stderr, "lockvet: no lockfile changes in %s\n", msg)
			return
		}
	} else {
		base, target = "HEAD", ""
		switch len(args) {
		case 0:
		case 1:
			base = args[0]
		case 2:
			base, target = args[0], args[1]
		default:
			fatal("too many arguments (want at most: <base> <target>)")
		}
		if i := strings.Index(base, ".."); i >= 0 && target == "" {
			base, target = base[:i], strings.TrimPrefix(base[i+2:], ".")
		}

		repo, err := gitx.Open(*dir)
		check(err)
		check(repo.ResolveRev(base))
		if target != "" {
			check(repo.ResolveRev(target))
		}

		changed, err := repo.ChangedFiles(base, target)
		check(err)

		for _, p := range changed {
			parser := lock.ByBasename(p)
			if parser == nil {
				continue
			}
			oldData, err := repo.Show(base, p)
			check(err)
			newData, err := repo.Show(target, p)
			check(err)
			oldF := parseOrNil(parser, p, oldData)
			newF := parseOrNil(parser, p, newData)
			if oldF == nil && newF == nil {
				continue
			}
			fd := diffx.Diff(oldF, newF)
			if len(fd.Changes) > 0 {
				diffs = append(diffs, fd)
				newContents[p] = newData
			}
		}

		if len(diffs) == 0 {
			where := "between " + base + " and " + displayTarget(target)
			fmt.Fprintf(os.Stderr, "lockvet: no lockfile changes %s\n", where)
			fmt.Fprintf(os.Stderr, "hint: try a range, e.g.  lockvet HEAD~10  or  lockvet main my-branch\n")
			return
		}
	}

	if *only != "" {
		total := 0
		for _, fd := range diffs {
			total += len(fd.Changes)
		}
		diffs = diffx.Filter(diffs, *only)
		if len(diffs) == 0 {
			fmt.Fprintf(os.Stderr, "lockvet: no changes matching -only %q (%s changed in total)\n",
				*only, plural(total, "package"))
			return
		}
	}

	// If nothing in the diff belongs to an OSV-covered ecosystem
	// (e.g. only flake.lock / Podfile.lock changed), don't claim
	// "vulnerabilities: 0" — there was nothing to check.
	anyOSV, anyMeta := false, false
	for _, fd := range diffs {
		for _, c := range fd.Changes {
			if lock.Ecosystem(c.Ecosystem).HasOSV() {
				anyOSV = true
			}
			if depsdev.Covers(c.Ecosystem) {
				anyMeta = true
			}
		}
	}

	vulnsChecked := false
	if !*noVulns && anyOSV {
		if err := osv.Annotate(diffs); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: vulnerability check skipped: %v\n", err)
		} else {
			vulnsChecked = true
		}
	}

	metaChecked := false
	if !*noMeta && anyMeta {
		if err := depsdev.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: release-metadata check skipped: %v\n", err)
		} else {
			metaChecked = true
			taglink.Annotate(diffs) // verified changelog/compare links
		}
	}

	sum := diffx.Summarize(diffs)

	switch {
	case *sarifOut:
		check(render.SARIF(os.Stdout, diffs, effectiveVersion(),
			func(p string) []byte { return newContents[p] }))
	case *jsonOut:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		check(enc.Encode(map[string]any{
			"base": base, "target": displayTarget(target),
			"files": diffs, "summary": sum,
			"vulns_checked": vulnsChecked,
			"meta_checked":  metaChecked, "fresh_days": *freshDays,
		}))
	case *md:
		render.Markdown(os.Stdout, diffs, sum, vulnsChecked, metaChecked, *freshDays)
	default:
		color := !*noColor && os.Getenv("NO_COLOR") == "" && isTTY()
		render.Terminal(os.Stdout, diffs, sum, color, vulnsChecked, metaChecked, *freshDays)
	}

	if *comment {
		var buf strings.Builder
		render.Markdown(&buf, diffs, sum, vulnsChecked, metaChecked, *freshDays)
		url, updated, err := remotePost(buf.String())
		if err != nil {
			fatal(fmt.Sprintf("could not post comment: %v", err))
		}
		verb := "posted"
		if updated {
			verb = "updated"
		}
		fmt.Fprintf(os.Stderr, "lockvet: comment %s: %s\n", verb, url)
	}

	if code := failCode(*failOn, diffs, sum); code != 0 {
		os.Exit(code)
	}
}

type queueOpts struct {
	author          string
	limit           int
	md, jsonOut     bool
	noVulns, noMeta bool
	freshDays       int
	only, failOn    string
	noColor         bool
}

// queueEntry is one open PR/MR to vet, forge-agnostic.
type queueEntry struct {
	refStr  string // canonical reference for JSON ("owner/repo#12", "group/proj!34")
	label   string // short label for the table ("#12", "repo#12", "proj!34")
	title   string
	author  string
	url     string
	updated time.Time
	fetch   func(isLockfile func(string) bool) (*ghpr.Result, error)
}

// splitQueueScope recognises a host-qualified queue scope like
// "https://gitlab.example.com/group/project" or "gitlab.com/group". A first
// path segment containing a dot is a host (GitHub owner names can't contain
// dots); anything else is a plain GitHub owner[/repo] scope.
func splitQueueScope(scope string) (host, rest string) {
	s := strings.TrimPrefix(strings.TrimPrefix(scope, "https://"), "http://")
	s = strings.Trim(s, "/")
	first, tail, found := strings.Cut(s, "/")
	if h := strings.TrimSuffix(first, ":443"); found && strings.Contains(h, ".") {
		return h, tail
	}
	return "", s
}

// runQueue implements `lockvet queue <scope>`: find every open
// dependency-update PR/MR in scope, vet each one, and print a triage table.
// Scope is a GitHub owner or owner/repo (default), or a GitLab group or
// project URL/path (host-qualified, e.g. gitlab.com/gitlab-org).
func runQueue(scope string, o queueOpts) {
	host, rest := splitQueueScope(scope)
	forge := "github"
	if host != "" && host != "github.com" {
		if gtpr.IsGiteaHost(host) {
			forge = "gitea"
		} else {
			forge = "gitlab"
		}
	}

	defaultAuthors, defaultLabel := ghpr.DefaultQueueAuthors, "dependabot + renovate"
	switch forge {
	case "gitlab":
		defaultAuthors, defaultLabel = glmr.DefaultQueueAuthors, "renovate-bot + dependabot"
	case "gitea":
		defaultAuthors, defaultLabel = gtpr.DefaultQueueAuthors, "renovate-bot + dependabot"
	}
	authors, authorLabel := defaultAuthors, defaultLabel
	switch a := strings.TrimSpace(o.author); {
	case a == "any" || a == "all" || a == "*":
		authors, authorLabel = nil, "any author"
	case a != "":
		authors = nil
		for _, part := range strings.Split(a, ",") {
			if part = strings.TrimSpace(part); part != "" {
				authors = append(authors, part)
			}
		}
		authorLabel = strings.Join(authors, ", ")
	}
	if o.limit <= 0 {
		o.limit = 30
	}

	var (
		entries []queueEntry
		qual    string
		noun    = "PRs"
	)
	switch forge {
	case "gitlab":
		noun = "MRs"
		items, label, err := glmr.ListQueue(host, rest, authors, o.limit)
		check(err)
		qual = label
		singleProject := strings.HasPrefix(label, "project:")
		for _, it := range items {
			it := it
			lbl := it.Ref.Project + "!" + fmt.Sprint(it.Ref.IID)
			if singleProject {
				lbl = "!" + fmt.Sprint(it.Ref.IID)
			} else if p, ok := strings.CutPrefix(it.Ref.Project, rest+"/"); ok {
				lbl = p + "!" + fmt.Sprint(it.Ref.IID) // relative to the group
			}
			entries = append(entries, queueEntry{
				refStr: it.Ref.String(), label: lbl,
				title: it.Title, author: it.Author, url: it.URL, updated: it.Updated,
				fetch: func(isLock func(string) bool) (*ghpr.Result, error) { return glmr.Fetch(it.Ref, isLock) },
			})
		}
		if len(items) > 5 && !glmr.HasToken() {
			fmt.Fprintf(os.Stderr, "lockvet: warning: unauthenticated GitLab API — vetting %d MRs may hit the rate limit; set GITLAB_TOKEN\n", len(items))
		}
	case "gitea":
		items, label, err := gtpr.ListQueue(host, rest, authors, o.limit)
		check(err)
		qual = label
		singleRepo := strings.Contains(rest, "/")
		for _, it := range items {
			it := it
			lbl := fmt.Sprintf("%s#%d", it.Ref.Repo, it.Ref.Index)
			if singleRepo {
				lbl = fmt.Sprintf("#%d", it.Ref.Index)
			}
			entries = append(entries, queueEntry{
				refStr: it.Ref.String(), label: lbl,
				title: it.Title, author: it.Author, url: it.URL, updated: it.Updated,
				fetch: func(isLock func(string) bool) (*ghpr.Result, error) { return gtpr.Fetch(it.Ref, isLock) },
			})
		}
		if len(items) == 0 && len(authors) > 0 && strings.TrimSpace(o.author) == "" {
			fmt.Fprintf(os.Stderr, "lockvet: hint: bot usernames vary per Gitea/Forgejo instance (Forgejo's own Renovate is %q) — try -author <username> or -author any\n", "viceice-bot")
		}
		if len(items) > 5 && !gtpr.HasToken() {
			fmt.Fprintf(os.Stderr, "lockvet: warning: unauthenticated Gitea/Forgejo API — vetting %d PRs may hit the rate limit; set GITEA_TOKEN\n", len(items))
		}
	default:
		items, label, err := ghpr.ListQueue(rest, authors, o.limit)
		check(err)
		qual = label
		singleRepo := strings.Contains(rest, "/")
		for _, it := range items {
			it := it
			lbl := fmt.Sprintf("%s#%d", it.Ref.Repo, it.Ref.Number)
			if singleRepo {
				lbl = fmt.Sprintf("#%d", it.Ref.Number)
			}
			entries = append(entries, queueEntry{
				refStr: it.Ref.String(), label: lbl,
				title: it.Title, author: it.Author, url: it.URL, updated: it.Updated,
				fetch: func(isLock func(string) bool) (*ghpr.Result, error) { return ghpr.Fetch(it.Ref, isLock) },
			})
		}
		if len(items) > 5 && !ghpr.HasToken() {
			fmt.Fprintf(os.Stderr, "lockvet: warning: unauthenticated GitHub API — vetting %d PRs may hit the rate limit; set GITHUB_TOKEN\n", len(items))
		}
	}

	// Fetch and diff every PR (a few at a time).
	type slot struct {
		diffs []diffx.FileDiff
		err   error
	}
	slots := make([]slot, len(entries))
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, it := range entries {
		wg.Add(1)
		go func(i int, it queueEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := it.fetch(func(p string) bool { return lock.ByBasename(p) != nil })
			if err != nil {
				slots[i].err = err
				return
			}
			for _, cf := range res.Files {
				parser := lock.ByBasename(cf.Path)
				oldF := parseOrNil(parser, cf.Path, cf.Old)
				newF := parseOrNil(parser, cf.Path, cf.New)
				if oldF == nil && newF == nil {
					continue
				}
				if fd := diffx.Diff(oldF, newF); len(fd.Changes) > 0 {
					slots[i].diffs = append(slots[i].diffs, fd)
				}
			}
			if o.only != "" {
				slots[i].diffs = diffx.Filter(slots[i].diffs, o.only)
			}
		}(i, it)
	}
	wg.Wait()

	// Annotate all PRs' diffs in one pass (one OSV batch, one deps.dev
	// batch — instead of one per PR).
	var combined []diffx.FileDiff
	spans := make([][2]int, len(entries))
	for i := range slots {
		spans[i][0] = len(combined)
		combined = append(combined, slots[i].diffs...)
		spans[i][1] = len(combined)
	}
	anyOSV, anyMeta := false, false
	for _, fd := range combined {
		for _, c := range fd.Changes {
			if lock.Ecosystem(c.Ecosystem).HasOSV() {
				anyOSV = true
			}
			if depsdev.Covers(c.Ecosystem) {
				anyMeta = true
			}
		}
	}
	vulnsChecked := false
	if !o.noVulns && anyOSV {
		if err := osv.Annotate(combined); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: vulnerability check skipped: %v\n", err)
		} else {
			vulnsChecked = true
		}
	}
	metaChecked := false
	if !o.noMeta && anyMeta {
		if err := depsdev.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: release-metadata check skipped: %v\n", err)
		} else {
			metaChecked = true
		}
	}

	// Build, sort, and render the rows.
	rows := make([]render.QueueRow, len(entries))
	failed := false
	for i, it := range entries {
		diffs := combined[spans[i][0]:spans[i][1]]
		rows[i] = render.QueueRow{
			Label: it.label, URL: it.url, Title: it.title, Author: it.author,
			Sum: diffx.Summarize(diffs), NoChanges: len(diffs) == 0,
		}
		if rows[i].NoChanges && o.only != "" {
			rows[i].NoChangesMsg = fmt.Sprintf("no changes matching -only %q", o.only)
		}
		if slots[i].err != nil {
			rows[i].Err = slots[i].err.Error()
		}
		if failCode(o.failOn, diffs, rows[i].Sum) != 0 {
			failed = true
		}
	}
	render.SortQueue(rows)

	heading := fmt.Sprintf("open dependency %s — %s · %s", noun, qual, authorLabel)
	if o.only != "" {
		heading += fmt.Sprintf(" · only %q", o.only)
	}
	switch {
	case o.jsonOut:
		type jsonRow struct {
			PR        string        `json:"pr"`
			URL       string        `json:"url"`
			Title     string        `json:"title"`
			Author    string        `json:"author"`
			UpdatedAt string        `json:"updated_at"`
			NoChanges bool          `json:"no_lockfile_changes"`
			Error     string        `json:"error,omitempty"`
			Summary   diffx.Summary `json:"summary"`
		}
		out := struct {
			Scope        string    `json:"scope"`
			Authors      []string  `json:"authors"`
			VulnsChecked bool      `json:"vulns_checked"`
			MetaChecked  bool      `json:"meta_checked"`
			FreshDays    int       `json:"fresh_days"`
			PRs          []jsonRow `json:"prs"`
		}{Scope: qual, Authors: authors, VulnsChecked: vulnsChecked, MetaChecked: metaChecked, FreshDays: o.freshDays}
		byLabel := map[string]queueEntry{}
		for _, it := range entries {
			byLabel[it.label] = it
		}
		for _, r := range rows {
			it := byLabel[r.Label]
			out.PRs = append(out.PRs, jsonRow{
				PR: it.refStr, URL: r.URL, Title: r.Title, Author: r.Author,
				UpdatedAt: it.updated.Format("2006-01-02T15:04:05Z07:00"),
				NoChanges: r.NoChanges, Error: r.Err, Summary: r.Sum,
			})
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		check(enc.Encode(out))
	case o.md:
		render.QueueMarkdown(os.Stdout, heading, strings.TrimSuffix(noun, "s"), rows, vulnsChecked, metaChecked, o.freshDays)
	default:
		color := !o.noColor && os.Getenv("NO_COLOR") == "" && isTTY()
		refHint := "lockvet pr <owner/repo#N>"
		switch forge {
		case "gitlab":
			refHint = "lockvet mr <group/project!N>"
		case "gitea":
			refHint = "lockvet pr <PR url>"
		}
		render.QueueTerminal(os.Stdout, heading, strings.TrimSuffix(noun, "s"), refHint, rows, color, vulnsChecked, metaChecked, o.freshDays)
	}

	if failed {
		os.Exit(1)
	}
}

func failCode(failOn string, diffs []diffx.FileDiff, sum diffx.Summary) int {
	for _, cond := range strings.Split(failOn, ",") {
		switch strings.TrimSpace(cond) {
		case "":
		case "major":
			if sum.Major > 0 {
				return 1
			}
		case "vuln", "vulns":
			if sum.VulnsIntroduced > 0 {
				return 1
			}
		case "downgrade", "downgrades":
			if sum.Downgraded > 0 {
				return 1
			}
		case "fresh":
			if sum.Fresh > 0 {
				return 1
			}
		case "deprecated":
			if sum.Deprecated > 0 {
				return 1
			}
		default:
			fatal(fmt.Sprintf("unknown -fail-on condition %q (want major, vuln, downgrade, fresh, or deprecated)", cond))
		}
	}
	return 0
}

// reorderArgs moves flags before positionals so that
// "lockvet HEAD~1 HEAD -no-vulns" works (Go's flag package stops at the
// first positional argument otherwise).
func reorderArgs(args []string) []string {
	var flags, pos []string
	takesValue := map[string]bool{
		"-fail-on": true, "-C": true, "-fresh-days": true, "-only": true,
		"--fail-on": true, "--C": true, "--fresh-days": true, "--only": true,
		"-author": true, "--author": true, "-limit": true, "--limit": true,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && a != "-" && a != "--" {
			flags = append(flags, a)
			if takesValue[a] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		pos = append(pos, a)
	}
	return append(flags, pos...)
}

func parseOrNil(parser *lock.Parser, p string, data []byte) *lock.File {
	if data == nil {
		return nil
	}
	f, err := parser.Parse(p, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lockvet: warning: could not parse %s: %v\n", path.Base(p), err)
		return nil
	}
	return f
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func displayTarget(target string) string {
	if target == "" {
		return "working tree"
	}
	return target
}

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func check(err error) {
	if err != nil {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "lockvet:", msg)
	os.Exit(2)
}

var _ = vers.Major // keep import for future flags
