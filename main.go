// lockvet — explain any lockfile change: what bumped, what's breaking,
// what's newly vulnerable. https://github.com/matteo-sung/lockvet
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	neturl "net/url"
	"os"
	"path"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/actreg"
	"github.com/matteo-sung/lockvet/internal/adopr"
	"github.com/matteo-sung/lockvet/internal/ansreg"
	"github.com/matteo-sung/lockvet/internal/bbpr"
	"github.com/matteo-sung/lockvet/internal/bzlreg"
	"github.com/matteo-sung/lockvet/internal/cargoreg"
	"github.com/matteo-sung/lockvet/internal/conanreg"
	"github.com/matteo-sung/lockvet/internal/condareg"
	"github.com/matteo-sung/lockvet/internal/cranreg"
	"github.com/matteo-sung/lockvet/internal/depsdev"
	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/flakereg"
	"github.com/matteo-sung/lockvet/internal/gemreg"
	"github.com/matteo-sung/lockvet/internal/ghpr"
	"github.com/matteo-sung/lockvet/internal/gitx"
	"github.com/matteo-sung/lockvet/internal/glmr"
	"github.com/matteo-sung/lockvet/internal/goreg"
	"github.com/matteo-sung/lockvet/internal/gradlereg"
	"github.com/matteo-sung/lockvet/internal/gtpr"
	"github.com/matteo-sung/lockvet/internal/hcache"
	"github.com/matteo-sung/lockvet/internal/helmreg"
	"github.com/matteo-sung/lockvet/internal/hexreg"
	"github.com/matteo-sung/lockvet/internal/hkgreg"
	"github.com/matteo-sung/lockvet/internal/ignore"
	"github.com/matteo-sung/lockvet/internal/jsrreg"
	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/mvnreg"
	"github.com/matteo-sung/lockvet/internal/npmreg"
	"github.com/matteo-sung/lockvet/internal/nugetreg"
	"github.com/matteo-sung/lockvet/internal/ocireg"
	"github.com/matteo-sung/lockvet/internal/orbreg"
	"github.com/matteo-sung/lockvet/internal/osv"
	"github.com/matteo-sung/lockvet/internal/phpreg"
	"github.com/matteo-sung/lockvet/internal/podreg"
	"github.com/matteo-sung/lockvet/internal/pubreg"
	"github.com/matteo-sung/lockvet/internal/pypireg"
	"github.com/matteo-sung/lockvet/internal/relnotes"
	"github.com/matteo-sung/lockvet/internal/render"
	"github.com/matteo-sung/lockvet/internal/squat"
	"github.com/matteo-sung/lockvet/internal/swiftreg"
	"github.com/matteo-sung/lockvet/internal/taglink"
	"github.com/matteo-sung/lockvet/internal/tfreg"
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

  lockvet pr <azure devops PR url>    vet an Azure DevOps pull request
                                      (dev.azure.com or Server). Uses
                                      AZURE_DEVOPS_TOKEN / SYSTEM_ACCESSTOKEN.

  lockvet compare <o>/<r> <a>...<b>   vet any two revisions of a GitHub,
  lockvet <compare url>               GitLab, Bitbucket, Gitea/Forgejo, or
  lockvet <commit url>                Azure DevOps repo, or a single commit,
                                      without cloning.

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

  lockvet queue <bitbucket ws url>    same for a Bitbucket Cloud workspace
  lockvet queue <bitbucket repo url>  or repo, e.g. lockvet queue
                                      bitbucket.org/atlassian. Author specs
                                      also match bot display names loosely.

  lockvet queue <azure project url>   same for an Azure DevOps project or
  lockvet queue <azure repo url>      repo, e.g. lockvet queue
                                      dev.azure.com/ORG/PROJECT[/_git/REPO].

  lockvet audit [path ...]            vet what the lockfiles pin RIGHT NOW,
                                      not a change: every pinned version that
                                      is affected by a known advisory,
                                      missing from its registry's index
                                      (unpublished/pulled — often malicious —
                                      releases), deprecated/retracted/yanked
                                      upstream, or published only days ago.
                                      Walks the tree for all 50 formats
                                      (node_modules/vendor skipped).

  lockvet pkg <eco>:<name>[@version]  vet a package BEFORE you install it —
                                      advisories (incl. malicious-package
                                      records), release age, deprecation/
                                      retraction/yank, versions missing from
                                      the registry index, typosquat
                                      suspicion. No version = the registry's
                                      latest. e.g. lockvet pkg npm:left-pad
                                      pypi:requests@2.32.0 cargo:serde
                                      go:github.com/gin-gonic/gin

  lockvet diff <old> <new>            vet two files on disk, no git needed —
                                      two lockfiles, or two SBOMs (CycloneDX
                                      or SPDX JSON, any mix), e.g. syft scans
                                      of two container images.

  lockvet mcp                         run as a Model Context Protocol
                                      server (stdio) so AI assistants and
                                      coding agents can vet lockfile
                                      changes: tools vet_url, vet_git,
                                      vet_files, audit, and queue.

  lockvet completion bash|zsh|fish    print a shell completion script.
  lockvet man                         print the manual page (roff).

FLAGS
  -md            markdown output (for PR comments)
  -json          JSON output
  -sarif         SARIF 2.1.0 output (GitHub Code Scanning: vulnerable,
                 unresolved, and deprecated incoming versions become alerts
                 on the exact lockfile line)
  -no-vulns      skip the OSV.dev vulnerability check
  -no-meta       skip the deps.dev metadata check (release age, deprecations)
                 and upstream changelog/diff links
  -offline       no network calls at all (= -no-vulns -no-meta). With
                 -osv-db the vulnerability check still runs, from disk
  -osv-db DIR    use local OSV databases under DIR (the per-ecosystem
                 all.zip files from osv.dev's export) instead of
                 api.osv.dev. Missing or stale ecosystems are downloaded
                 automatically unless -offline is set, so one run with
                 network prepares an air-gapped one. env: LOCKVET_OSV_DB
  -no-cache      don't read or write the on-disk response cache. Registry
                 and advisory answers are cached for 1h under
                 ~/.cache/lockvet (LOCKVET_CACHE_DIR overrides) so repeat
                 runs are fast; forge data (PR contents) is never cached
  -cache-ttl D   how long cached registry/advisory answers stay fresh
                 (default 1h; 0 disables the cache)
  -fresh-days N  flag versions published fewer than N days ago (default 7;
                 0 shows ages but never flags)
  -changelogs    fetch upstream release notes for every bump (incl. the
                 releases a multi-version jump skips over) and show them
                 inline. GitHub Releases first, then the repo's changelog
                 file (CHANGELOG/CHANGES/NEWS/HISTORY) at the verified tag;
                 GITHUB_TOKEN / gh login raises the releases-API rate limit
  -only PAT      show one package's story: only changes whose name — or any
                 package in their "via" chain — matches PAT. Glob, case-
                 insensitive, comma list ok: -only jiff, -only "@babel/*"
  -comment       (pr / mr modes) post the report as a comment on the pull or
                 merge request — reruns update the same comment in place.
                 Needs GITHUB_TOKEN / gh login, GITLAB_TOKEN (api scope), or
                 BITBUCKET_TOKEN / app password (pullrequest:write).
  -fail-on X     exit 1 if the diff contains X: "major", "vuln", "downgrade",
                 "fresh", "deprecated", "unlisted", "typosquat", "scripts",
                 "provenance", "integrity", "registry", or "license"
                 (repeatable as comma list: -fail-on major,vuln,fresh)
  -ignore-file F acknowledged findings that skip the summary and -fail-on
                 (default: .lockvetignore next to the lockfiles, if present;
                 one rule per line: an advisory ID, pkg[@version], or
                 kind:pkg[@version] with optional until=YYYY-MM-DD)
  -no-ignore     ignore no findings even if .lockvetignore exists
  -author LIST   (queue mode) bot accounts to search for, comma list
                 (GitHub default "app/dependabot,app/renovate"; GitLab and
                 Gitea/Forgejo default "renovate-bot,dependabot"; "any" =
                 every open PR/MR that touches a lockfile)
  -limit N       (queue mode) vet at most N pull/merge requests (default 30)
  -C dir         run as if started in dir
  -no-color      disable colors (also respects NO_COLOR)
  -version       print version

SUPPORTED LOCKFILES
  ` + strings.Join(lock.KnownBasenames(), ", ") + `,
  *.cdx.json, *.spdx.json (SBOMs: multi-ecosystem, incl. Alpine/Debian
  container packages when the purl says which release)

Every ecosystem in one binary.
Data: https://osv.dev (vulnerabilities) · https://deps.dev (release metadata)
`

func main() {
	var (
		md         = flag.Bool("md", false, "")
		jsonOut    = flag.Bool("json", false, "")
		sarifOut   = flag.Bool("sarif", false, "")
		noVulns    = flag.Bool("no-vulns", false, "")
		noMeta     = flag.Bool("no-meta", false, "")
		offline    = flag.Bool("offline", false, "")
		freshDays  = flag.Int("fresh-days", 7, "")
		changelogs = flag.Bool("changelogs", false, "")
		only       = flag.String("only", "", "")
		author     = flag.String("author", "", "")
		limit      = flag.Int("limit", 30, "")
		comment    = flag.Bool("comment", false, "")
		failOn     = flag.String("fail-on", "", "")
		ignoreFile = flag.String("ignore-file", "", "")
		noIgnore   = flag.Bool("no-ignore", false, "")
		noCache    = flag.Bool("no-cache", false, "")
		cacheTTL   = flag.Duration("cache-ttl", hcache.DefaultTTL, "")
		dir        = flag.String("C", ".", "")
		noColor    = flag.Bool("no-color", false, "")
		showVer    = flag.Bool("version", false, "")
		osvDB      = flag.String("osv-db", "", "")
	)
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.CommandLine.Parse(reorderArgs(os.Args[1:]))

	if *showVer {
		fmt.Println("lockvet", effectiveVersion())
		return
	}
	if *osvDB == "" {
		*osvDB = os.Getenv("LOCKVET_OSV_DB")
	}
	if *offline {
		*noMeta = true
		if *osvDB == "" {
			*noVulns = true // no local database: nothing to check against
		}
	}
	if *osvDB != "" && !*noVulns {
		osv.UseLocal(*osvDB, !*offline)
	}
	hcache.Configure(*noCache, *cacheTTL)
	if *changelogs && *noMeta {
		fatal("-changelogs needs the deps.dev metadata pass (it supplies each package's source repo) — drop -no-meta/-offline")
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
	setADO := func(ref adopr.Ref) {
		remoteFetch = func(f func(string) bool) (*ghpr.Result, error) { return adopr.Fetch(ref, f) }
		remoteWhat = ref.String()
		remotePost = func(body string) (string, bool, error) { return adopr.PostComment(ref, body) }
	}
	setADOCmp := func(ref adopr.CmpRef) {
		remoteFetch = func(f func(string) bool) (*ghpr.Result, error) { return adopr.FetchCompare(ref, f) }
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
	var fileOld, fileNew string // `lockvet diff <old> <new>` file mode

	switch {
	case len(args) > 0 && args[0] == "mcp":
		runMCP()
		return
	case len(args) > 0 && args[0] == "completion":
		runCompletion(args[1:])
		return
	case len(args) > 0 && args[0] == "man":
		runMan()
		return
	case len(args) > 0 && args[0] == "audit":
		if *comment {
			fatal("-comment needs a pull or merge request to comment on — audit reports have no PR; pipe -md wherever you need it")
		}
		if *changelogs {
			fatal("-changelogs is not available in audit mode — there is no bump whose release notes would explain anything")
		}
		runAudit(args[1:], *dir, vetOptions{only: *only, freshDays: *freshDays, noVulns: *noVulns, noMeta: *noMeta,
			ignoreFile: *ignoreFile, noIgnore: *noIgnore},
			*md, *jsonOut, *sarifOut, *noColor, *failOn)
		return
	case len(args) > 0 && args[0] == "pkg":
		if len(args) < 2 {
			fatal("usage: lockvet pkg <ecosystem>:<name>[@version] ...   (e.g. lockvet pkg npm:left-pad pypi:requests@2.32.0)")
		}
		if *comment {
			fatal("-comment needs a pull or merge request to comment on — pkg reports have no PR; pipe -md wherever you need it")
		}
		if *sarifOut {
			fatal("-sarif needs a lockfile to anchor alerts to — pkg mode vets a package that is not pinned anywhere yet; use -json or -md")
		}
		runPkg(args[1:], vetOptions{only: *only, freshDays: *freshDays, noVulns: *noVulns, noMeta: *noMeta,
			changelogs: *changelogs, ignoreFile: *ignoreFile, noIgnore: *noIgnore},
			*md, *jsonOut, *noColor, *failOn)
		return
	case len(args) > 0 && args[0] == "diff":
		if len(args) != 3 {
			fatal("usage: lockvet diff <old-file> <new-file>   (two lockfiles, or two CycloneDX/SPDX JSON SBOMs)")
		}
		fileOld, fileNew = args[1], args[2]
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
		if *changelogs {
			fatal("-changelogs is not available in queue mode — run lockvet pr <url> -changelogs per PR")
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
		} else if ref, ok := adopr.Parse(args[1]); ok {
			setADO(ref)
		} else if ref, ok := ghpr.Parse(args[1]); ok {
			setPR(ref)
		} else if ref, ok := glmr.ParseMR(args[1]); ok {
			setMR(ref)
		} else if ref, ok := gtpr.Parse(args[1]); ok {
			setGT(ref)
		} else {
			fatal(fmt.Sprintf("cannot parse %q as a pull/merge request (want owner/repo#N, group/project!N, or a GitHub/GitLab/Bitbucket/Gitea/Azure DevOps url)", args[1]))
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
			} else if ref, ok := adopr.ParseCompare(args[1]); ok {
				setADOCmp(ref)
			} else if inst, proj, repo, sha, ok := adopr.ParseCommit(args[1]); ok {
				ref, err := adopr.ResolveCommit(inst, proj, repo, sha)
				check(err)
				setADOCmp(ref)
			} else if ref, ok := gtpr.ParseCommit(args[1]); ok {
				setGTCommit(ref)
			} else if ref, ok := gtpr.ParseCompare(args[1]); ok {
				setGTCmp(ref)
			} else {
				fatal(fmt.Sprintf("cannot parse %q (want a GitHub/GitLab/Bitbucket/Gitea/Azure DevOps compare/commit url, or: lockvet compare owner/repo base...head)", args[1]))
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
	case len(args) == 1 && strings.Contains(args[0], "/_git/"):
		// Azure DevOps web URLs (dev.azure.com, *.visualstudio.com, or
		// self-hosted Server) all put /_git/ before the repository name.
		if ref, ok := adopr.Parse(args[0]); ok {
			setADO(ref)
		} else if ref, ok := adopr.ParseCompare(args[0]); ok {
			setADOCmp(ref)
		} else if inst, proj, repo, sha, ok := adopr.ParseCommit(args[0]); ok {
			ref, err := adopr.ResolveCommit(inst, proj, repo, sha)
			check(err)
			setADOCmp(ref)
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
		res, err := remoteFetch(lock.PathFilter(lock.SniffBudget))
		check(err)
		for _, w := range res.Warnings {
			fmt.Fprintf(os.Stderr, "lockvet: warning: %s\n", w)
		}
		lock.CIInstanceHost = res.CIHost // GitLab fetches name their instance
		defer func() { lock.CIInstanceHost = "" }()
		base, target = res.BaseLabel, res.HeadLabel
		for _, cf := range res.Files {
			parser := lock.ByBasename(cf.Path)
			if parser == nil {
				// Admitted by the sniff side of the path filter.
				parser = lock.SniffParser()
			}
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
	} else if fileNew != "" {
		// File mode: two files on disk, no git. Format from the filename
		// when recognizable, otherwise SBOM content sniffing.
		// Format from the file's own name when recognizable; otherwise the
		// other file's (so "Cargo.lock.old" vs "Cargo.lock" works); SBOM
		// content sniffing as the last resort.
		pOld, pNew := lock.ByBasename(fileOld), lock.ByBasename(fileNew)
		if pOld == nil {
			pOld = pNew
		}
		if pNew == nil {
			pNew = pOld
		}
		parseFile := func(p string, parser *lock.Parser) (*lock.File, []byte) {
			data, err := os.ReadFile(p)
			check(err)
			if parser == nil {
				parser = lock.FallbackParser(p)
			}
			f, err := parser.Parse(p, data)
			if err != nil {
				fatal(fmt.Sprintf("%s: %v\nhint: lockvet diff wants two lockfiles with their usual names (one side may carry a suffix, e.g. Cargo.lock.orig vs Cargo.lock), or CycloneDX/SPDX JSON SBOMs under any filename", p, err))
			}
			return f, data
		}
		oldF, _ := parseFile(fileOld, pOld)
		newF, newData := parseFile(fileNew, pNew)
		base, target = fileOld, fileNew
		fd := diffx.Diff(oldF, newF)
		if len(fd.Changes) == 0 {
			fmt.Fprintf(os.Stderr, "lockvet: no changes between %s and %s\n", fileOld, fileNew)
			return
		}
		diffs = append(diffs, fd)
		newContents[fileNew] = newData
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
		if err != nil {
			fatal(fmt.Sprintf("%v\n\nlockvet's default mode diffs lockfiles in a git repository. Outside one, try:\n"+
				"  lockvet audit .              vet what a directory already pins\n"+
				"  lockvet pr <url>             vet a pull request, no clone needed\n"+
				"  lockvet diff <old> <new>     vet two lockfiles on disk\n"+
				"  lockvet -h                   everything else", err))
		}
		check(repo.ResolveRev(base))
		if target != "" {
			check(repo.ResolveRev(target))
		}

		changed, err := repo.ChangedFiles(base, target)
		check(err)

		for _, p := range changed {
			parser := lock.ByBasename(p)
			if parser == nil {
				if !lock.SniffableYAML(p) {
					continue
				}
				// Unclaimed YAML in a diff: content-sniff it as a
				// Kubernetes manifest (strict apiVersion+kind gate;
				// anything else parses to an empty file).
				parser = lock.SniffParser()
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

	metaChecked := false
	if !*noMeta {
		// Resolve workflow pins before the vulnerability check: OSV
		// ranges for GitHub Actions are evaluated client-side against
		// the releases actreg resolves each pin to.
		if ok, err := actreg.Annotate(diffs); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: action tag check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := swiftreg.Annotate(diffs); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: swift tag check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
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

	if !*noMeta && anyMeta {
		if err := depsdev.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: release-metadata check skipped: %v\n", err)
		} else {
			metaChecked = true
		}
	}
	if !*noMeta {
		// deps.dev has no Composer system: for PHP, Packagist itself is
		// the metadata layer (ages, abandoned, licenses, unlisted).
		if ok, err := phpreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Packagist registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := hexreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: hex.pm registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := pubreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: pub.dev registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := jsrreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: jsr.io registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := podreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: CocoaPods registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := tfreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Terraform registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := helmreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Helm chart repository check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := ansreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Ansible Galaxy check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := orbreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: orb registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := conanreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: ConanCenter registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := cranreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: CRAN registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := hkgreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Hackage registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := bzlreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Bazel Central Registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := gradlereg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Gradle version-index check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := condareg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: anaconda.org registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := ocireg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: image registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if metaChecked || anyZigChanges(diffs) {
			// build.zig.zon has no registry layer: the repo's own tags
			// (taglink) ARE the metadata source for Zig-only diffs.
			taglink.Annotate(diffs) // verified changelog/compare links
			if *changelogs {
				for _, w := range relnotes.Annotate(diffs, ghpr.Token()) {
					fmt.Fprintf(os.Stderr, "lockvet: warning: %s\n", w)
				}
			}
		}
		if err := npmreg.Annotate(diffs); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: install-script check skipped: %v\n", err)
		}
		if err := pypireg.Annotate(diffs); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: PyPI registry check skipped: %v\n", err)
		}
		if err := cargoreg.Annotate(diffs); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: crates.io registry check skipped: %v\n", err)
		}
		if err := gemreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: RubyGems registry check skipped: %v\n", err)
		}
		if err := nugetreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: NuGet registry check skipped: %v\n", err)
		}
		if err := goreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Go module proxy check skipped: %v\n", err)
		}
		if err := mvnreg.Annotate(diffs, *freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Maven repository check skipped: %v\n", err)
		}
	}
	// The typosquat check is fully local (embedded popularity lists) — it
	// runs even with -no-meta/-offline; with ages unknown the young-release
	// gate honestly passes everything through. Last so it can use ages when
	// the metadata layers did run.
	// Flake input ages + rev...rev compare links come from the lockfile
	// itself — fully local, so this runs even with -no-meta/-offline.
	flakereg.Annotate(diffs, *freshDays)
	squat.Annotate(diffs)

	ignSet, err := ignore.Resolve(*ignoreFile, *noIgnore, *dir)
	check(err)
	if _, warns := ignSet.Apply(diffs, time.Now()); len(warns) > 0 {
		for _, w := range warns {
			fmt.Fprintf(os.Stderr, "lockvet: warning: %s\n", w)
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
// splitADOQueueScope turns a queue scope host+rest into an Azure DevOps
// instance URL, project, and optional repo (URL path segments, kept
// percent-encoded). dev.azure.com scopes are ORG/PROJECT[/_git/REPO];
// *.visualstudio.com scopes are PROJECT[/_git/REPO].
func splitADOQueueScope(host, rest string) (instance, project, repo string, ok bool) {
	segs := strings.Split(strings.Trim(rest, "/"), "/")
	if strings.EqualFold(host, "dev.azure.com") {
		if len(segs) < 2 || segs[0] == "" {
			return "", "", "", false
		}
		instance = "https://dev.azure.com/" + segs[0]
		segs = segs[1:]
	} else {
		instance = "https://" + host
	}
	if len(segs) == 0 || segs[0] == "" {
		return "", "", "", false
	}
	project = segs[0]
	segs = segs[1:]
	if len(segs) > 0 && segs[0] == "_git" {
		segs = segs[1:]
	}
	switch {
	case len(segs) == 0:
		return instance, project, "", true
	case len(segs) == 1 && segs[0] != "":
		return instance, project, segs[0], true
	}
	return "", "", "", false
}

// adoPathLabel decodes a percent-encoded Azure DevOps path segment for
// display.
func adoPathLabel(seg string) string {
	if u, err := neturl.PathUnescape(seg); err == nil {
		return u
	}
	return seg
}

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
	failed, err := queueRun(scope, o, os.Stdout)
	check(err)
	if failed {
		os.Exit(1)
	}
}

// queueRun is runQueue's reusable core: it writes the report to w and
// returns instead of exiting (the MCP server uses it too). Warnings and
// hints still go to stderr.
func queueRun(scope string, o queueOpts, w io.Writer) (failed bool, err error) {
	host, rest := splitQueueScope(scope)
	forge := "github"
	switch {
	case strings.EqualFold(host, "bitbucket.org"):
		forge = "bitbucket"
	case strings.EqualFold(host, "dev.azure.com"), strings.HasSuffix(strings.ToLower(host), ".visualstudio.com"):
		forge = "ado"
	case host != "" && host != "github.com":
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
	case "bitbucket":
		defaultAuthors, defaultLabel = bbpr.DefaultQueueAuthors, "renovate-bot + dependabot"
	case "ado":
		defaultAuthors, defaultLabel = adopr.DefaultQueueAuthors, "dependabot + renovate"
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
		if err != nil {
			return false, err
		}
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
		if err != nil {
			return false, err
		}
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
	case "bitbucket":
		items, label, note, err := bbpr.ListQueue(rest, authors, o.limit)
		if err != nil {
			return false, err
		}
		qual = label
		if note != "" {
			fmt.Fprintf(os.Stderr, "lockvet: note: %s\n", note)
		}
		singleRepo := strings.Contains(rest, "/")
		for _, it := range items {
			it := it
			lbl := fmt.Sprintf("%s#%d", it.Ref.Repo, it.Ref.ID)
			if singleRepo {
				lbl = fmt.Sprintf("#%d", it.Ref.ID)
			}
			entries = append(entries, queueEntry{
				refStr: it.Ref.String(), label: lbl,
				title: it.Title, author: it.Author, url: it.URL, updated: it.Updated,
				fetch: func(isLock func(string) bool) (*ghpr.Result, error) { return bbpr.Fetch(it.Ref, isLock) },
			})
		}
		if len(items) == 0 && len(authors) > 0 && strings.TrimSpace(o.author) == "" {
			fmt.Fprintf(os.Stderr, "lockvet: hint: Bitbucket bots often run as app users with only a display name — author specs match display names as substrings; try -author <name or {uuid}> or -author any\n")
		}
		if len(items) > 5 && !bbpr.HasToken() {
			fmt.Fprintf(os.Stderr, "lockvet: warning: unauthenticated Bitbucket API — vetting %d PRs may hit the rate limit; set BITBUCKET_TOKEN\n", len(items))
		}
	case "ado":
		instance, project, repo, ok := splitADOQueueScope(host, rest)
		if !ok {
			return false, fmt.Errorf("cannot parse the Azure DevOps queue scope — want dev.azure.com/ORG/PROJECT or dev.azure.com/ORG/PROJECT/_git/REPO")
		}
		items, label, err := adopr.ListQueue(instance, project, repo, authors, o.limit)
		if err != nil {
			return false, err
		}
		qual = label
		for _, it := range items {
			it := it
			lbl := fmt.Sprintf("%s#%d", adoPathLabel(it.Ref.Repo), it.Ref.ID)
			if repo != "" {
				lbl = fmt.Sprintf("#%d", it.Ref.ID)
			}
			entries = append(entries, queueEntry{
				refStr: it.Ref.String(), label: lbl,
				title: it.Title, author: it.Author, url: it.URL, updated: it.Updated,
				fetch: func(isLock func(string) bool) (*ghpr.Result, error) { return adopr.Fetch(it.Ref, isLock) },
			})
		}
		if len(items) == 0 && len(authors) > 0 && strings.TrimSpace(o.author) == "" {
			fmt.Fprintf(os.Stderr, "lockvet: hint: bot identities vary on Azure DevOps — author specs match display names as substrings; try -author <display name> or -author any\n")
		}
		if len(items) > 5 && !adopr.HasToken() {
			fmt.Fprintf(os.Stderr, "lockvet: warning: unauthenticated Azure DevOps API — vetting %d PRs may hit the rate limit; set AZURE_DEVOPS_TOKEN\n", len(items))
		}
	default:
		items, label, err := ghpr.ListQueue(rest, authors, o.limit)
		if err != nil {
			return false, err
		}
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
	if forge == "gitlab" {
		// One queue = one instance: every MR's $CI_SERVER_FQDN component
		// pins resolve against the queue's own host. Set before the
		// workers start (they only read it), cleared after they finish.
		lock.CIInstanceHost = host
		defer func() { lock.CIInstanceHost = "" }()
	}
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for i, it := range entries {
		wg.Add(1)
		go func(i int, it queueEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res, err := it.fetch(lock.PathFilter(lock.SniffBudget))
			if err != nil {
				slots[i].err = err
				return
			}
			for _, cf := range res.Files {
				parser := lock.ByBasename(cf.Path)
				if parser == nil {
					parser = lock.SniffParser()
				}
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
	metaChecked := false
	if !o.noMeta {
		// Resolve workflow pins before the vulnerability check (queue
		// PRs bump `uses:` pins constantly).
		if ok, err := actreg.Annotate(combined); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: action tag check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := swiftreg.Annotate(combined); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: swift tag check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
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
	if !o.noMeta && anyMeta {
		if err := depsdev.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: release-metadata check skipped: %v\n", err)
		} else {
			metaChecked = true
		}
	}
	if !o.noMeta {
		if ok, err := phpreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Packagist registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := hexreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: hex.pm registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := pubreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: pub.dev registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := jsrreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: jsr.io registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := podreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: CocoaPods registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := tfreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Terraform registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := helmreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Helm chart repository check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := ansreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Ansible Galaxy check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := orbreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: orb registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := conanreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: ConanCenter registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := cranreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: CRAN registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := hkgreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Hackage registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := bzlreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Bazel Central Registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := gradlereg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Gradle version-index check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := condareg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: anaconda.org registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if ok, err := ocireg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: image registry check skipped: %v\n", err)
		} else if ok {
			metaChecked = true
		}
		if err := npmreg.Annotate(combined); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: install-script check skipped: %v\n", err)
		}
		if err := pypireg.Annotate(combined); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: PyPI registry check skipped: %v\n", err)
		}
		if err := cargoreg.Annotate(combined); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: crates.io registry check skipped: %v\n", err)
		}
		if err := gemreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: RubyGems registry check skipped: %v\n", err)
		}
		if err := nugetreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: NuGet registry check skipped: %v\n", err)
		}
		if err := goreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Go module proxy check skipped: %v\n", err)
		}
		if err := mvnreg.Annotate(combined, o.freshDays); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: Maven repository check skipped: %v\n", err)
		}
	}
	flakereg.Annotate(combined, o.freshDays) // fully local, like squat below
	squat.Annotate(combined)                 // fully local; runs even with -no-meta/-offline

	// Build, sort, and render the rows.
	rows := make([]render.QueueRow, len(entries))
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
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return failed, err
		}
	case o.md:
		render.QueueMarkdown(w, heading, strings.TrimSuffix(noun, "s"), rows, vulnsChecked, metaChecked, o.freshDays)
	default:
		color := !o.noColor && os.Getenv("NO_COLOR") == "" && isTTY()
		refHint := "lockvet pr <owner/repo#N>"
		switch forge {
		case "gitlab":
			refHint = "lockvet mr <group/project!N>"
		case "gitea", "bitbucket", "ado":
			refHint = "lockvet pr <PR url>"
		}
		render.QueueTerminal(w, heading, strings.TrimSuffix(noun, "s"), refHint, rows, color, vulnsChecked, metaChecked, o.freshDays)
	}

	return failed, nil
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
		case "unlisted":
			if sum.Unlisted > 0 {
				return 1
			}
		case "typosquat", "typosquats":
			if sum.Typosquats > 0 {
				return 1
			}
		case "scripts", "install-scripts":
			if sum.ScriptsAdded > 0 {
				return 1
			}
		case "provenance":
			if sum.ProvenanceDropped > 0 {
				return 1
			}
		case "integrity":
			if sum.IntegrityChanged > 0 || sum.TagMismatch > 0 {
				return 1
			}
		case "registry", "resolution":
			if sum.RegistryMoved > 0 {
				return 1
			}
		case "license":
			if sum.LicenseChanged > 0 {
				return 1
			}
		default:
			fatal(fmt.Sprintf("unknown -fail-on condition %q (want major, vuln, downgrade, fresh, deprecated, unlisted, typosquat, scripts, provenance, integrity, registry, or license)", cond))
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
		"-fail-on": true, "-C": true, "-fresh-days": true, "-only": true, "-ignore-file": true,
		"--fail-on": true, "--C": true, "--fresh-days": true, "--only": true, "--ignore-file": true,
		"-author": true, "--author": true, "-limit": true, "--limit": true,
		"-cache-ttl": true, "--cache-ttl": true, "-osv-db": true, "--osv-db": true,
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
