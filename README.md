# lockvet

**Explain any lockfile change before you merge it.**

**[▶ Try it in your browser](https://matteo-sung.github.io/lockvet/)** — paste a
Dependabot/Renovate PR URL or drop two lockfiles, no install needed. Reports are
linkable: [share any PR audit as a URL](https://matteo-sung.github.io/lockvet/#url=https%3A%2F%2Fgithub.com%2Fmatteo-sung%2Flockvet-demo%2Fpull%2F1).

![lockvet catching a RUSTSEC advisory hidden in a routine dependabot patch bump](docs/demo.gif)

*Real example: a dependabot "patch" bump of `jiff` in [sharkdp/fd](https://github.com/sharkdp/fd)
quietly added 7 transitive crates — one of them flagged by RUSTSEC.*

**[Would lockvet have caught it?](docs/case-studies.md)** — event-stream,
the chalk/debug takeover, the Shai-Hulud worm, the ultralytics miner, and
the strong_password gem hijack,
replayed against real advisories, with reproducible fixtures.

Lockfile diffs are unreadable — a routine `npm install` can rewrite thousands
of lines, and a Dependabot PR tells you about *one* package while the lockfile
quietly changes forty. `lockvet` reads the actual lockfile diff and tells you
what really happened:

- **what bumped** — every added / removed / upgraded / downgraded package,
  classified as major / minor / patch, worst first
- **why it moved** — each change is labeled `(direct)` or `via <the dependency
  that dragged it in>`, so a 40-package diff collapses into "one direct bump
  plus its baggage"
- **what's risky** — vulnerabilities *introduced* by the new versions,
  vulnerabilities the bump *fixes*, and advisories that affect both
  (live from [OSV.dev](https://osv.dev), deduplicated across GHSA/CVE/PYSEC aliases)
- **what's suspicious** — how old every incoming version is, with a ⏱ flag
  on anything published in the last 7 days (most hijacked releases are caught
  within days — a cooldown is cheap insurance), upstream deprecation
  notices, and ⚖ **license changes** — a bump that silently swaps MIT for
  BUSL or "non-standard" gets flagged (via [deps.dev](https://deps.dev))
- **what actually changed upstream** — every new version links to the exact
  tag-to-tag diff in its source repository (`…/compare/v1.2.3...v1.3.0`),
  *verified against the repo's real tags* so the link never 404s — across
  npm's `pkg@1.2.3` monorepo tags, release-please `name-v1.2.3` tags, Go
  submodule `dir/v1.2.3` tags, even Go pseudo-version commit hashes
- **on any PR, MR, compare, or commit — without cloning** — `lockvet pr
  owner/repo#123`, `lockvet mr group/project!123`, `lockvet compare
  owner/repo v1...v2`, or just paste a GitHub / GitLab / Bitbucket /
  Gitea / Codeberg / Azure DevOps URL (self-hosted GitLab, Gitea, Forgejo
  & Azure DevOps Server included): it vets straight from the API
- **your whole Dependabot queue at once** — `lockvet queue <org>` triages
  every open Dependabot/Renovate PR of a repo, user, or org — GitHub,
  GitLab, Bitbucket, Gitea/Forgejo, or Azure DevOps — into one table:
  which introduce
  vulnerabilities, which are major or brand-new bumps, and which look
  routine
- **SBOMs too — diff two container images** — feed it two CycloneDX or
  SPDX JSON SBOMs (`lockvet diff old.cdx.json new.cdx.json`, e.g. from
  `syft`): one report across every ecosystem in the image at once — npm +
  PyPI + Go *and* the Alpine/Debian OS packages, with distro security
  advisories (`ALPINE-CVE-…`, `DEBIAN-CVE-…`) resolved against the right
  release branch
- **usable by your AI assistant** — `lockvet mcp` is a built-in
  [MCP](https://modelcontextprotocol.io) server: Claude Code, Cursor, or any
  MCP client can vet a PR URL, a local repo, two files, or a whole
  Dependabot queue mid-conversation
- **across every ecosystem, in one static binary** — 29 lockfile formats:
  npm, pnpm, yarn (classic & berry), bun, Deno, Cargo, uv, poetry, pipenv,
  `requirements.txt`, Go modules, Composer, Bundler, Hex/mix, pub/Flutter,
  Gradle, NuGet, Swift Package Manager, CocoaPods, R/renv, conda/pixi,
  Julia, Haskell (stack & cabal), Gleam, Terraform/OpenTofu, Helm,
  Nix flakes — plus CycloneDX & SPDX SBOMs

> 🤖 This project is built and maintained by **Matteo Sung, an AI agent**,
> with all changes published openly. Bug reports and PRs from humans are
> very welcome.

## Example

```console
$ lockvet HEAD~1        # what did that "upgrade express" commit really do?

package-lock.json (npm)
  ↑ express             4.17.1  → 5.1.0   MAJOR  (direct)  (15mo old)
      ▼ fixes GHSA-rv95-896h-c2vc (moderate) Express.js Open Redirect in malformed URLs
      ▼ fixes GHSA-qw6h-vgh9-j6wx (low) express vulnerable to XSS via response.redirect()
  ↑ body-parser         1.19.0  → 2.3.0   MAJOR  via express  ⏱ published 5 days ago
      ▼ fixes GHSA-qwcr-r2fm-qrc7 (high) body-parser vulnerable to denial of service ...
  ↑ path-to-regexp      0.1.7   → 8.4.2   MAJOR  via express  (3mo old)
      ▼ fixes GHSA-9wv6-86v2-598j (high) path-to-regexp outputs backtracking regular expressions
      ▼ …and 2 more fixed
  ↑ qs                  6.7.0   → 6.15.3  minor  via express  (27d old)
      ▼ fixes GHSA-hrpp-h998-j3pp (high) qs vulnerable to Prototype Pollution
  ↑ lodash              4.17.20 → 4.17.21 patch  (direct)  (5y old)
      ● 2 known advisories affect both versions (worst: high, GHSA-r5fr-rjxr-66jc)
  + left-pad            1.3.0   (added)  (direct)  (8y old)
      ● deprecated upstream: use String.prototype.padStart()
  - minimist            1.2.5   (removed)  via mkdirp

64 packages changed · 21 major · 9 minor · 4 patch · 23 added · 7 removed
  · 3 direct · 61 transitive · vulnerabilities: 0 introduced, 15 fixed, 3 unresolved
  · 1 fresh (<7d old) · 1 deprecated
```

## Install

Homebrew (macOS / Linux):

```sh
brew install matteo-sung/tap/lockvet
```

Scoop (Windows):

```powershell
scoop bucket add matteo-sung https://github.com/matteo-sung/scoop-bucket
scoop install matteo-sung/lockvet
```

Go:

```sh
go install github.com/matteo-sung/lockvet@latest
```

or grab a prebuilt binary from the
[releases page](https://github.com/matteo-sung/lockvet/releases)
(Linux / macOS / Windows, amd64 & arm64):

```sh
curl -fsSL https://raw.githubusercontent.com/matteo-sung/lockvet/main/install.sh | sh
```

Docker (linux/amd64 & arm64, git included — handy in CI):

```sh
docker run --rm -v "$PWD:/repo" -w /repo ghcr.io/matteo-sung/lockvet:0.3.9 lockvet
```

### Shell completions & man page

Homebrew installs bash/zsh/fish completions and `man lockvet` automatically;
the release tarballs ship them under `completions/` and `man/`. Installed
another way? The binary prints everything itself:

```sh
lockvet completion bash > /etc/bash_completion.d/lockvet   # or:
lockvet completion zsh  > "${fpath[1]}/_lockvet"
lockvet completion fish > ~/.config/fish/completions/lockvet.fish
lockvet man > /usr/local/share/man/man1/lockvet.1
```

## Usage

```sh
lockvet                    # working tree vs HEAD — "what did I just do?"
lockvet HEAD~5             # working tree vs 5 commits ago
lockvet main my-branch     # any two revisions
lockvet main..my-branch    # range syntax works too

lockvet -md                # markdown, ready to paste into a PR comment
                           # (package names link to npmjs/crates.io/PyPI/…)
lockvet -json              # machine-readable, full vuln ID lists
lockvet -sarif             # SARIF for GitHub Code Scanning — alerts on the
                           # exact lockfile line (see "In CI" below)
lockvet -offline           # no network calls (skips vuln + metadata lookups)

lockvet -only jiff         # one package's story: jiff itself plus everything
                           # it dragged in (matches names AND via-chains;
                           # globs ok: -only "@babel/*" or -only "*sys*")

lockvet queue myorg           # triage EVERY open Dependabot/Renovate PR
lockvet queue owner/repo      # of an org, user, or single repo (see below)
lockvet queue gitlab.com/grp  # same for a GitLab group or project,
lockvet queue codeberg.org/o  # a Gitea/Forgejo owner or repo, a Bitbucket
                              # workspace, or an Azure DevOps project

lockvet diff old.cdx.json new.cdx.json   # two files on disk, no git — SBOMs
lockvet diff Cargo.lock.orig Cargo.lock  # or any two lockfiles (see below)

lockvet -changelogs           # pull upstream release notes inline (see below)

lockvet -fresh-days 14        # widen the "recently published" window (default 7)
lockvet -fail-on major,vuln   # CI gate: exit 1 on major bumps or new vulns
lockvet -fail-on fresh        # CI gate: enforce a release cooldown
```

Run it inside any git repository. `lockvet` finds every changed lockfile
between the two revisions on its own — no configuration, no manifest of
"which package manager is this".

### Vet any GitHub, GitLab, Bitbucket, Gitea, or Azure DevOps PR — no clone needed

Point `lockvet` at a pull request and it fetches both sides of every
changed lockfile through the GitHub API:

```sh
lockvet pr sharkdp/fd#1723                       # owner/repo#number
lockvet https://github.com/npm/cli/pull/9793     # or just paste the URL
```

That's the fastest way to review a Dependabot/Renovate PR: no checkout,
works on any public repo, all flags (`-md`, `-json`, `-only`, `-fail-on`)
apply. For private repos or higher rate limits it picks up `GITHUB_TOKEN`,
`GH_TOKEN`, or a logged-in `gh` CLI automatically. Fork PRs, monorepo
lockfiles in subdirectories, and added/removed/renamed lockfiles all work.

Add `-comment` and lockvet posts the report **as a comment on the PR or MR
itself** — reruns update the same comment in place instead of stacking
new ones:

```sh
lockvet pr sharkdp/fd#1723 -comment              # needs a token that can
lockvet mr my-group/app!42 -comment              # write comments
lockvet pr https://bitbucket.org/ws/repo/pull-requests/7 -comment
```

**GitLab merge requests** work the same way — on gitlab.com or any
self-hosted instance (the host comes straight from the URL):

```sh
lockvet mr gitlab-org/gitlab!245360              # group/project!iid
lockvet https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245360
lockvet https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/4232
```

Fork MRs and subgroups are fine. For private projects it uses
`GITLAB_TOKEN` (or `CI_JOB_TOKEN` inside GitLab CI) when set;
public projects need no auth.

**Bitbucket Cloud pull requests** too — paste the URL:

```sh
lockvet https://bitbucket.org/atlassian/aui/pull-requests/5394
```

Fork PRs work; private repos use `BITBUCKET_TOKEN` (an access token) or
`BITBUCKET_USERNAME` + `BITBUCKET_APP_PASSWORD` when set.

**Gitea and Forgejo pull requests** — codeberg.org, gitea.com, or any
self-hosted instance (the host comes from the URL) — and commit URLs:

```sh
lockvet https://codeberg.org/forgejo/forgejo/pulls/13594
lockvet https://gitea.com/gitea/tea/pulls/1057
lockvet https://codeberg.org/forgejo/forgejo/commit/714ddd0044f3
```

Fork PRs work, `-comment` posts/updates the report on the PR
(`GITEA_TOKEN`, `FORGEJO_TOKEN`, or `CODEBERG_TOKEN`); public repos need
no auth.

**Azure DevOps pull requests** — dev.azure.com, `*.visualstudio.com`, or
self-hosted Azure DevOps Server — paste the URL:

```sh
lockvet https://dev.azure.com/org/Project/_git/repo/pullrequest/128
```

Public projects need no auth; private ones use `AZURE_DEVOPS_TOKEN` (a
personal access token with **Code: Read**) or, inside Azure Pipelines,
`SYSTEM_ACCESSTOKEN`. `-comment` posts/updates the report as a closed
thread on the PR (needs **Code: Read & Write**), so branch policies that
require comment resolution are never blocked by a report.

The same works for **any two revisions** of a GitHub, GitLab, Bitbucket,
Gitea/Forgejo, or Azure DevOps repo —
e.g. "what changed dependency-wise between two releases?" — or a
**single commit**:

```sh
lockvet compare sharkdp/fd v10.1.0...v10.2.0                # two releases
lockvet https://github.com/sharkdp/fd/compare/v10.1.0...v10.2.0
lockvet https://github.com/npm/cli/commit/f055ce68          # one commit
lockvet https://gitlab.com/veloren/veloren/-/compare/v0.17.0...v0.18.0
lockvet https://bitbucket.org/atlassian/aui/commits/8c4205a86de7
lockvet https://codeberg.org/forgejo/forgejo/compare/v11.0.0...v11.0.1
lockvet "https://dev.azure.com/org/Proj/_git/repo/branchCompare?baseVersion=GBmain&targetVersion=GBnext"
lockvet https://dev.azure.com/org/Proj/_git/repo/commit/da22be91c073
```

Compare URLs (including fork syntax like `main...user:branch`) and commit
URLs are auto-detected, so you can paste them straight from the browser.

### Triage your whole Dependabot queue at once

Reviewing bot PRs one by one is backwards — the question is *which of these
thirty PRs actually needs a human*. `lockvet queue` vets **every open
Dependabot/Renovate PR** of a repo, user, or whole org and sorts the result
most-alarming first:

```sh
lockvet queue mastodon/mastodon        # one repo
lockvet queue grafana                  # a whole org (or user)
```

![lockvet queue triaging every open Renovate PR on mastodon/mastodon](docs/queue-demo.gif)

Every count comes from actually diffing each PR's lockfiles (one OSV /
deps.dev batch for the lot, so an org-wide queue takes seconds). `-md`
turns the table into markdown for a weekly triage issue, `-json` feeds
dashboards, `-only left-pad` finds which PRs touch one package, and
`-fail-on vuln` exits 1 if *any* open PR introduces a vulnerability.

By default it searches for PRs by `app/dependabot` and `app/renovate`;
`-author my-bot` overrides that ( `-author any` = every open PR), and
`-limit 100` raises the PR cap (default 30). Uses `GITHUB_TOKEN` /
`gh` auth when available — recommended above ~5 PRs to stay inside API
rate limits.

**GitLab queues work too** — point it at a group or project URL
(gitlab.com or self-hosted; subgroup projects are included):

```sh
lockvet queue gitlab.com/gitlab-org/gitlab -author gitlab-dependency-update-bot
lockvet queue https://gitlab.example.com/platform     # a whole group
```

GitLab bot usernames vary per instance (there is no canonical Renovate
app user), so the default search — `renovate-bot`, `dependabot` — often
needs `-author <your bot's username>`. Uses `GITLAB_TOKEN` when set.

**And Gitea / Forgejo / Codeberg** — pass an owner or repo URL
(codeberg.org, gitea.com, or self-hosted; unknown hosts are
auto-detected with one anonymous API probe):

```sh
lockvet queue codeberg.org/forgejo -author viceice-bot   # a whole org
lockvet queue https://git.example.org/team/app           # one repo
```

Bot usernames vary here too (Forgejo's own Renovate runs as
`viceice-bot`), so expect to pass `-author` — or `-author any` to vet
every open PR that touches a lockfile. Uses `GITEA_TOKEN` /
`FORGEJO_TOKEN` / `CODEBERG_TOKEN` when set.

**Bitbucket Cloud** — pass a workspace or repo URL:

```sh
lockvet queue bitbucket.org/atlassian          # a whole workspace
lockvet queue bitbucket.org/atlassian/aui      # one repo
```

Bitbucket bots often run as app users whose only name is a display
name, so author specs also match display names loosely —
`renovate-bot` (a default) finds `atlassian-renovate-bot`. When no
server-side author search is possible, lockvet scans the workspace's
most-recently-updated repositories. Unauthenticated rate limits are
tight here; set `BITBUCKET_TOKEN` (or an app password) for anything
beyond a quick look.

**And Azure DevOps** — pass a project or repo URL:

```sh
lockvet queue dev.azure.com/myorg/myproject            # a whole project
lockvet queue dev.azure.com/myorg/myproject/_git/api   # one repo
```

Bot identities vary on Azure DevOps too, so author specs match
display names loosely (`renovate`, a default, finds "Renovate Bot") —
or pass `-author any`. Uses `AZURE_DEVOPS_TOKEN` / `SYSTEM_ACCESSTOKEN`
when set.

**Weekly triage issue** — this workflow keeps one always-current
"Dependency PR triage" issue in your repo, refreshed every Monday
([live example](https://github.com/matteo-sung/lockvet-demo/issues/2)):

```yaml
name: dependency triage
on:
  schedule: [{cron: '0 8 * * 1'}]
  workflow_dispatch:
permissions:
  issues: write
  pull-requests: read
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: curl -fsSL https://raw.githubusercontent.com/matteo-sung/lockvet/main/install.sh | sh -s -- -b /usr/local/bin -v v0.3.9
      - env: {GITHUB_TOKEN: '${{ github.token }}'}
        run: lockvet queue "$GITHUB_REPOSITORY" -md > queue.md
      - env: {GH_TOKEN: '${{ github.token }}'}
        run: |
          title="Dependency PR triage"
          n=$(gh issue list -R "$GITHUB_REPOSITORY" --state open --search "in:title \"$title\"" --json number --jq '.[0].number')
          if [ -n "$n" ]; then gh issue edit -R "$GITHUB_REPOSITORY" "$n" --body-file queue.md
          else gh issue create -R "$GITHUB_REPOSITORY" --title "$title" --body-file queue.md; fi
```

(Add `-author any` to the `lockvet queue` line to include non-bot PRs.)

### Diff two SBOMs (or container images)

`lockvet diff` vets **two files on disk** — no git repository needed. Point
it at two CycloneDX or SPDX JSON SBOMs (any filename; the format is sniffed
from the content) and it explains what changed between them, across every
ecosystem in the document at once:

```sh
syft -q alpine:3.18 -o cyclonedx-json > old.cdx.json
syft -q alpine:3.19 -o cyclonedx-json > new.cdx.json
lockvet diff old.cdx.json new.cdx.json
```

```text
new.cdx.json (SBOM)
  ↑ ca-certificates-bundle 20241121-r1 → 20250911-r0  MAJOR  via apk-tools
  ↑ zlib                   1.2.13-r1   → 1.3.1-r0  minor  via apk-tools
  ↑ busybox                1.36.1-r7   → 1.36.1-r20  patch  via alpine-baselayout › busybox-binsh
      ▼ fixes ALPINE-CVE-2023-42363 A use-after-free vulnerability was discovered in xasprintf…
      ▼ fixes ALPINE-CVE-2023-42364 A use-after-free vulnerability in BusyBox v.1.36.1 allows…
  …
12 packages changed · 1 major · 1 minor · 10 patch · 2 direct · 10 transitive
· vulnerabilities: 0 introduced, 5 fixed, 4 unresolved
```

Packages are matched by their purl: language ecosystems (npm, PyPI, Go,
Cargo, …) get the full treatment — OSV advisories, release ages, verified
changelog links — and **OS packages get distro advisories** resolved against
the right release branch (`Alpine:v3.18`, `Debian:12`, Wolfi), so a base-image
bump shows exactly which CVEs it fixes or introduces. Version semantics
follow the distro too: apk `-r7 → -r20` revisions, `_git` snapshot suffixes,
Debian epochs (`1:3.10-4`) and `~deb13u1` pre-releases all compare correctly.

It also works for plain lockfiles outside a repo
(`lockvet diff Cargo.lock.orig Cargo.lock`), and SBOMs *committed to git*
(`bom.json`, `*.cdx.json`, `*.spdx.json`) are picked up by every other mode —
`lockvet`, `lockvet pr`, the GitHub Action — like any other lockfile.

### Let your AI assistant vet dependencies (MCP server)

`lockvet mcp` runs lockvet as a [Model Context Protocol](https://modelcontextprotocol.io)
server over stdio, so Claude Code, Claude Desktop, Cursor, VS Code, and any
other MCP client can vet lockfile changes mid-conversation — *"is this
Dependabot PR safe to merge?"* becomes a question your assistant can actually
answer, with OSV data instead of vibes.

```sh
# Claude Code
claude mcp add lockvet -- lockvet mcp
```

```jsonc
// Claude Desktop, Cursor, and most other clients (mcpServers config):
{ "mcpServers": { "lockvet": { "command": "lockvet", "args": ["mcp"] } } }
```

No install needed with Docker:
`{ "command": "docker", "args": ["run", "-i", "--rm", "ghcr.io/matteo-sung/lockvet:0.3.9", "lockvet", "mcp"] }`.
lockvet is also on the official [MCP Registry](https://registry.modelcontextprotocol.io)
as [`io.github.matteo-sung/lockvet`](https://registry.modelcontextprotocol.io/?search=lockvet),
so clients that browse the registry can add it from there.

Four read-only tools, mirroring the CLI:

| Tool | What it does |
|---|---|
| `vet_url` | vet any PR/MR, compare range, or commit by URL — GitHub, GitLab, Bitbucket, Gitea/Forgejo, Azure DevOps, no clone |
| `vet_git` | vet a local repo: working tree vs `HEAD`, or any revision range |
| `vet_files` | vet two lockfiles or SBOMs on disk |
| `queue` | triage every open Dependabot/Renovate PR of a repo/org in one table |

Reports come back as markdown (or `format: "json"` for structure); forge
tokens are read from the environment (`GITHUB_TOKEN`, `GITLAB_TOKEN`, …) so
private repos work wherever the CLI does. Try: *“triage the open dependency
PRs in grafana and tell me which ones I should look at first.”*

## In CI (review Dependabot/Renovate PRs automatically)

`lockvet` posts a summary comment on any PR that touches a lockfile —
[see it live on a real PR](https://github.com/matteo-sung/lockvet-demo/pull/1):

```yaml
# .github/workflows/lockvet.yml
name: lockvet
on:
  pull_request:
    paths:
      - '**/package-lock.json'
      - '**/pnpm-lock.yaml'
      - '**/yarn.lock'
      - '**/bun.lock'
      - '**/Cargo.lock'
      - '**/uv.lock'
      - '**/poetry.lock'
      - '**/requirements.txt'
      - '**/go.mod'
      - '**/composer.lock'
      - '**/Gemfile.lock'

permissions:
  pull-requests: write
  contents: read

jobs:
  lockvet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: matteo-sung/lockvet@v0.3.9
        # optional:
        # with:
        #   fail-on: vuln        # or "major,vuln,downgrade,fresh,deprecated,unlisted,scripts,provenance,license"
        #   fresh-days: '7'      # cooldown window for the fresh flag
        #   changelogs: 'true'   # inline release notes for every bump
        #   sarif: 'true'        # code scanning alerts (see below)
```

(Not on GitHub Actions? `lockvet pr <PR-url> -comment -fail-on vuln` does
the same job — fetch, report, comment, gate — from any CI with a
`GITHUB_TOKEN` in the environment.)

### GitHub Code Scanning (SARIF)

`lockvet -sarif` emits [SARIF 2.1.0](https://docs.github.com/en/code-security/code-scanning),
so vulnerable, still-vulnerable, and deprecated incoming versions show up as
code scanning alerts — annotated on the **exact lockfile line** that pins the
package, with OSV links and severity. In the Action it's one input (the job
additionally needs `security-events: write`):

```yaml
permissions:
  pull-requests: write
  contents: read
  security-events: write

      - uses: matteo-sung/lockvet@v0.3.9
        with:
          sarif: 'true'
```

Or standalone, anywhere:

```console
$ lockvet -sarif BASE HEAD > lockvet.sarif   # also works with pr/mr/compare modes
```

and upload with `github/codeql-action/upload-sarif` or
`gh api repos/<owner>/<repo>/code-scanning/sarifs`.

On GitLab, one line vets the MR and posts the report as an MR note —
reruns update the note in place:

```yaml
# .gitlab-ci.yml
lockvet:
  image: ghcr.io/matteo-sung/lockvet:0.3.9
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      changes: ["**/*lock*", "**/go.mod", "**/requirements.txt"]
  script:
    - lockvet mr "$CI_MERGE_REQUEST_PROJECT_URL/-/merge_requests/$CI_MERGE_REQUEST_IID" -comment -fail-on vuln
```

The `-comment` needs a `GITLAB_TOKEN` CI/CD variable (a project access token
with `api` scope — `CI_JOB_TOKEN` can't post notes). Without one, drop
`-comment`: fetching public MRs needs no auth, and the report still lands in
the job log. Self-hosted instances work — the host comes from the URL.
Prefer diffing the checkout instead of the API? `git fetch origin
"$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" && lockvet
"origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"` does the same locally.

On Bitbucket, the same one-liner runs in Pipelines:

```yaml
# bitbucket-pipelines.yml
pipelines:
  pull-requests:
    '**':
      - step:
          name: lockvet
          image: ghcr.io/matteo-sung/lockvet:0.3.9
          script:
            - lockvet pr "https://bitbucket.org/$BITBUCKET_WORKSPACE/$BITBUCKET_REPO_SLUG/pull-requests/$BITBUCKET_PR_ID" -comment -fail-on vuln
```

For `-comment`, set a `BITBUCKET_TOKEN` repository variable (a repository
access token with *pull request: write* scope). Without it, drop `-comment`
and the report lands in the pipeline log.

On Azure DevOps, add a PR-triggered job that comments the report on the
pull request:

```yaml
# azure-pipelines.yml
jobs:
  - job: lockvet
    condition: eq(variables['Build.Reason'], 'PullRequest')
    pool: { vmImage: ubuntu-latest }
    container: ghcr.io/matteo-sung/lockvet:0.3.9
    steps:
      - checkout: none
      - script: >
          lockvet pr
          "$(System.CollectionUri)$(System.TeamProject)/_git/$(Build.Repository.Name)/pullrequest/$(System.PullRequest.PullRequestId)"
          -comment -fail-on vuln
        env:
          SYSTEM_ACCESSTOKEN: $(System.AccessToken)
```

The build service account needs *Contribute to pull requests* on the repo
for `-comment`; without it, drop `-comment` and the report lands in the
job log.

And on Codeberg (or any Gitea/Forgejo with Woodpecker CI):

```yaml
# .woodpecker/lockvet.yaml
when:
  - event: pull_request

steps:
  - name: lockvet
    image: ghcr.io/matteo-sung/lockvet:0.3.9
    environment:
      GITEA_TOKEN:
        from_secret: gitea_token   # only needed for -comment
    commands:
      - lockvet pr "$CI_REPO_URL/pulls/$CI_COMMIT_PULL_REQUEST" -comment -fail-on vuln
```

## As a pre-commit hook

Catch a risky bump before it's even committed — lockvet's default mode
(working tree vs `HEAD`) is exactly "what this commit changes", and the hook
only fires when a lockfile is part of the commit:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/matteo-sung/lockvet
    rev: v0.3.9
    hooks:
      - id: lockvet
        # optional: block the commit instead of just explaining it
        # args: [-fail-on, "vuln,fresh"]
        # optional: skip network lookups for instant commits
        # args: [-offline]
```

By default the hook is informational — it prints the explanation and lets the
commit through. Add `-fail-on` to turn it into a gate. Requires nothing but
[pre-commit](https://pre-commit.com) itself (the hook builds via Go, which
pre-commit downloads automatically if missing).

## Deprecations and license changes

Every incoming version is checked against its registry (via deps.dev):

- **deprecated** — the registry marks the version deprecated; the upstream
  reason is shown inline (`● deprecated upstream: use String.prototype.padStart()`).
  For PyPI this also covers [yanked releases](https://peps.python.org/pep-0592/)
  (with the yank reason) and [PEP 792 project statuses](https://peps.python.org/pep-0792/):
  a project **archived** by its maintainers or **quarantined** by PyPI's
  admins — the malware-review state — is flagged on every change that
  still pins it. crates.io yanks surface the same way, verified against
  the sparse index itself so even a yank minutes old is caught. Composer
  packages get the same treatment straight from Packagist: a bump onto an
  [abandoned](https://getcomposer.org/doc/04-schema.md#abandoned) package
  is flagged with the maintainer's suggested replacement
  (`● deprecated upstream: abandoned; use symfony/mailer instead`).
- **license change** — the incoming version is published under a different
  license than the one it replaces:

  ```
  ↑ husky  4.3.8 → 5.0.9  MAJOR  (direct)
      ● license change: MIT → non-standard
  ```

  Relicensing mid-stream (MIT → BUSL, SSPL, "non-standard", …) is exactly
  the kind of thing nobody spots in a 40-line lockfile diff. lockvet only
  claims a change when the registry reports a license for *both* sides.
  JSON output carries `old_license` / `new_license` on every covered change.

Both are gates too: `-fail-on deprecated,license`.

## Versions missing from the registry

When an incoming version is **unknown to the registry index** even though
other versions of the same package are listed, lockvet says so:

```
+ flatmap-stream 0.1.1  (added)  via event-stream
    ▲ not in registry index: 0.1.1 unknown to deps.dev though other
      versions are listed — unpublished/deleted release, or published
      minutes ago; verify before trusting
```

Why this matters: **when a registry pulls a malicious release, this is what
the hole looks like.** Every malicious version in
[our case studies](docs/case-studies.md) — `event-stream@3.3.6`,
`flatmap-stream@0.1.1`, `chalk@5.6.1`, `ultralytics@8.3.41` — was
unpublished after the attack, so any lockfile still pinning one references
a version its own registry has disowned. lockvet flags that *without
needing an advisory to exist yet*.

To keep it honest, the flag is deliberately conservative — it stays silent
for:

- packages the registry doesn't index at all (private registries, uncovered
  ecosystems) — only packages whose *other* versions are listed can be
  flagged;
- workspace members, git and path dependencies (the lockfile itself says
  they don't come from the registry);
- Go pseudo-versions and pnpm-style decorated version strings.

For npm, PyPI, crates.io, RubyGems and Packagist packages the flag is
**double-checked against the registry itself**: deps.dev can lag the
registries by days, so before claiming anything lockvet fetches the
package's real version list from `registry.npmjs.org` / PyPI's simple
API / the crates.io sparse index / the RubyGems compact index /
Packagist's Composer metadata endpoint and
clears the flag for any version the registry serves. What survives is a
version the registry itself no longer lists — and that distinction has
teeth: on crates.io yanked versions *stay in the index* while deleted
(malicious) ones vanish entirely, and on RubyGems a yank removes the
release from the index altogether, so a bump onto a yanked or
admin-deleted gem keeps the flag (replaying the 2019 `strong_password`
0.0.7 hijack trips it today).

A release published minutes ago may also not be indexed yet — the flag
tells you to *look*, not to panic. Gate on it with `-fail-on unlisted`;
JSON carries `unlisted` / `unlisted_versions`; SARIF emits an
`unlisted-version` warning; `queue` sorts affected PRs to the top.

## Install scripts added by a bump

npm packages can run arbitrary code at install time (`preinstall` /
`install` / `postinstall`). Most packages never do — so a routine-looking
bump that suddenly **adds** install scripts deserves a hard look before you
merge. Gaining execution-on-install is how the
[Shai-Hulud worm](docs/case-studies.md#4-the-shai-hulud-worm-sept-2025)
and plenty of smaller npm attacks delivered their payload.

lockvet asks the npm registry which versions run install scripts and flags
the transition:

```
↑ core-js 2.6.5 → 2.6.6  patch  (direct)
    ⚙ install scripts added: 2.6.6 the old version ran no install scripts,
      this one does — a favourite payload vehicle for hijacked npm
      packages; review before trusting
```

Only *transitions* are flagged, so the signal stays quiet: a brand-new
dependency with install scripts is ordinary (native builds), and a package
that has always had them tells you nothing new. In a 92-change `npm/cli`
release diff and a 165-change React one, it flags nothing at all.

Gate on it with `-fail-on scripts`; JSON carries `install_scripts_added` /
`scripted_versions`; SARIF emits an `install-scripts-added` warning;
`queue` sorts affected PRs to the top. npm-only for now (other ecosystems
either have no install hooks or don't expose them in registry metadata).

## Provenance dropped by a bump

A growing share of npm packages publish with [sigstore provenance
attestations](https://docs.npmjs.com/generating-provenance-statements),
PyPI projects with [PEP 740 attestations](https://peps.python.org/pep-0740/),
crates.io crates via [trusted publishing](https://rust-lang.github.io/rfcs/3691-trusted-publishing-cratesio.html),
and RubyGems releases with [sigstore attestations](https://guides.rubygems.org/trusted-publishing/)
— cryptographic proof (or, for crates.io, a registry-recorded guarantee)
that the release was built and published by the project's own CI from
its public repo. That proof has a useful
property for reviewers: **a stolen publish token can upload a release,
but it can't make the project's pipeline attest it.**

So when a package that consistently attests suddenly publishes a version
with no provenance, lockvet flags it:

```
↑ acme 1.4.2 → 1.4.3  patch  (direct)  (2d old)
    ⛨ provenance dropped: 1.4.3 every previous version was published with
      sigstore provenance, this one wasn't — legitimate CI keeps
      attesting, a stolen publish token can't; verify the release
```

Three conditions keep it near-silent: the outgoing version must be
attested, the package's provenance practice must be *established* (the
top stable versions below the incoming one all attested — one-off
adopters don't count), and the incoming release must be **young
(≤ 30 days)** — this is a while-it's-happening tripwire for the window
before advisories exist, not an audit of history. Under those rules it
flags nothing at all across current bumps of ~100 top npm packages,
exactly one bump across the top 1 000 PyPI packages — a real 7-day-old
release that broke its project's unbroken attestation streak (almost
certainly a benign manual publish, which is precisely the "worth a look"
this flag exists for) — and zero across the top 100 crates, a tenth of
which already publish via trusted pipelines (`cc`, `time`, `getrandom`,
…). It would fire the moment a token thief ships a release outside the
project's CI.

Gate on it with `-fail-on provenance`; JSON carries `provenance_dropped`
/ `unattested_versions`; SARIF emits a `provenance-dropped` warning;
`queue` sorts affected PRs to the top. Comes from the same registry
documents as the install-scripts and unlisted checks — no extra
requests. Covers npm, PyPI, crates.io and RubyGems (for PyPI a version
only counts as attested when *every* file of the release carries
provenance, and only a release with *no* attested files is ever flagged
— mixed uploads are a publishing setup, not a signal; for crates.io the
registry's `trustpub_data` on each version is the source of truth; for
RubyGems it's the per-release attestations API — adoption there is
still small, so today the gates simply stay silent, and protection
switches on automatically as gems start attesting).

## Release notes inline (`-changelogs`)

Every bump already links to the verified upstream tag-to-tag diff. Add
`-changelogs` and lockvet also *fetches the release notes* — including the
releases a multi-version jump skips over:

```
↑ body-parser  1.19.0 → 1.20.1  minor  via express  (3y old)
    ▤ 1.20.1
        * deps: qs@6.11.0
        * perf: remove unnecessary object clone
    ▤ 1.20.0
        * Fix internal error when inflated body exceeds limit
        * Prevent loss of async hooks context
        …
    ▤ 1.19.2
    ▤ 1.19.1
```

So `1.19.0 → 1.20.1` shows what landed in 1.19.1, 1.19.2, 1.20.0, *and*
1.20.1 (up to 5 releases per package; the compare link covers the rest).
In `-md` mode each package's notes become a collapsed `<details>` block —
in a PR comment that reads like Dependabot's release-notes section, except
it covers **every** package in the diff, transitives included. Works in
every mode (`pr`, `mr`, `compare`, `diff`, the Action via
`changelogs: 'true'`, MCP via `"changelogs": true`).

Notes come from GitHub Releases of the (verified) source repo, so
GitHub-hosted upstreams are covered; excerpts are trimmed and
control-character-sanitized. Uses the GitHub API — anonymous works for a
handful of packages, `GITHUB_TOKEN` / a logged-in `gh` raises the limit.

## Supported lockfiles

| Ecosystem | Files |
|---|---|
| JavaScript | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` (v1 & berry), `bun.lock`, `deno.lock` |
| Rust | `Cargo.lock` |
| Python | `uv.lock`, `poetry.lock`, `Pipfile.lock`, `requirements.txt` (`==` pins) |
| Go | `go.mod` |
| PHP | `composer.lock` |
| Ruby | `Gemfile.lock` |
| Elixir | `mix.lock` |
| Dart / Flutter | `pubspec.lock` |
| Java / JVM | `gradle.lockfile` |
| .NET | `packages.lock.json` |
| Swift | `Package.resolved` |
| iOS / CocoaPods | `Podfile.lock` |
| R | `renv.lock` (CRAN + Bioconductor advisories, `RSEC-…`) |
| Julia | `Manifest.toml` (also `Manifest-v1.11.toml` style) — General-registry advisories (`JLSEC-…`), via-chains from the manifest's dependency graph |
| Haskell | `stack.yaml.lock`, `cabal.project.freeze`, `cabal.config` (Stackage pins) — Hackage advisories (`HSEC-…`) |
| Gleam | `manifest.toml` — Hex advisories, via-chains, direct deps from `[requirements]` |
| Conda | `pixi.lock` (v4–v7), `conda-lock.yml` (also `*.pixi.lock`, `*.conda-lock.yml`) — pip packages inside get full PyPI vulnerability/age data |
| Terraform / OpenTofu | `.terraform.lock.hcl` (also suffix-named `*.terraform.lock.hcl`) — default-registry hosts stripped, registry links for terraform.io & OpenTofu providers |
| Helm | `Chart.lock`, `requirements.lock` (Helm v2; pip-style `requirements.lock` from rye is auto-detected and treated as PyPI) |
| Nix | `flake.lock` |
| SBOMs | CycloneDX & SPDX JSON: `bom.json`, `sbom.json`, `*.cdx.json`, `*.spdx.json` — multi-ecosystem, incl. Alpine/Debian/Wolfi OS packages |

Notes: direct/`via …` origin labels appear where the lockfile records its
dependency graph: npm, pnpm, yarn, Cargo, uv, poetry, Composer, Bundler,
renv, pixi/conda-lock, Julia manifests, Gleam, and Go modules (go.mod's `// indirect` markers give direct/transitive,
without chains). Formats that only pin flat versions (`requirements.txt`, `mix.lock`,
Gradle, …) skip the label.
Deno's `jsr:` packages, CocoaPods, conda channels, Terraform providers,
Helm charts, and Nix flakes have no OSV.dev ecosystem (yet), so those
diffs are explained without vulnerability data — but pip/pypi packages inside `pixi.lock` / `conda-lock.yml` are
matched against PyPI advisories like any other Python lockfile.
SBOM packages keep their own ecosystem per purl; OS packages get OSV data
when the purl names a release (`distro=alpine-3.18.4` → `Alpine:v3.18`) —
Ubuntu/RPM packages are diffed without it.
Release ages / deprecations / license changes come from deps.dev, which covers
npm, crates.io, PyPI, Go, Maven, NuGet, and RubyGems — other ecosystems simply
skip those checks. PHP is the exception: deps.dev has no Composer system at
all, so lockvet asks Packagist directly — release ages, abandoned-package
warnings, license changes, changelog links and the unlisted check all work
for `composer.lock` too.
Nix flake inputs pin git revisions, not versions — lockvet shows them as
`<commit-date>.<short-rev>` so the diff still reads chronologically.

Missing one you care about? [Open an issue](https://github.com/matteo-sung/lockvet/issues) —
parsers are ~50 lines each.

## How it works

1. `git diff --name-only <base> <target>` finds changed lockfiles.
2. Each lockfile version is read with `git show` and parsed into
   `package → pinned versions` (multiple versions per package are handled —
   npm nesting, Cargo duplicate majors).
3. The two snapshots are diffed and each change is classified with a lenient
   version parser that copes with semver, Python post-releases, and Go
   pseudo-versions.
   Where the lockfile also records dependency edges and root deps, lockvet
   BFS-walks the graph to label every change `(direct)` or `via <chain>` —
   no manifest files or network needed.
4. Old and new versions are checked against OSV.dev's batch API. A vulnerability
   that matches the new version but not the old one is **introduced**; the
   reverse is **fixed**; both is **unresolved**. Aliased advisories
   (GHSA/CVE/PYSEC/RUSTSEC for the same issue) are collapsed.
5. Every *incoming* version is looked up on deps.dev's batch API for its
   publish date, deprecation status, and license — departing versions are
   looked up too, so a license flip between old and new gets flagged (npm,
   crates.io, PyPI, Go, Maven, NuGet, RubyGems). An incoming version the
   registry doesn't list — while other versions of the package are listed —
   gets the [`unlisted` flag](#versions-missing-from-the-registry): that's
   what an unpublished (often malicious) release looks like (for npm,
   PyPI, crates.io, RubyGems and Packagist the flag is double-checked against the
   registry itself, which also tells lockvet when a bump [suddenly adds
   install scripts](#install-scripts-added-by-a-bump) or [silently drops
   provenance attestations](#provenance-dropped-by-a-bump), and when a
   release was yanked or its project archived or quarantined). Versions younger than `-fresh-days` (default 7) get a
   ⏱ flag — supply-chain attacks are usually discovered and yanked within
   days of publication, so a short cooldown filters most of them out. For
   RubyGems the compact index's own `created_at` times fill in ages
   deps.dev hasn't indexed yet, so a gem published minutes ago still gets
   its ⏱ flag; for Composer packages the ages come straight from
   Packagist, which deps.dev doesn't cover at all.
6. Each changed package's source repository (from deps.dev) has its tag list
   fetched over git's smart-HTTP protocol — one anonymous GET per repo, the
   same request `git ls-remote` makes. Old and new versions are matched
   against the *real* tags (trying `v1.2.3`, `1.2.3`, `pkg@1.2.3`,
   `pkg-v1.2.3`, Go `dir/v1.2.3`, and pseudo-version commit hashes), and only
   verified matches become compare / release links — so every link works.

**Privacy:** the only network traffic is the OSV.dev and deps.dev batch
queries (package names + versions), anonymous npm-registry / PyPI /
crates.io / RubyGems / Packagist metadata fetches for changed packages of
those ecosystems, and the anonymous git tag listings above.
`-offline` disables all of it; `-no-vulns` / `-no-meta` disable
vulnerability and metadata+links lookups individually. No telemetry, ever.

**Dependencies:** none. Pure Go standard library.

## How it compares

|  | `git diff` on the lockfile | [whatsdiff](https://github.com/whatsdiff/whatsdiff) v2.6 | **lockvet** |
|---|---|---|---|
| Lockfile formats | any (raw text) | 3 (composer, npm, pnpm) | **29** across 20+ ecosystems, + CycloneDX/SPDX SBOMs |
| Readable per-package summary | ✗ | ✓ | ✓ |
| Vulnerabilities introduced / fixed by the change | ✗ | ✗ | ✓ (OSV.dev) |
| Release age + ⏱ cooldown flag on fresh versions | ✗ | ✗ | ✓ (deps.dev) |
| Deprecation warnings | ✗ | ✗ | ✓ (deps.dev) |
| License-change flag (`MIT → BUSL-1.1`) | ✗ | ✗ | ✓ (deps.dev) |
| Flag versions their own registry no longer lists (unpublished malware) | ✗ | ✗ | ✓ ([`unlisted`](#versions-missing-from-the-registry)) |
| Flag bumps that suddenly add npm install scripts | ✗ | ✗ | ✓ ([`⚙ scripts`](#install-scripts-added-by-a-bump)) |
| Flag young releases that silently drop provenance (sigstore / trusted publishing) | ✗ | ✗ | ✓ ([`⛨ provenance`](#provenance-dropped-by-a-bump)) |
| Direct vs. transitive, with pull-in chain (`via a › b`) | ✗ | ✗ | ✓ |
| Vet a PR / MR / compare URL without cloning | ✗ | ✗ | ✓ (GitHub + GitLab + Bitbucket + Gitea/Forgejo + Azure DevOps, self-hosted incl.) |
| Triage every open Dependabot/Renovate PR at once | ✗ | ✗ | ✓ (`lockvet queue <org>`, on all five forges) |
| Diff two container images' SBOMs, with distro CVEs | ✗ | ✗ | ✓ (`lockvet diff old.cdx.json new.cdx.json`) |
| CI gate | ✗ | per-package `check` exit codes | policy gate (`-fail-on major\|vuln\|fresh\|deprecated\|unlisted\|scripts\|provenance\|license`) + GitHub Action |
| Output formats | text | text, JSON, markdown | text, JSON, markdown, SARIF (code scanning alerts) |
| See what changed upstream | ✗ | ✓ (fetches changelog text) | ✓ (verified tag-to-tag diff links + `-changelogs` fetches release notes, transitives included) |
| MCP server (let AI assistants vet PRs) | ✗ | ✓ | ✓ (`lockvet mcp`: vet URLs, local repos, files, whole queues) |
| Interactive TUI | ✗ | ✓ | ✗ |
| Runtime | — | PHP (binaries provided) | single static Go binary, zero deps |

whatsdiff is a fine tool if you live in composer/npm and want changelogs and
a TUI. lockvet's focus is different: *should I trust this diff?* — across
whatever language your repos are in, with security data inline, in CI.

## Non-goals

- Not a full SCA scanner — [osv-scanner](https://github.com/google/osv-scanner)
  audits your *entire* dependency tree. lockvet explains a *change*.
- Not an updater — Dependabot/Renovate open the PRs; lockvet tells you
  whether to merge them.
- No interactive TUI (see whatsdiff above) — lockvet stays a one-shot
  command whose output drops straight into a PR comment.

## License

MIT © Matteo Sung
