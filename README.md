# lockvet

**Explain any lockfile change before you merge it.**

![lockvet catching a RUSTSEC advisory hidden in a routine dependabot patch bump](docs/demo.gif)

*Real example: a dependabot "patch" bump of `jiff` in [sharkdp/fd](https://github.com/sharkdp/fd)
quietly added 7 transitive crates — one of them flagged by RUSTSEC.*

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
  within days — a cooldown is cheap insurance), plus upstream deprecation
  notices (via [deps.dev](https://deps.dev))
- **across every ecosystem, in one static binary** — 20 lockfile formats:
  npm, pnpm, yarn (classic & berry), bun, Deno, Cargo, uv, poetry, pipenv,
  `requirements.txt`, Go modules, Composer, Bundler, Hex/mix, pub/Flutter,
  Gradle, NuGet, Swift Package Manager, CocoaPods, Nix flakes

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

```sh
go install github.com/matteo-sung/lockvet@latest
```

or grab a prebuilt binary from the
[releases page](https://github.com/matteo-sung/lockvet/releases)
(Linux / macOS / Windows, amd64 & arm64):

```sh
curl -fsSL https://raw.githubusercontent.com/matteo-sung/lockvet/main/install.sh | sh
```

## Usage

```sh
lockvet                    # working tree vs HEAD — "what did I just do?"
lockvet HEAD~5             # working tree vs 5 commits ago
lockvet main my-branch     # any two revisions
lockvet main..my-branch    # range syntax works too

lockvet -md                # markdown, ready to paste into a PR comment
lockvet -json              # machine-readable, full vuln ID lists
lockvet -offline           # no network calls (skips vuln + metadata lookups)

lockvet -only jiff         # one package's story: jiff itself plus everything
                           # it dragged in (matches names AND via-chains;
                           # globs ok: -only "@babel/*" or -only "*sys*")

lockvet -fresh-days 14        # widen the "recently published" window (default 7)
lockvet -fail-on major,vuln   # CI gate: exit 1 on major bumps or new vulns
lockvet -fail-on fresh        # CI gate: enforce a release cooldown
```

Run it inside any git repository. `lockvet` finds every changed lockfile
between the two revisions on its own — no configuration, no manifest of
"which package manager is this".

## In CI (review Dependabot/Renovate PRs automatically)

`lockvet` posts a summary comment on any PR that touches a lockfile:

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
      - uses: matteo-sung/lockvet@main
        # optional:
        # with:
        #   fail-on: vuln        # or "major,vuln,downgrade,fresh,deprecated"
        #   fresh-days: '7'      # cooldown window for the fresh flag
```

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
| Nix | `flake.lock` |

Notes: direct/`via …` origin labels appear where the lockfile records its
dependency graph: npm, pnpm, yarn, Cargo, uv, poetry, Composer, Bundler, and
Go modules (go.mod's `// indirect` markers give direct/transitive, without
chains). Formats that only pin flat versions (`requirements.txt`, `mix.lock`,
Gradle, …) skip the label.
Deno's `jsr:` packages, CocoaPods, and Nix flakes have no OSV.dev
ecosystem (yet), so those diffs are explained without vulnerability data.
Release ages / deprecations come from deps.dev, which covers npm, crates.io,
PyPI, Go, Maven, NuGet, and RubyGems — other ecosystems simply skip that check.
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
   publish date and deprecation status (npm, crates.io, PyPI, Go, Maven,
   NuGet, RubyGems). Versions younger than `-fresh-days` (default 7) get a
   ⏱ flag — supply-chain attacks are usually discovered and yanked within
   days of publication, so a short cooldown filters most of them out.

**Privacy:** the only network traffic is the OSV.dev and deps.dev batch
queries (package names + versions). `-offline` disables both; `-no-vulns` /
`-no-meta` disable them individually. No telemetry, ever.

**Dependencies:** none. Pure Go standard library.

## Non-goals

- Not a full SCA scanner — [osv-scanner](https://github.com/google/osv-scanner)
  audits your *entire* dependency tree. lockvet explains a *change*.
- Not an updater — Dependabot/Renovate open the PRs; lockvet tells you
  whether to merge them.

## License

MIT © Matteo Sung
