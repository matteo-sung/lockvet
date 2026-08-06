# Changelog

All notable changes to lockvet. Versions follow [semver](https://semver.org)
with a 0.x major: minor bumps may consolidate, patch bumps add features and
fixes.

## v0.4.1 — 2026-08-06

- **`.lockvetignore` — acknowledge a finding without turning the gate
  off.** One rule per line: an advisory ID (`GHSA-…`, `RUSTSEC-…`, any
  OSV ID), a `pkg[@version]`, or a `kind:pkg[@version]` where *kind* is
  `vuln`, `fresh`, `deprecated`, `unlisted`, `scripts`, `provenance`,
  `license`, `major`, or `downgrade`. Globs and case-insensitive
  matching throughout; `# comments` encouraged; an `until=YYYY-MM-DD`
  expiry makes an acknowledgement temporary — after that date the rule
  stops applying and every run warns until the line is removed.
  Suppressed findings stop counting toward the summary and `-fail-on`
  but stay visible: a dim `○ ignored (.lockvetignore)` marker in
  terminal and markdown reports, `ignored` / `ignored_vulns` in JSON,
  and an "N findings ignored" summary note. Discovered automatically
  next to the lockfiles (the audited tree for `lockvet audit`, the
  working directory for PR/compare modes and the Action); `-ignore-file
  <path>` points elsewhere, `-no-ignore` disables it for "no ignores in
  CI" policies. `queue` mode spans many repositories and applies no
  ignore file. Ignored-but-visible keeps the report honest; expiring
  snoozes keep the file honest.

## v0.4.0 — 2026-08-05

- **`lockvet audit` — vet what you pin *right now*, not a change.** Walks
  the tree (skipping `node_modules`, `vendor`, `.git`, …), reads every
  lockfile in all 30 formats (SBOMs included), and runs the full pipeline
  over the current dependency set, reporting only findings: pinned versions
  affected by **known advisories** (OSV.dev, `MAL-*` included), versions
  **missing from their registry's index** while siblings are listed (the
  shape of an unpublished/pulled malicious release — a lockfile still
  pinning Sept 2025's `chalk@5.6.1` trips both flags), **deprecated /
  retracted / yanked / abandoned** pins with upstream reasons, and pins
  **published only days ago** (⏱). Composes with `-md`, `-json`, `-only`,
  `-fail-on vuln,unlisted,…`, and `-sarif` (alerts say "is pinned at", and
  anchor to the exact lockfile line — a scheduled workflow keeps Code
  Scanning honest between dependency PRs). Transition-based signals
  (⚙ install scripts added, ⛨ provenance dropped) stay diff-only: an audit
  reports state, not history. Also available as the MCP `audit` tool.
- **False-positive fixes the audit's full-tree coverage surfaced (both
  affected diff mode too):**
  - `go.mod` `replace` directives are now honoured: replaced modules
    (monorepo `require sibling v0.0.0` + `replace` → local path) no longer
    get unlisted flags or advisories matched against the `v0.0.0` sentinel —
    which sits below *every* advisory's fixed range and previously pulled in
    the module's complete historical advisory list.
  - yarn `npm:` **alias descriptors** (`wrap-ansi-cjs@npm:wrap-ansi@^7`) no
    longer produce unlisted flags for the alias name, which doesn't exist on
    the registry.

## v0.3.19 — 2026-08-05

- **Conan support** — `conan.lock` is lockfile format #30, covering C/C++:
  - **Conan 2 flat lockfiles** (`requires` / `build_requires` /
    `python_requires` / `config_requires`) and **Conan 1 graph locks**
    (whose node graph gives direct/`via …` origin labels) both parse;
    references pinned with a user/channel are marked non-registry and
    never checked against ConanCenter.
  - **Release ages and the ⏱ cooldown flag straight from ConanCenter**
    (the live `center2.conan.io` remote — the frozen legacy remote would
    misdate everything recent). A version is dated by its *oldest*
    recipe revision, so recipe re-exports don't make five-year-old
    releases look fresh. `-fail-on fresh` works for C/C++ diffs.
  - Deliberately **no unlisted claims**: a Conan reference doesn't
    record which remote it came from, and real projects layer private
    remotes over ConanCenter for the same package names — absence from
    ConanCenter proves nothing.
  - OSV's `ConanCenter` ecosystem is queried too; it is near-empty
    today, so advisories will surface on `conan.lock` diffs
    automatically as it fills in. Markdown output links package names
    to conan.io/center recipe pages.
  - ConanCenter sends no CORS headers, so the browser playground skips
    the registry layer for Conan (diffs still parse and classify).
- New animated demo: the Sept 2025 chalk+debug npm takeover replayed
  during its two-hour live window
  ([docs/supplychain-demo.gif](docs/supplychain-demo.gif)).

## v0.3.18 — 2026-08-05

- **JSR joins the registry lineup** (npm · PyPI · crates.io · RubyGems ·
  Packagist · NuGet · Hex · Go · Pub · CocoaPods · Terraform · Maven ·
  JSR) — `jsr:` packages in `deno.lock` had no OSV ecosystem *and* no
  deps.dev coverage, so their diffs carried zero registry data until now.
  jsr.io itself fills the gap:
  - **Release ages and the ⏱ cooldown flag** from each version's
    `createdAt` in the package's `meta.json` — the exact document Deno
    resolves against.
  - **Yanked versions and archived packages land in the deprecation
    lane** (`● deprecated upstream: version yanked on jsr.io`).
  - **Registry-verified unlisted detection.** JSR never lets publishers
    delete versions — yanking keeps them listed in `meta.json` — so an
    incoming version missing while the package's other versions ARE
    listed is a strong scrubbed-release signal.
  - **Verified changelog links**: the GitHub repository each package
    links on jsr.io feeds the tag-verified compare links and
    `-changelogs` release notes, and markdown output links JSR package
    names to their jsr.io pages.
  - Two anonymous GETs per changed package against CORS-open endpoints
    — the identical route works native and in the
    [browser playground](https://matteo-sung.github.io/lockvet/).
  - JSR publishes are sigstore-signed across the board (no unattested
    baseline to fall from), so provenance-drop detection honestly does
    not apply; jsr.io keeps no per-release license history, so that
    check is skipped there too.
- OSV.dev queries are no longer issued for `jsr:` names (npm's OSV
  ecosystem cannot know them); JSR advisories will light up once OSV
  grows a JSR ecosystem.

## v0.3.17 — 2026-08-05

- **Maven joins the registry lineup** (npm · PyPI · crates.io · RubyGems ·
  Packagist · NuGet · Hex · Go · Pub · CocoaPods · Terraform · Maven) —
  `gradle.lockfile` diffs and Maven packages in SBOMs now get signals from
  the Maven repositories themselves (Central, falling back to Google's
  Maven repository, where the androidx world lives):
  - **Relocation stubs land in the deprecation lane.** A bump onto a POM
    whose `<distributionManagement><relocation>` points at new
    coordinates is flagged with those coordinates and the author's
    message — `● deprecated upstream: relocated to
    com.mysql:mysql-connector-j — MySQL Connector/J artifacts moved to
    reverse-DNS compliant Maven 2+ coordinates.` deps.dev has no
    relocation concept, so these were invisible before.
  - **Registry-verified unlisted detection.** The unlisted flag is
    settled by the repository's own per-version POM: a version Central
    or Google serves loses the flag (deps.dev can lag by days), a
    version both 404 on keeps it.
  - **Release-age backfill** from the POM's `Last-Modified` upload time
    for versions deps.dev hasn't indexed yet, so the ⏱ cooldown flag
    works on freshly cut Java releases too.
  - One anonymous CDN GET per introduced `group:artifact` version — the
    same files every `mvn`/`gradle` build resolves — deduplicated across
    lockfiles, 8-way concurrent, with the winning host remembered per
    package. No CORS on either host, so the browser playground keeps the
    deps.dev-only layer for Maven (like RubyGems).

## v0.3.16 — 2026-08-05

- **Terraform/OpenTofu providers join the registry lineup** (npm · PyPI ·
  crates.io · RubyGems · Packagist · NuGet · Hex · Go · Pub · CocoaPods ·
  Terraform) — another blank spot filled outright: neither OSV nor
  deps.dev has any Terraform system, so `.terraform.lock.hcl` diffs
  carried no registry data at all until now.
  - **Release ages and the ⏱ cooldown flag** from the registries'
    per-version publish times — Dependabot/Renovate provider bumps now
    show how old the incoming release is, and `-fail-on fresh` gates
    them.
  - **Deprecation lane** for providers the registry warns about,
    providers delisted from registry.terraform.io, providers blocked by
    the OpenTofu registry (block reason included), and HashiCorp's
    archived providers with their suggested replacement (`This provider
    has been archived. Please use the templatefile function or the
    Cloudinit provider instead`).
  - **Registry-verified unlisted detection.** The registry's version
    list endpoints cap at 500 entries (the AWS provider has more), so a
    version absent from the list is re-checked against the per-version
    endpoint and only flagged after the registry itself answers 404.
    That distinction is real: HashiCorp pulled AWS provider 5.71.0
    after a regression — it is still tagged on GitHub, and a lockfile
    pinning it gets the ▲ flag. In a 162-commit replay across three
    infra repos it was the *only* flag raised.
  - **Verified changelog links and `-changelogs`** via each provider's
    source repository (from the registry), including intermediate
    releases.
  - Routing follows the lockfile: default-host providers are asked about
    on registry.terraform.io, `registry.opentofu.org/…` pins on
    api.opentofu.org, and custom/private registry hosts are left alone.
  - Playground: registry.terraform.io sends no CORS headers, so the
    browser build gets ages + changelog links from the CORS-open
    OpenTofu mirror instead — and, because a mirror can lag, makes no
    unlisted or deprecation claims there.

## v0.3.15 — 2026-08-05

- **CocoaPods joins the registry lineup** (npm · PyPI · crates.io ·
  RubyGems · Packagist · NuGet · Hex · Go · Pub · CocoaPods) — and it is
  the biggest blank spot filled yet: neither OSV *nor* deps.dev has a
  CocoaPods system, so until now `Podfile.lock` diffs were explained with
  no registry data at all. lockvet now reads the registry the same way
  `pod install` does:
  - **Registry-verified unlisted detection** from the sharded CDN index
    (`all_pods_versions_*.txt` — the exact file CocoaPods resolves
    against): an incoming version missing while the pod's other versions
    are listed is what a deleted or moderated release looks like.
  - **Release ages and the ⏱ cooldown flag** from the trunk API's
    per-version publish timestamps.
  - **Deprecated pods** land in the deprecation lane with the podspec's
    named successor (`● deprecated upstream: deprecated on CocoaPods; in
    favor of FirebaseCrashlytics` — a live catch on `Fabric`).
    `pod trunk deprecate` rewrites every version's podspec, so the
    incoming version's spec carries the verdict.
  - **License changes** old → new from the two versions' podspecs, and
    the **upstream source repo** from `source.git` feeds the tag-verified
    changelog/compare-link layer (Firebase's monorepo links resolve).
- **`Podfile.lock` parsing got the full treatment** while at it:
  - **Via-chains**: the PODS section's requirement lines build the
    dependency graph, and DEPENDENCIES supplies the roots — pod bumps now
    say `(direct)` or `via Firebase › FirebaseCore` like npm and Cargo
    diffs do, and `-only <pod>` follows the chains.
  - **NonRegistry exemptions**: pods pinned from git/path (`EXTERNAL
    SOURCES`) or served by a private specs repo (any `SPEC REPOS` key
    besides trunk) are exempt from registry checks — Signal-iOS's
    git-pinned `LibSignalClient` stays quiet, no false ▲.
- The browser playground reads the CDN through its CORS-open jsDelivr
  mirror (podspecs + version index; trunk sends no CORS headers, so
  in-browser pod reports carry no ages).

## v0.3.14 — 2026-08-05

- **pub.dev joins the registry lineup** (npm · PyPI · crates.io ·
  RubyGems · Packagist · NuGet · Hex · Go · Pub) — and like Packagist and
  hex.pm it *is* the metadata layer for its world: deps.dev has no Pub
  system, so until now `pubspec.lock` diffs had OSV vulnerability data
  but no release metadata at all. One anonymous GET per changed package
  against pub.dev's CORS-open packages API (the browser playground uses
  the identical route) now brings Dart/Flutter to parity:
  - **Release ages and the ⏱ cooldown flag** from each version's
    publish timestamp.
  - **Discontinued packages** land in the deprecation lane with the
    publisher's named replacement (`● deprecated upstream: discontinued
    on pub.dev; replaced by flutter_markdown_plus` — a live catch:
    `flutter_markdown` is discontinued, as are `js` and the retired
    `macros` experiment). **Retracted versions** — ones `dart pub`
    refuses to newly resolve — are flagged the same way (live: `dio`
    5.8.0, `riverpod` 2.3.9). `-fail-on deprecated` gates both.
  - **Registry-verified unlisted detection**: pub.dev never deletes a
    version outside moderation takedowns (retraction keeps it listed),
    so absence-while-siblings-exist is real signal.
  - **Verified changelog/compare links**: the upstream repo from the
    package's pubspec feeds the tag-verified link layer — monorepo
    `/tree/…` paths are reduced to the repo, and the Flutter monorepo's
    `shared_preferences_android-v2.4.6`-style tags resolve to exact
    tag-to-tag diffs.
  - The parser marks git / path / SDK / private-host packages
    NonRegistry, so forked plugins pinned from GitHub (AppFlowy pins
    `permission_handler` that way) are exempt from registry checks
    instead of raising phantom flags. pub.dev keeps no per-release
    license history, so license-change detection is honestly skipped.
- **Version ordering fix for `+` build metadata**: semver's spec says to
  ignore it, but registries that put it in lockfiles order it — Dart
  orders `+N` numerically and Debian repacks carry `+dfsg-N` revisions.
  `0.5.1+10 → 0.5.1+11` was previously mis-rendered as a **DOWNGRADE**
  (the two parsed equal, and a differing-but-equal-comparing pair fell
  into the downgrade branch) in every Dart diff; it now classifies as
  the patch-level upgrade it is, and `1.0.0 → 1.0.0+1` counts as patch.

## v0.3.13 — 2026-08-05

- **The Go module proxy joins the registry lineup** (npm · PyPI ·
  crates.io · RubyGems · Packagist · NuGet · Hex · Go) — two anonymous
  GETs per changed module against `proxy.golang.org`, the same endpoints
  `go get` uses (`GOPROXY` is honoured: a private proxy works, `off`/
  `direct` disables the check):
  - **Retractions with the author's rationale**: a bump onto a version
    its author [retracted](https://go.dev/ref/mod#go-mod-file-retract)
    lands in the deprecation lane with the rationale comment from the
    module's latest `go.mod` (`● deprecated upstream: retracted:
    https://github.com/klauspost/compress/issues/1114`) — including
    retractions deps.dev hasn't re-indexed yet. `-fail-on deprecated`
    gates them.
  - **`// Deprecated:` module notices** are caught even where deps.dev
    misses them (live example: `go.mongodb.org/mongo-driver` →
    "Use go.mongodb.org/mongo-driver/v2 instead").
  - **Registry-verified unlisted detection**: the proxy never removes a
    version once cached, so absence-while-siblings-exist is real signal —
    and a tag deps.dev simply hasn't indexed yet no longer raises a
    false ▲ alarm (it gets its ⏱ age instead).
  - **Release ages for brand-new tags** from `@v/{version}.info`, so the
    ⏱ cooldown flag fires on a Go tag cut minutes ago. Pseudo-versions
    carry their commit time in the version string itself and age for
    free — no request at all.
  - Repos renamed with a redirect serve the *new* module's `go.mod`; its
    directives are never applied to the old path.
  - `proxy.golang.org` sends `Access-Control-Allow-Origin: *`, so the
    [browser playground](https://matteo-sung.github.io/lockvet/) gets
    every signal too.

## v0.3.12 — 2026-08-05

- **Hex joins the registry lineup** (npm · PyPI · crates.io · RubyGems ·
  Packagist · NuGet · Hex) — and like Packagist, hex.pm isn't a
  double-check here, it's the *whole* metadata layer: deps.dev has no Hex
  system, so until now Elixir and Gleam diffs had vulnerability data but
  no ages, no deprecations, nothing. One anonymous GET per changed
  package against hex.pm's CORS-open packages API (the browser playground
  gets every signal too):
  - **Release ages and the ⏱ cooldown flag** from each release's
    `inserted_at` — `-fail-on fresh` now works for the BEAM world.
  - **Retired releases land in the deprecation lane** with the
    maintainer's reason and message (`● deprecated upstream: retired:
    deprecated — Not really maintained, please check out Tesla`);
    `-fail-on deprecated` gates them.
  - **Registry-verified unlisted detection**: hex.pm deletes releases
    only in the first hour (or by admin action against malware) — an
    incoming version missing while the package's other versions are
    listed earns the ▲ flag.
  - **Changelog links**: the upstream repo from the package's links
    powers verified tag-to-tag compare links and `-changelogs`.
  - Hex keeps no per-release license history, so license-change
    detection is honestly skipped for this ecosystem.
- **mix.lock renamed forks resolve correctly**: the lockfile's map key is
  the OTP *application* name, but the Hex *package* name is the atom
  after `:hex` — for renamed forks like `"chatterbox": {:hex,
  :ts_chatterbox, …}` lockvet now reports (and queries OSV/hex.pm for)
  `ts_chatterbox`, fixing both phantom ▲ flags and advisories matched
  against the wrong package's versions.
- **Private Hex repos exempt**: `mix.lock` entries resolved from a
  non-`"hexpm"` repo, and Gleam `manifest.toml` packages with git/path
  sources, are never judged against hex.pm.
- Rate limit note: hex.pm allows 100 anonymous requests/minute; lockvet
  sends one per changed package and surfaces a hint (set `HEX_API_KEY`)
  if you ever hit it.

## v0.3.11 — 2026-08-05

- **NuGet joins the registry lineup** (npm · PyPI · crates.io · RubyGems ·
  Packagist · NuGet). One anonymous GET per changed package against the
  registration index — the same metadata endpoint `dotnet restore` reads,
  CORS-open, so the browser playground gets every signal too:
  - **Unlisted, the way NuGet itself means it.** NuGet is the one
    registry where "unlisted" is a native concept: a *stable* incoming
    version absent from the registration index entirely — what an
    admin-deleted (malicious) package looks like — gets the ▲ flag,
    registry-verified; a version its author merely unlisted
    (`listed:false`, hidden from search but still restorable) lands in
    the deprecation lane instead.
  - **Fewer false ▲ flags than before, not more**: absent *prereleases*
    are now cleared rather than flagged — on NuGet those are
    overwhelmingly CI-feed daily builds (Roslyn nightlies and friends)
    that `packages.lock.json` cannot attribute to their real feed. The
    deps.dev-only layer used to flag them.
  - **Deprecations with the replacement package deps.dev drops**:
    `● deprecated upstream: legacy; use Azure.Storage.Common instead`
    (deps.dev relays only the bare reason).
  - **Release-age backfill** from registration `published` times when
    deps.dev lags (NuGet's 1900-01-01 unlisted sentinel is ignored), and
    **license-change fallback** from per-version `licenseExpression`.
  - Packages with long version histories page their registration index;
    lockvet fetches only the pages whose version range covers a version
    the diff mentions.

## v0.3.10 — 2026-08-05

- **PHP finally gets real metadata: Packagist joins the registry lineup**
  (npm · PyPI · crates.io · RubyGems · Packagist). deps.dev has no
  Composer system at all, so until now `composer.lock` diffs carried
  vulnerability data but no ages, deprecations or licenses. lockvet now
  asks Packagist directly — one anonymous GET per changed package against
  the same p2 metadata CDN `composer update` uses (the CORS-open
  packagist.org API in the browser playground):
  - **Release ages and ⏱ fresh flags** from Packagist's per-version
    publish times — the `-fail-on fresh` cooldown gate now works for PHP.
  - **Abandoned packages** land in the deprecation lane with the
    maintainer's suggested replacement
    (`● deprecated upstream: abandoned; use symfony/mailer instead`) —
    `-fail-on deprecated` covers them.
  - **License changes** old → new from the per-version license lists
    (`-fail-on license`).
  - **`unlisted` detection, registry-verified from the start**: an
    incoming version missing from Packagist while the package's other
    versions are listed — what an unpublished/deleted release looks like.
  - **Verified changelog links and `-changelogs` release notes** now work
    for Composer packages too (the upstream repo comes from Packagist's
    source field).
- **composer.lock packages installed from VCS/path repositories are now
  marked non-registry** (Composer only writes a packagist.org
  `notification-url` for real Packagist installs) — a pinned fork's
  version that never existed on packagist.org cannot produce a false
  `unlisted` flag.
- Unlisted-flag wording no longer says "unknown to deps.dev" — the flag
  has been registry-verified on every covered ecosystem for a while.

## v0.3.9 — 2026-08-05

- **RubyGems completes the registry-signal quartet** (npm · PyPI ·
  crates.io · RubyGems). One anonymous GET per changed gem against the
  compact index — the same Fastly-cached endpoint Bundler itself uses:
  - **`unlisted` flags are now registry-verified for RubyGems.** A yank
    removes the release from the index entirely, so a bump onto a yanked
    or admin-deleted gem keeps the flag: replaying the 2019
    `strong_password` 0.0.7 hijack trips it today (now
    [case study #5](docs/case-studies.md#5-strong_password-2019--the-one-a-human-caught)).
  - **Release ages backfilled from the index's own `created_at`** when
    deps.dev hasn't caught up yet, so a gem published minutes ago still
    gets its ⏱ fresh flag — the exact window the cooldown gate exists for.
  - **`⛨ provenance dropped` now covers RubyGems**
    ([sigstore attestations](https://guides.rubygems.org/trusted-publishing/)),
    with the same three noise gates as npm/PyPI/crates.io. Attestation
    adoption on RubyGems is still small, so the gates stay silent today —
    protection switches on automatically as gems start attesting.
- **Gemfile.lock `GIT` / `PATH` / `PLUGIN SOURCE` gems are now marked
  non-registry** — a pinned fork's version that never existed on
  rubygems.org can no longer produce a false `unlisted` flag, and
  registry lookups skip them entirely.
- Neither RubyGems endpoint sends CORS headers, so the browser playground
  keeps its previous deps.dev-only behaviour for RubyGems; the CLI does
  the full check.

## v0.3.8 — 2026-08-05

- **crates.io joins the registry-signal lineup.** The native build reads
  the sparse index (the same static CDN cargo itself uses — one anonymous
  GET per changed crate, no rate limits) and consults the crates.io API
  only for the few young bumps that need provenance data; the
  [browser playground](https://matteo-sung.github.io/lockvet/) uses the
  CORS-open API for everything:
  - **`⛨ provenance dropped` now covers crates.io** ([trusted
    publishing](https://rust-lang.github.io/rfcs/3691-trusted-publishing-cratesio.html)):
    a young (≤ 30 days) release published *without* the registry's
    `trustpub_data` provenance record, where the outgoing pin and the
    crate's recent stable line all carried it, is what publishing with a
    stolen API token looks like — a token thief can `cargo publish`, but
    cannot make the project's CI pipeline do it. Same three noise gates
    as npm and PyPI. A tenth of the top 100 crates already publish this
    way (`cc`, `time`, `getrandom`, …); their current bumps produce zero
    flags.
  - **`unlisted` flags are now registry-verified for crates.io**: deps.dev
    can lag the registry by days, so lockvet clears the flag for any
    version the sparse index serves (live-verified on a release minutes
    old). What survives is a version crates.io itself lacks — and that
    distinction has teeth on crates.io, where yanked versions *stay in
    the index* and deleted malicious ones vanish entirely.
  - **Yanks surface even before deps.dev indexes them** — the sparse
    index's per-version yank flags act as the lag fallback on the
    deprecation lane (deps.dev-supplied reasons are never overwritten).
- No new flags, no new output: the existing `⛨` / `▲ unlisted` /
  deprecation surfaces, `-fail-on provenance|unlisted|deprecated` gates,
  JSON fields and SARIF rules simply cover Cargo now.

## v0.3.7 — 2026-08-05

- **PyPI joins the registry-signal lineup.** Everything the npm registry
  integration catches now has a PyPI counterpart, powered by one anonymous
  GET per changed package to PyPI's simple API (JSON flavour, PEP 691 —
  CORS-open, so the [browser playground](https://matteo-sung.github.io/lockvet/)
  gets it all too):
  - **`⛨ provenance dropped` now covers PyPI** ([PEP 740
    attestations](https://peps.python.org/pep-0740/)): a young (≤ 30 days)
    release published with *no* attested files, where the outgoing pin and
    the project's recent stable line all attested, is what publishing with
    a stolen PyPI token looks like — trusted publishing keeps attesting, a
    token thief can't. Same three noise gates as npm; a release with
    *mixed* attested/unattested files never flags (that's a publishing
    setup, not a signal). Across the top 1 000 PyPI packages' current
    bumps it flags exactly one — a real week-old attestation-streak break.
  - **`unlisted` flags are now registry-verified for PyPI** like they are
    for npm: deps.dev can lag PyPI by days, so lockvet clears the flag for
    any version PyPI's own version list serves; what survives is a version
    PyPI itself no longer has — what an unpublished (pulled) release looks
    like.
  - **Yanked releases ([PEP 592](https://peps.python.org/pep-0592/)) and
    [PEP 792](https://peps.python.org/pep-0792/) project statuses** surface
    on the deprecation lane: an incoming version whose files were all
    yanked shows the maintainer's yank reason, and a project **archived**
    by its maintainers or **quarantined** by PyPI admins (the
    malware-review state) is called out on every change that still pins
    it — with `-fail-on deprecated` as the gate.
- Provenance wording is now ecosystem-neutral ("a stolen publish token
  can't") in terminal, markdown, and SARIF output.

## v0.3.6 — 2026-08-05

- **`⛨ provenance dropped` — flag young npm releases published without
  sigstore provenance where every previous release attested.** A stolen
  npm token can publish, but it can't make the project's CI attest the
  release — so a package that consistently publishes [provenance
  attestations](https://docs.npmjs.com/generating-provenance-statements)
  suddenly shipping an unattested version is exactly what a token-theft
  attack looks like at T+0, before any advisory exists. Three conditions
  keep it near-silent: the outgoing pin must be attested, the package's
  practice must be established (top stable versions below the incoming one
  all attested — one-off adopters never flag), and the release must be
  young (≤ 30 days — this is a while-it's-happening tripwire, not an
  audit of history; it stays quiet on historical bumps like `chokidar
  4.0.1 → 4.0.2` or `axios 1.13.2 → 1.13.3` where a single manual publish
  broke an attested streak long ago). Zero flags across current bumps of
  ~100 top npm packages. Reads the same npm registry document as the
  install-scripts check — no extra requests, works in the browser
  playground too. Gate with `-fail-on provenance`; JSON carries
  `provenance_dropped` / `unattested_versions`; SARIF emits a
  `provenance-dropped` warning; `queue` sorts affected PRs into the top
  tier.

## v0.3.5 — 2026-08-05

- **`⚙ install scripts added` — flag npm bumps that gain
  execution-on-install.** lockvet now asks the npm registry which versions
  run install scripts (`preinstall`/`install`/`postinstall`) and flags a
  bump whose incoming version runs them while the outgoing version ran
  none — the transition the Shai-Hulud worm and plenty of smaller npm
  attacks used to deliver their payload, visible in registry metadata at
  T+0 with no advisory needed. Only transitions are flagged (brand-new
  deps with scripts and packages that always had them stay quiet: zero
  flags across 92-change npm/cli and 165-change React release diffs).
  Gate with `-fail-on scripts`; JSON carries `install_scripts_added` /
  `scripted_versions`; SARIF emits an `install-scripts-added` warning;
  `queue` sorts affected PRs into the top tier.
- **`unlisted` is now double-checked against the npm registry itself.**
  deps.dev can lag npm by days (real case: a version published 12 days
  earlier still missing from its index), so before flagging an npm version
  lockvet fetches the package's real version list from
  `registry.npmjs.org` and clears anything npm actually serves. All six
  case-study malware versions keep their flag (they are genuinely gone
  from npm); indexing-lag false positives disappear. Zero extra requests:
  the same metadata document powers both checks.
- Queue summary line now says what the top tier means:
  `N alarming (vulns/unlisted/install scripts)`.

## v0.3.4 — 2026-08-05

- **`unlisted` — flag versions their own registry no longer lists.** When
  an incoming version is unknown to the registry index (deps.dev) even
  though *other* versions of the same package are listed, the report says
  so: `▲ not in registry index`. That is what an unpublished or deleted
  release looks like — registries pull malicious versions, and every
  malicious version in [the case studies](docs/case-studies.md)
  (`event-stream@3.3.6`, `flatmap-stream@0.1.1`, `chalk@5.6.1`,
  `ultralytics@8.3.41`, `@ctrl/tinycolor@4.1.1`, `debug@4.4.2`) now trips
  it — no advisory needed. Gate with `-fail-on unlisted`; JSON carries
  `unlisted` / `unlisted_versions`; SARIF emits an `unlisted-version`
  warning; `queue` sorts affected PRs into the top (most-alarming) tier.
- Deliberately conservative to stay quiet on legitimate diffs: packages
  the registry doesn't index at all are never flagged (the *package* must
  be known, the *version* missing), and lockfile-declared non-registry
  packages are skipped — Cargo workspace members and git deps (`source`
  field), npm git/`file:` deps (`resolved` field), poetry `[package.source]`
  tables, uv git/path/editable sources — plus Go pseudo-versions and
  pnpm-style decorated version strings. Verified against real-world diffs
  (helix, zed, fd, ruff, hugo, mastodon, grafana, poetry): zero false flags.
- Case studies doc updated: all four replays now show the flag, and the
  honest-gates section explains what `-fail-on unlisted` does and doesn't
  buy you (it works from registry-takedown time, not T+0).

## v0.3.3 — 2026-08-05

- **`-changelogs` — upstream release notes inline.** Every bump already
  links to the verified tag-to-tag diff; `-changelogs` also *fetches the
  release notes* from the (verified) GitHub source repo — including the
  releases a multi-version jump skips over (`1.19.0 → 1.20.1` shows
  1.19.1, 1.19.2, 1.20.0 *and* 1.20.1; up to 5 per package). Terminal
  output shows trimmed, sanitized excerpts; `-md` puts each package's
  notes in a collapsed `<details>` block — a PR comment reads like
  Dependabot's release-notes section, but for **every** package in the
  diff, transitives included; JSON carries `release_notes` per change.
  Works in all modes (local git, `pr`/`mr`/`compare`, `diff`, MCP via
  `"changelogs": true`) and in the Action (`changelogs: 'true'`).
  One GitHub API call per repository; `GITHUB_TOKEN` / `gh` login raises
  the rate limit. Monorepo tag conventions (`pkg@1.2.3`, `pkg-v1.2.3`,
  Go `dir/v1.2.3`) are matched per package.

## v0.3.2 — 2026-08-04

- **MCP Registry**: lockvet is published to the official
  [MCP Registry](https://registry.modelcontextprotocol.io) as
  `io.github.matteo-sung/lockvet` (OCI package — MCP clients can run it
  via the Docker image with zero install). The image now carries the
  `io.modelcontextprotocol.server.name` annotation, and the repo carries
  `server.json`.

## v0.3.1 — 2026-08-04

- **Windows fix**: `lockvet diff` (and the MCP `vet_files` tool) now
  recognise lockfiles given by Windows paths — `lockvet diff
  C:\tmp\Cargo.lock.orig C:\tmp\Cargo.lock` used to fail to detect the
  format because only forward slashes were treated as separators. Affected
  every prior release; forge and git modes were never affected.

## v0.3.0 — 2026-08-04

- **MCP server**: `lockvet mcp` speaks the
  [Model Context Protocol](https://modelcontextprotocol.io) over stdio, so
  Claude Code, Claude Desktop, Cursor, VS Code, and any other MCP client
  can vet lockfile changes mid-conversation. Four read-only tools mirror
  the CLI: `vet_url` (any PR/MR/compare/commit URL on GitHub, GitLab,
  Bitbucket, Gitea/Forgejo, or Azure DevOps), `vet_git` (a local
  repository), `vet_files` (two lockfiles or SBOMs on disk), and `queue`
  (triage every open Dependabot/Renovate PR of a repo, user, or org).
  Markdown reports by default, `format: "json"` for structure; forge
  tokens come from the environment exactly like the CLI. Hand-rolled
  JSON-RPC — lockvet still has zero dependencies.
- **Browser playground**: [try lockvet without installing it](https://matteo-sung.github.io/lockvet/)
  — lockvet compiled to WebAssembly. Paste a PR/compare/commit URL or drop
  two lockfiles/SBOMs; reports are shareable as deep links.
  *(Shipped on GitHub Pages between v0.2.4 and this release.)*

## v0.2.4 — 2026-07-31

- **Shell completions**: `lockvet completion bash|zsh|fish` prints a
  completion script (subcommands, flags, `-fail-on` values, file/dir
  arguments). Homebrew installs them automatically; release tarballs ship
  them under `completions/`.
- **Man page**: `lockvet man` prints roff; `man lockvet` works out of the
  box with Homebrew, and the tarballs carry `man/lockvet.1`.

## v0.2.3 — 2026-07-31

- **`lockvet queue` on Bitbucket Cloud**: triage a whole workspace or a
  single repo (`lockvet queue bitbucket.org/myworkspace[/repo]`). Author
  specs also match bot *display names* loosely, since Bitbucket bots are
  often app users — `renovate-bot` finds `atlassian-renovate-bot`. Set
  `BITBUCKET_TOKEN`: the unauthenticated rate limit is tight, and a
  mid-scan limit degrades to partial results with a note.
- **`lockvet queue` on Azure DevOps**: project or repo scope
  (`lockvet queue dev.azure.com/ORG/PROJECT[/_git/REPO]`,
  `*.visualstudio.com` too). Creator filtering happens client-side
  (`renovate` finds `Renovate Bot`).
- The queue matrix now covers all five forges: GitHub, GitLab,
  Gitea/Forgejo, Bitbucket Cloud, and Azure DevOps.
- **Julia, Haskell, and Gleam support**: `Manifest.toml` (Julia General
  registry + stdlibs), `stack.yaml.lock`, `cabal.project.freeze`,
  `cabal.config`, and Gleam's `manifest.toml` — 29 formats total.
  *(This entry was added retroactively: the parsers shipped in v0.2.3
  without a changelog line.)*

## v0.2.2 — 2026-07-31

- **Terraform / OpenTofu support**: `.terraform.lock.hcl` (including
  suffix-named variants like atmos's `.plat-uw2-dev-kms-key.terraform.lock.hcl`)
  as lockfile format #24. Default-registry hosts are stripped from provider
  names; OpenTofu and custom-registry addresses keep theirs. `--md` links
  providers to registry.terraform.io / search.opentofu.org pages.
- **Helm support**: `Chart.lock` and Helm v2 `requirements.lock` as format
  #25, every entry labeled direct. Pip-style `requirements.lock` (rye) is
  auto-detected and gets the full PyPI vulnerability/age treatment instead.
- Terraform providers and Helm charts have no OSV.dev ecosystem, so their
  diffs are explained without vulnerability claims — same policy as Nix
  and conda channels.

## v0.2.1 — 2026-07-31

- **Conda support**: `pixi.lock` (schema v4 through v7) and `conda-lock.yml`
  join the lineup (23 formats), including suffix-named unified lockfiles
  (`audio.pixi.lock`, `conda-reqs.conda-lock.yml`). Conda dependency graphs
  (`depends:` / `dependencies:`) drive direct/via-chain labels; pip/pypi
  packages inside either format are matched against **PyPI advisories** on
  OSV.dev and get deps.dev release ages, deprecation and license-change
  data, exactly like any other Python lockfile. Conda channels themselves
  have no OSV ecosystem (yet), so pure-conda diffs are explained without
  vulnerability claims.

## v0.2.0 — 2026-07-25

- **R support**: `renv.lock` joins the lineup (21 formats) — versions,
  `Requirements`-based via-chains, CRAN **and** Bioconductor advisories
  (`RSEC-…`) from OSV.dev, registry links in `--md`. Tolerates real-world
  renv.lock files that serialize R's `NA` unquoted (not valid JSON).
- This release consolidates the 0.1.x line; upgrade freely from any 0.1.x —
  there are no breaking CLI changes.

## v0.1.18 — 2026-07-25

- **Azure DevOps**: `lockvet pr <dev.azure.com PR url>` (also
  `*.visualstudio.com` and self-hosted Server), branchCompare and commit
  URLs, `-comment` (threads posted "closed" so comment-resolution policies
  never block). Auth via `AZURE_DEVOPS_TOKEN` PAT or pipeline
  `SYSTEM_ACCESSTOKEN`. Forge lineup complete:
  GitHub · GitLab · Bitbucket · Gitea/Forgejo · Azure DevOps.

## v0.1.17 — 2026-07-24

- **License-change detection**: a bump whose registry license differs
  old→new is flagged (`MIT → non-standard`), with `-fail-on license` as a
  gate. Conservative: both sides must be known; case-only diffs ignored.

## v0.1.16 — 2026-07-24

- **SBOM support**: CycloneDX & SPDX JSON as lockfile formats
  (`bom.json`, `*.cdx.json`, `*.spdx.json`, …) — one report across every
  ecosystem in a container image, including Alpine/Debian/Wolfi OS packages
  resolved against the right release branch.
- New mode `lockvet diff <old> <new>`: compare two files on disk, no git.
- Version compare understands apk/deb conventions (epochs, `~`, `_git`).

## v0.1.15 — 2026-07-24

- `lockvet queue` on **Gitea/Forgejo** (codeberg.org, gitea.com,
  self-hosted auto-detected).

## v0.1.14 — 2026-07-24

- `lockvet queue` on **GitLab**: triage every Renovate MR of a group or
  project, subgroups included.

## v0.1.13 — 2026-07-24

- **`lockvet queue <owner|owner/repo>`**: triage every open
  Dependabot/Renovate PR in one table, sorted most-alarming first; one
  OSV/deps.dev batch for the whole queue.

## v0.1.12 — 2026-07-24

- **SARIF output** (`-sarif`, Action input `sarif: 'true'`): vulnerability,
  deprecation and license findings as code-scanning alerts anchored to the
  exact lockfile line.

## v0.1.11 — 2026-07-24

- Gitea/Forgejo **compare** URLs (`lockvet <codeberg compare url>`).
- Official **Docker image**: `ghcr.io/matteo-sung/lockvet` (amd64+arm64).

## v0.1.10 — 2026-07-24

- **Verified changelog links**: every bump links to the exact upstream
  tag-to-tag diff, validated against the repo's real tags over git
  smart-HTTP (GitHub, GitLab, Bitbucket, Gitea, Gitiles); OSC 8 hyperlinks
  in the terminal.

## v0.1.9 — 2026-07-24

- **Gitea/Forgejo/Codeberg PRs**: `lockvet <codeberg PR url>`, commit URLs,
  `-comment`.

## v0.1.8 — 2026-07-24

- **Bitbucket Cloud**: PR / compare / commit URLs, `-comment`.

## v0.1.7 — 2026-07-24

- **`-comment`**: post the report on the PR/MR itself, updating in place
  (same marker as the GitHub Action — no duplicates).

## v0.1.6 — 2026-07-24

- **GitLab merge requests**: `lockvet mr group/project!N` or any MR URL;
  self-hosted instances; GitLab compare/commit URLs.
- Fix: multi-version copies no longer cross-compare (10.x+11.3.5 →
  10.x+11.3.6 is a patch, not a major).

## v0.1.5 — 2026-07-24

- **`lockvet compare owner/repo A...B`**: vet any two revisions or a single
  commit on GitHub without cloning; fork syntax `main...user:branch`.

## v0.1.4 — 2026-07-24

- **`lockvet pr owner/repo#N`**: vet any GitHub PR by URL, no clone.

## v0.1.3 — 2026-07-24

- **pre-commit hook** (`.pre-commit-hooks.yaml`) and GitLab CI recipe.

## v0.1.2 — 2026-07-24

- Registry links in `--md`: package names link to npm/crates.io/PyPI/… for
  the incoming version.

## v0.1.1 — 2026-07-24

- `install.sh` verifies checksums; `-b <dir>` / `-v <tag>` flags.
- Fix: Go module proxy hash mismatch from v0.1.0.

## v0.1.0 — 2026-07-24

Initial release: 17 lockfile parsers, semver classification, OSV.dev
vulnerabilities (introduced / fixed / unresolved), release ages with ⏱
fresh flag, deprecation warnings, origin labels (direct / `via <chain>`),
terminal / `--md` / `--json` output, `-fail-on` CI gate, GitHub Action,
`install.sh`, single static binary for 6 platforms.
