# Changelog

All notable changes to lockvet. Versions follow [semver](https://semver.org)
with a 0.x major: minor bumps may consolidate, patch bumps add features and
fixes.

## v0.6.3 — 2026-08-09

- **Conan recipe revisions are pins now.** Every `conan.lock` ref carries
  a `#recipe-revision` — a hash of the *recipe*, the build script Conan
  will execute for that version. lockvet now records it as a pin, so a
  revision change under an **unchanged version** — the build script
  changing under your feet — renders as a neutral ↻ `recipe revision
  f52e03ae3d25 → aaaa03ae3d25` row where it used to be complete silence.
  Neutral on purpose: ConanCenter maintains recipes independently of
  upstream releases and re-exports them for old versions routinely
  (rippled's full `conan.lock` history replays to 55 such rows — all
  legitimate), so this rides the same lane as a container's same-tag
  digest bump: visible, not loud, and never a `-fail-on integrity` gate.
  Revisions are accepted only when hash-shaped, in both Conan 2 flat
  lockfiles and Conan 1 graph locks.

## v0.6.2 — 2026-08-09

- **vcpkg manifests are format #60, and the registry lineup is 22.**
  `vcpkg.json` barely pins versions — the `builtin-baseline` commit does:
  every dependency resolves to what microsoft/vcpkg recorded at that
  commit, so the baseline IS the lockfile. lockvet now verifies each
  baseline bump against the registry repository itself: the commit's own
  date becomes the release age, `old...new` compare links let you read
  what the registry picked up, and a baseline that is **not** a commit in
  the registry's repository — the poisoned-registry shape, where the
  build only resolves on a fork — lands in the ▲ lane with
  vcpkg-specific wording. `overrides` version pins are checked against
  the registry's append-only versions database (a version no port ever
  shipped is real evidence), and `vcpkg-configuration.json` registry
  baselines get the same treatment — a swapped `default-registry`
  surfaces as a resolution move (⇄). Honesty gates: overrides under
  declared `overlay-ports` or custom registries claim nothing
  (microsoft/terminal pins fmt to an overlay-only version exactly this
  way — replayed, quiet), and both baseline and override claims require
  the outgoing value to resolve first. `lockvet pkg vcpkg:<port>`
  resolves latest from the versions database. Replayed 50 manifest-bump
  pairs across microsoft/terminal, cesium-native, OpenVINO and
  onnxruntime: zero noise. Everything works in the browser playground
  too (both endpoints are CORS-open).

## v0.6.1 — 2026-08-09

- **Single-tool version files are format #57.** `.nvmrc` / `.node-version`
  (nvm, fnm, nodenv), `.python-version` (pyenv — multi-version fallback
  lists included), `.ruby-version` (rbenv/rvm — the `ruby-3.3.4` spelling
  is understood), `.go-version`, `.java-version`, `.terraform-version` and
  `.terragrunt-version` (tfenv/tgenv) each pin one tool for a repository,
  every version manager in that tool's ecosystem reads them, and Renovate
  bumps them with dedicated managers. Each pin now rides the asdf/mise
  pipeline: verified `(=tag)` resolutions against the tool's own
  repository tags, compare links and release notes, and ▲ when a concrete
  pin matches no release. Vendor-prefixed values (`corretto-17`,
  `pypy3.10-7.3.16`, `jruby-9.4.5.0`) and symbolic selectors
  (`lts/hydrogen`, `latest:^1.5`, pyenv virtualenv names) honestly claim
  nothing.
- **SDKMAN's `.sdkmanrc` is format #58.** `sdk env` pins
  `candidate=version` per line: `gradle=`, `maven=` and `sbt=` map onto
  the registries lockvet already verifies (the Gradle distribution index
  at services.gradle.org, Maven Central — with ages and real GHSAs),
  `kotlin=`/`scala=` verify against their repos' tags, and SDKMAN's
  vendor-suffixed Java builds (`17.0.9-tem`) render claim-free rows.
- **`mise.lock` is format #59 — with integrity pins.** mise's own lockfile
  records the exact resolved version per tool plus per-platform
  sha256/blake3 checksums of the artifacts mise downloads. lockvet reads
  the checksums as artifact-scoped integrity pins: a checksum that changes
  while its version stays put — the poisoned-download shape — flags
  **‼ REPINNED** (`-fail-on integrity` gates it), while newly added
  platforms and per-distro artifact variants (disambiguated by `options`)
  never flag. The `backend` string picks the pipeline: `core:*` and bare
  names ride the tool map, `npm:`/`cargo:`/`pipx:`/`gem:`/`dotnet:`/`go:`
  get the full registry treatment, `ubi:`/`aqua:`/`github:`/`spm:` verify
  against the named repo's tags, `asdf:`/`vfox:`/`http:` plugins honestly
  claim nothing. Both header shapes in the wild parse (the documented
  `[tools.x.platforms.linux-x64]` and the quoted
  `[tools.x."platforms.linux-x64"]` mise actually writes, plus the legacy
  `[tools.x.checksums]` asset table).

## v0.6.0 — 2026-08-09

- **asdf/mise toolchain pins are formats #55–56.** `.tool-versions` and
  `mise.toml` (plus `.mise.toml`, `mise.local.toml` and `mise/config.toml`
  locations) pin the exact toolchain a project runs — node, python,
  terraform, kubectl — `mise up` and Renovate's `asdf`/`mise` managers bump
  them like lockfile entries, and nothing vets them. Every pin is now
  verified against the tool's OWN repository tags via a curated ~90-tool
  map that speaks each repo's tag dialect (`go1.23.4`, ruby's `v3_4_2`,
  Erlang's `OTP-27.1.2`, `jq-1.7.1`, `kustomize/v5.8.1`, PostgreSQL's
  `REL_18_4`, `swift-6.1-RELEASE`, yarn's 1.x/berry split): verified
  `(=tag)` resolutions with compare links and `-changelogs` release notes,
  fuzzy pins (`node = "22"`) resolved to what they'd install today, and
  the ▲ not-a-release flag when a concrete pin matches no tag — the same
  check that catches the tj-actions attack shape in workflows. mise's
  backend-prefixed tools are real registry packages and get the full
  registry treatment (`npm:prettier` → npm, `cargo:eza` → crates.io,
  `pipx:`/`pip:` → PyPI, `gem:`, `dotnet:`, `go:` — advisories, ages,
  deprecations, typosquat checks); `ubi:`/`aqua:`/`github:`/`spm:` tools
  verify against the named GitHub repo's tags; `gradle`, `maven` and `sbt`
  pins ride the registries lockvet already verifies (services.gradle.org,
  Maven Central). Honesty rules: plugin-sourced tools (`asdf:`, `vfox:`),
  symbolic selectors (`latest`, `lts`, `system`, `ref:`/`path:`/`prefix:`
  pins), letter-suffixed builds (`3.13t`) and vendor-prefixed Java
  versions claim nothing; the curated map only lists repos with complete
  tag history, and every entry is live-validated in tests. `lockvet pkg
  tool:node` (also `tool:ubi:owner/repo`) vets a tool release before you
  switch, resolving "latest" from the tool's own tags.

## v0.5.31 — 2026-08-09

- **sbt build definitions + `project/build.properties` are formats
  #53–54.** Scala has no npm-style lockfile — the build definition is the
  pin file and scala-steward bumps it in place. `"org" %% "artifact" %
  "1.2.3"` resolves the Scala binary suffix from the same file's
  `scalaVersion` (including `val` references) so the registry artifact
  (`cats-core_2.13`) gets OSV advisories, Maven Central ages and unlisted
  checks; `addSbtPlugin(…)` pins resolve under the sbt cross-suffix
  (`sbt-scalafmt_2.12_1.0` — the name Central actually serves);
  `CrossVersion.full`/`for3Use2_13`/`for2_13Use3` map to their documented
  suffixes; anything unknowable from the file alone honestly claims
  nothing. `project/build.properties` pins sbt itself — a real Maven
  Central artifact with real advisories (try `lockvet pkg
  maven:org.scala-sbt:sbt@1.10.7`). Validated on 240 replayed commits
  across playframework, scala-steward, http4s and zio: 0 failures, 0
  false positives.

## v0.5.30 — 2026-08-09

- **Build-tool wrappers are formats #51–52.** `gradle-wrapper.properties`
  `distributionUrl` pins are verified against Gradle's own version index
  at services.gradle.org (release ages, withdrawn-as-broken releases,
  registry-verified unlisted checks — snapshot/nightly pins exempt), and
  a pinned `distributionSha256Sum` is cross-checked against the checksum
  Gradle actually publishes: the wrapper will happily verify a poisoned
  distribution against a poisoned checksum, so a pin matching no official
  checksum lands in the ‼ lane, and a matching one renders ✔ digest
  verified. `.mvn/wrapper/maven-wrapper.properties` pins parse as
  ordinary Maven coordinates (`org.apache.maven:apache-maven`) and get
  the full Maven treatment. Corporate mirror URLs stay claim-free in
  both. `lockvet pkg gradle:gradle` resolves the current release.

## v0.5.29 — 2026-08-09

- **Gradle build scripts are format #50.** `build.gradle` /
  `build.gradle.kts` (plus `settings.gradle(.kts)` and any other
  `*.gradle(.kts)` script) parse as pin files: coordinate string literals,
  Groovy map / Kotlin named-argument forms, `plugins { id(…) version … }`
  blocks resolved as Plugin Portal markers, and `$version` interpolation
  against same-file `ext`/`def`/`val`/`extra[…]` assignments — a
  Log4Shell-era `ext.log4jVersion` downgrade surfaces its advisories even
  though no dependency line changed. Dynamic versions, unresolved
  properties and SNAPSHOTs claim nothing. Also: `pkg maven:` latest is
  now stable-preferring (no more `3.0.0-beta3` for log4j-core).

## v0.5.28 — 2026-08-09

- **Maven `pom.xml` is format #49.** Maven has no npm-style lockfile —
  the POM's versions *are* the pins, and Dependabot/Renovate bump them in
  place — so lockvet now reads the manifest itself: `<dependencies>` and
  `<dependencyManagement>` entries with explicit versions (BOM imports
  included — bumping a `junit-bom` or `spring-boot-dependencies` import is
  the everyday Renovate shape), the `<parent>` coordinate
  (`spring-boot-starter-parent` bumps are the single most common Java
  dependency PR), `<build>` plugins and extensions (default groupId
  `org.apache.maven.plugins`, as Maven itself defaults), and the same
  blocks inside `<profiles>`. `${property}` references resolve against the
  POM's own `<properties>` and the `project.*` built-ins — a Log4Shell-era
  `<log4j.version>` property downgrade surfaces with its advisories even
  though no `<dependency>` block changed. Honesty rules: versions that
  reference the project's own version (`${project.version}`, `${revision}`,
  `${sha1}`, `${changelist}`) mark reactor siblings NonRegistry — no
  registry claims about internal modules; unresolved properties,
  version-less (managed) dependencies, ranges and `LATEST`/`RELEASE`
  dynamics claim nothing; SNAPSHOT and system-scope dependencies stay
  NonRegistry. Everything else rides the existing Maven pipeline: OSV
  advisories with "fixed in X", release ages and the ⏱ cooldown from
  Maven Central/Google, relocation stubs in the deprecation lane,
  registry-verified unlisted checks, verified compare links and
  `-changelogs` release notes. ISO-8859-1/windows-1252 POM encodings are
  decoded tolerantly. `audit` walks find every `pom.xml` in the tree, and
  the pre-commit hook covers it.

## v0.5.27 — 2026-08-09

- **CircleCI configs are format #48, and the CircleCI orb registry is
  registry #21.** `.circleci/config.yml` (plus continuation configs and
  fragments under `.circleci/`, behind a CI-shape gate) pins two kinds of
  dependencies, and lockvet now reads both. `orbs:` entries
  (`node: circleci/node@5.1.0`) get the registry treatment from the orb
  registry's own API — release ages and the ⏱ cooldown flag, floating
  pins (`volatile`, `5`, `5.1`) resolved to the release they fetch today
  ("volatile (=5.4.2)"), verified compare links and `-changelogs` release
  notes from the orb's `display.source_url` repository, and — because
  published orb versions are immutable — registry-verified **▲ not in
  registry index** detection for pins the full version list omits, absence
  re-proven uncached before it is claimed. `dev:*` versions (mutable by
  design), inline orb definitions and templated references stay
  claim-free. Docker executor `- image:` refs get the Dockerfile registry
  treatment; `machine:` VM image labels are skipped, and block scalars are
  opaque. `lockvet pkg orb:namespace/name` vets an orb before you add it
  (21st `pkg` ecosystem). An orb the registry answers null for makes no
  claims — private Server-install namespaces and typos look the same from
  outside, and silence is the honest read.

## v0.5.26 — 2026-08-09

- **`$CI_SERVER_FQDN` component pins resolve in URL modes.** A
  `.gitlab-ci.yml` on disk never says which GitLab instance runs its
  pipelines, so `$CI_SERVER_FQDN/ns/proj/name@1.2.3` component pins were
  honestly claim-free everywhere. But an MR URL, a compare URL, or a
  `queue` scope *names the instance* — so `mr`, `compare`, and `queue`
  modes (and the playground's URL tab) now resolve those pins against
  the fetched host and give them the full tag-verification treatment:
  real-tag verification with **▲ not a release**, floating-form
  resolution, compare links, and `-changelogs`. This is the dominant way
  gitlab.com projects pin components (gitlab-org's own repos included),
  so most real component-bump MRs gain verification. Local/`pr`-on-disk
  reads stay claim-free, and `include: project:` + `ref:` pins keep
  their no-claims contract even when the instance is known — a `ref:`
  can be a branch or SHA on a private project.

## v0.5.25 — 2026-08-09

- **GitLab CI configuration is read — format #47.** `.gitlab-ci.yml`
  (plus suffix-named variants like `backend.gitlab-ci.yml` and CI
  fragments under `.gitlab/` or `.gitlab-ci/` directories) pins
  dependencies in two places, and both now get the full treatment in
  every mode:
  - **`include: component:` pins** (CI/CD Catalog components) are
    verified against the component project's real tags over anonymous
    git smart-HTTP — the GitHub Actions machinery, pointed at GitLab.
    GitLab's floating forms resolve to the release they mean today:
    `@2` / `@2.0` semver range shorthands and `@~latest` all display the
    concrete version (`2 (=2.3.0)`), jumps are classified from the
    resolved versions, and a pinned version matching no tag in the
    project raises **▲ not a release** — the tj-actions attack shape,
    for GitLab. Compare links point at the project's tags and
    `-changelogs` renders the component's `CHANGELOG.md` sections for
    the exact versions a bump pulls in.
  - **job `image:` and `services:` refs** are container pulls the runner
    performs — they ride the existing image-registry verification
    (digest-vs-tag, unknown tags, Docker Hub ages). Block scalars
    (`script: |`) are opaque, templated values pin nothing, and
    `variables:` blocks are exempt.
  - `include: project:` + `ref:` pins become version rows but stay
    claim-free: the file never records which GitLab instance hosts the
    project, so lockvet won't guess (same for `$CI_SERVER_FQDN`-prefixed
    component pins).
  - `lockvet pkg component:gitlab.com/components/opentofu/full-pipeline`
    vets a component before you include it (latest = newest stable tag,
    what `@~latest` would fetch); the MCP `vet_package` tool accepts the
    same spec.

## v0.5.24 — 2026-08-09

- **Dev Containers are read — format #46.** `devcontainer.json` (and
  `.devcontainer.json`, subfolder variants) names the container your
  editor and Codespaces actually build: the `"image"` is verified exactly
  like a Dockerfile `FROM`, and every OCI-referenced Feature under
  `"features"` (`ghcr.io/devcontainers/features/go:1`, digest pins
  included) is verified against the registry through the same
  distribution API — a Feature tag the registry does not serve flags ▲,
  digest movements are explained, and Renovate's devcontainer-manager
  bumps get real version rows. JSONC is understood (comments + trailing
  commas, as the VS Code templates ship). Compose-/Dockerfile-based
  configs, local-path Features, tarball URIs and legacy host-less Feature
  ids honestly pin nothing. Works in every mode: diffs, PR vetting,
  `audit` (`.devcontainer/` trees are discovered), and the playground.

## v0.5.23 — 2026-08-09

- **Helm values files are read — format #45.** The standard chart image
  convention — an `image:` mapping with `repository:` and `tag:` children
  (Bitnami-style `registry:` and `digest:` too) — is read straight out of
  `values.yaml`, `values-prod.yaml` / `app.values.yaml` overlays, and
  arbitrarily named helmfile/Argo value overlays discovered under GitOps
  directory conventions or diff-mode content sniffing. That's the exact
  shape Renovate's `helm-values` manager bumps, and nothing else vets it:
  the image pins inside get the full registry treatment (digest
  verification, unknown tags, ages, same-tag digest moves), and a
  `digest:` child lands as an integrity pin.
- **Noise design:** convention-named values files also accept bare
  `image: ghcr.io/owner/app:v1.2.3` scalars — only when a tag or digest
  is present, so `image: nginx` and asset paths pin nothing; files merely
  discovered (dir conventions, sniffing, playground drops) require the
  structured `repository:`/`tag:` shape. Block-scalar bodies (`config: |`
  — embedded app configuration) are opaque to the scanner, templated
  values (`{{ … }}`, `$(VAR)`, `${VAR}`) are never pins, and YAML anchors
  on values (`tag: &img 1.2.3@sha256:…`) resolve like everywhere else.
- Validated against 133 values-file commit replays across argo-helm,
  grafana/helm-charts and kdwils/homelab (0 failures, 0 false flags;
  the only online flags were true ones — Bitnami's 2025 Docker Hub tag
  purge makes old `docker.io/bitnami/*` pins genuinely unpullable) plus
  a live end-to-end PR replay of the motivating shape.

## v0.5.22 — 2026-08-08

- **`go.sum` is now read — as a pins-only ledger (format #44).** Version
  churn stays go.mod's story (a bump PR shows no duplicate rows from
  go.sum), but a **same-version `h1:` hash edit flags ‼ REPINNED**: a
  released module version's hash never changes legitimately, so this is
  the poisoned-go.sum shape — the only way a tampered module gets past
  `go mod verify`, and for `GOPRIVATE` modules the only check there is.
  Zip and `/go.mod` manifest hashes are compared artifact-scoped (they
  never cross); an untidied go.sum that grows entries in the same edit
  that swaps an existing version's hash still gets the repin check on the
  common versions; SARIF alerts anchor the exact edited line.
- **Bundler ≥ 2.6 `CHECKSUMS` become integrity pins.** A same-version
  sha256 swap in `Gemfile.lock` flags ‼ REPINNED; platform gems
  (`1.16.0-x86_64-linux`) keep their own line and their own hash;
  entries recorded without a checksum stay honest no-claims.
- **Appraisal lockfiles route to the Gemfile.lock parser.** Suffix-named
  `gemfiles/rails_7.0.gemfile.lock` variants (14k+ files on GitHub) are
  the same format exactly and now get the same treatment.

## v0.5.21 — 2026-08-08

- **`-changelogs` now finds mid-history releases in busy monorepos.**
  Release-notes lookup used to read only a repository's newest 100
  releases; in monorepos that cut releases daily (Helm chart repos like
  `prometheus-community/helm-charts`, release-please workspaces), any
  bump older than a few weeks fell past that window and rendered a
  compare link with no excerpt — the known gap for chart pins in
  Kubernetes manifests, Flux HelmReleases, Argo CD Applications and
  `Chart.lock`. Now every change the list missed gets one exact
  `releases/tags/{tag}` probe (capped per repository), so the excerpt
  renders for any release age. The playground's no-verified-tag path
  tries the usual tag-naming conventions directly, so in-browser
  reports gain the same coverage.

## v0.5.20 — 2026-08-08

- **Argo CD Application chart pins are lockfile entries.** An
  `Application` whose `spec.source` carries `chart:` pins that chart at
  `targetRevision:`, and the inline `repoURL:` is the chart repository
  itself — so bumps are verified against that repository's own
  `index.yaml` like Flux HelmReleases: release ages, deprecated charts,
  the prune-guarded unlisted check, verified changelog links.
  Multi-source `spec.sources` lists work per item, and `ApplicationSet`
  templates (`spec.template.spec.source`/`.sources`) get the same
  reading — `{{ … }}` parameters are recognized as templates, not
  literal pins. Only exact revisions count (`1.2.*`, `>=1.0.0`, `*` and
  branch names track the repo and pin nothing); Git-source Applications
  (`path:` instead of `chart:`) are left alone; OCI `repoURL`s yield the
  version row without registry claims. Discovery adds the Argo
  conventions: `application.yaml`, `applicationset.yaml`, `appset.yaml`
  basenames and `argocd/`, `argo/`, `argo-cd/`, `applications/`,
  `applicationsets/` directories (strict `apiVersion:` + `kind:` gate as
  always), and changed-YAML sniffing covers arbitrary layouts in diff
  modes.
- **Regenerated chart indexes no longer claim ages.** Some Helm
  repositories rebuild `index.yaml` and stamp historical entries with
  the generation time — app.getambassador.io does it on every request
  (every chart looked published today), kyverno's index did it once
  (three years of releases share one instant). No chart publishes three
  versions of itself within an hour, so a ≥3-version cluster of
  `created` times inside a one-hour window is treated as a generation
  artifact: versions in the cluster claim no age or ⏱ freshness,
  versions outside it keep their real timestamps.
- The pre-commit hook's `files` pattern now matches the Flux and Argo CD
  file conventions and the GitOps directory conventions the other modes
  already discovered.

## v0.5.19 — 2026-08-08

- **Changed YAML is content-sniffed in diff modes.** GitOps repos keep
  workload manifests under arbitrary layouts (`default/nzbget/nzbget.yaml`)
  that no directory or basename convention can anticipate. In diff modes —
  local git, `pr`/`mr`/`compare`, `queue`, the playground's URL mode —
  every changed `*.yaml`/`*.yml` that nothing else claims is now sniffed
  as a Kubernetes manifest, behind the same strict top-level `apiVersion:`
  + `kind:` gate (non-Kubernetes YAML stays silent; Helm `templates/`
  stays excluded). Remote fetches cap sniff candidates at 20 files per
  diff so a big refactor PR can't balloon the download count. `lockvet
  audit` directory walks keep convention-based discovery.
- **Helm values `image:` mappings are pins.** Inside a `HelmRelease`'s
  `values:`, the standard chart image shape — `image:` with `repository:`
  and `tag:` children, plus Bitnami-style `registry:` and `digest:` — is
  read as an image pin and gets the container-registry verification.
  That's the exact field Flux image automation and Renovate bump in
  home-ops repos: replaying billimek/k8s-gitops turns entire eras of
  `Auto-release …` and `feat(container): update image …` commits from
  "no lockfile changes" into precise image-bump rows, both the 2020 Flux
  v1 era and current Renovate commits. Templated values (`{{ … }}`,
  `$(VAR)`, `${VAR}`) and tag-less mappings are skipped, and the shape is
  only read inside `HelmRelease` documents under a `values:` path — an
  arbitrary CR can't feed it.
- **YAML anchors on pin values parse.** The current app-template
  convention writes `tag: &hass-image 2026.8.1@sha256:…` — a leading
  `&name` is always an anchor (plain scalars can't start with `&`), so
  the anchor is stripped and the value behind it is read, embedded
  digest included; the digest becomes an integrity pin and gets registry
  verification. Alias values (`*name`) can't be resolved by a line
  scanner and honestly stay silent.

## v0.5.18 — 2026-08-08

- **Flux HelmRelease and OCIRepository CRs are pins.** A `HelmRelease`
  whose `spec.chart.spec.version` is an exact pin becomes a Helm package:
  when the `sourceRef`'s `HelmRepository` is defined in the same file, its
  URL rides along and the bump is verified against that chart repository's
  own `index.yaml` — release ages, deprecated charts, unlisted versions,
  and `-changelogs` release notes. A sourceRef defined in another file, or
  an OCI/Git source, still yields the version row and jump classification —
  just no registry claims, because there is no `index.yaml` to honestly
  check. The legacy Flux v1 flat shape (`spec.chart.repository` +
  `name` + `version`) carries its URL directly and gets the full
  treatment. Version ranges pin nothing and are skipped, and charts with
  a path shape (`./charts/app` from a `GitRepository`) are exempt.
- **`OCIRepository` `ref.tag` / `ref.digest` pins get the image
  treatment.** Modern chartRef setups put the chart version in an
  `OCIRepository`'s `spec.ref.tag` — exactly the field Renovate bumps in
  home-ops-style repos. That is an OCI artifact pin, so it now gets the
  Dockerfile registry verification: ✔ digest verified / ‼ tag mismatch /
  ▲ unknown tag against the allowlisted registries. `ref.semver` ranges
  are skipped.
- **Discovery covers the Flux layouts.** New conventional directories
  (`apps/`, `infrastructure/`, `infra/`, `flux/`, `flux-system/`,
  `chart/`, `charts/`) and basenames (`helmrelease.yaml`,
  `helm-release.yaml`, `release.yaml`, `ocirepository.yaml`,
  `helmrepository.yaml`) — same strict `apiVersion:` + `kind:` gate, so
  matched non-Kubernetes YAML stays silently ignored.
- **`k8s.gcr.io` pins verified.** The frozen legacy Kubernetes registry
  redirects every request to registry.k8s.io with identical paths, so
  pins against the old host are now checked against the live one instead
  of being skipped as an unknown host.
- **Fixed: cached registry responses could produce a false `‼ tag
  mismatch`.** The on-disk response cache dropped the
  `Docker-Content-Digest` header, so a warm-cache run could claim a
  digest-pinned image no longer matches its tag (with an empty "tag now
  serves"). The header is now cached, and manifest digests additionally
  fall back to the sha256 of the served bytes — the content-addressed
  definition — so the claim is right even against old cache entries.

## v0.5.17 — 2026-08-08

- **Kubernetes manifests and kustomizations: formats #42 and #43.** What
  your cluster pulls is a pin like any other. Every `image:` under a
  `containers:` / `initContainers:` / `ephemeralContainers:` list in a
  Kubernetes manifest (Deployments, StatefulSets, CronJobs — any nesting)
  now gets the same registry verification as Dockerfile images: digest
  pins checked against what the tag serves today, `▲ not in the registry`
  for tags the registry doesn't serve, Docker Hub release ages, `↻` for
  routine same-tag digest bumps. Discovery is convention-based and
  strict: `*.yaml` under `k8s/`, `kubernetes/` or `manifests/`
  directories, `*.k8s.yaml` suffixes, and conventional workload basenames
  (`deployment.yaml`, `statefulset.yaml`, …) — a document must declare
  top-level `apiVersion:` and `kind:` to count, non-Kubernetes YAML that
  happens to match is silently ignored, Helm `templates/` directories are
  excluded, and templated image values (`{{ … }}`, `$(VAR)`, `${VAR}`)
  are skipped rather than guessed at.
- **`kustomization.yaml` is a lockfile too.** `images:` transformer
  entries (`newTag:` / `digest:` — exactly the values Renovate and Flux
  image automation bump) are verified like any other image pin, and
  `helmCharts:` entries are checked against the chart repository's own
  `index.yaml` like `Chart.yaml` dependencies (release ages, deprecated
  charts, the unlisted check). `oci://` and `file://` chart repos are
  exempt, range constraints are skipped.
- **`lockvet audit` skips `testdata/` directories.** Go's reserved
  fixture directory holds deliberately fabricated pins (argo-cd's
  kustomize fixtures pin images that don't exist); audit walks no longer
  descend into it. Naming a `testdata` directory explicitly still audits
  it.

## v0.5.16 — 2026-08-08

- **Ansible Galaxy: `requirements.yml` is format #41 and registry #20.**
  Ansible content has no OSV ecosystem and no deps.dev coverage — nothing
  vets a `requirements.yml` bump. Now lockvet parses Galaxy requirements
  files (collections and classic roles, the old bare role-list shape
  included; exact version pins only — pip-style `==8.6.0` spellings
  count, range constraints are skipped) and asks
  galaxy.ansible.com itself: release ages and the ⏱ cooldown flag from
  the v3 collection index (the exact API `ansible-galaxy collection
  install` resolves against) and the v1 role index, deprecated
  collections in the deprecation lane, upstream source repositories from
  each collection version's own metadata (verified compare links and
  `-changelogs` work), and a registry-verified unlisted check for
  collections — Galaxy keeps every published version, so a 404 while the
  collection IS listed is what a pulled release looks like; absence is
  re-proven uncached before it is claimed. Honesty rules: classic roles
  never get absence claims (their index only updates when the owner
  re-imports), `git`/`file`/`url` entries and private Automation Hub
  `source:` hosts are exempt, and the Helm-shared `requirements.yaml`
  basename is content-sniffed. `lockvet pkg ansible:namespace.name`
  resolves latest (collections first, roles as fallback). The browser
  playground skips this layer (galaxy.ansible.com sends no CORS
  headers); the CLI covers it fully.
- **package-lock v2/v3 aliased installs no longer flag as unlisted.**
  `"react-loadable": "npm:@docusaurus/react-loadable@^5.5.2"` records the
  real package in the entry's `name` field; registry claims under the
  alias name were wrong (the yarn `npm:` alias fix from v0.4.0, now
  applied to package-lock.json too).

## v0.5.15 — 2026-08-08

- **Helm chart repositories: registry signals for `Chart.lock` — and
  `Chart.yaml` manifests now parse.** Helm has no OSV ecosystem and no
  deps.dev coverage, so chart bumps were signal-free; now lockvet asks
  the chart repository's own `index.yaml` — the exact document
  `helm dependency update` resolves against: release ages and the ⏱
  cooldown flag, deprecated charts in the deprecation lane (a bump onto
  a `deprecated: true` release flags directly; a chart whose *latest*
  release is deprecated flags any bump, worded apart — catches things
  like the retired `stable/…` charts and grafana-agent-operator),
  upstream source links from each release's `sources` (verified compare
  links and `-changelogs` work, including monorepo `name-1.2.3` tag
  conventions), and a **prune-guarded** registry-verified unlisted
  check: chart repositories routinely prune old releases from their
  index, so only a missing version that sorts at or above the oldest
  release the index still lists is flagged — and absence is re-proven
  with an uncached fetch before it is claimed. The repository URL comes
  from the lockfile itself, so any HTTP(S) chart repo works; `oci://`
  references have no index and are honestly skipped, `file://`
  subcharts are exempt. New: `Chart.yaml` (and Helm v2
  `requirements.yaml`) parse as manifests — most repos commit only the
  manifest and Renovate bumps it in place; exact version pins are read,
  range constraints (`^`, `~`, `1.x`) are not pins and are skipped.
  `lockvet pkg helm:<repo-url>/<chart>[@version]` vets a chart before
  you add it, resolving "latest" against that repository's index
  (deprecated releases skipped). Works in every mode; in the browser
  playground per-repo reachability depends on the chart repo's CORS
  headers. Replayed 100 chart-touching commits from argo-helm and
  grafana/helm-charts history: zero false flags, one real catch.

## v0.5.14 — 2026-08-08

- **rebar.lock: format #40.** Erlang's rebar3 lockfile gets the full Hex
  treatment mix.lock already had: OSV advisories, release ages and ⏱
  published-days-ago, retirements with the maintainer's reason, and the
  registry-verified `▲ not in registry index` check — all straight from
  hex.pm. The lock's own level numbers mark direct dependencies, so
  `(direct)` / `via …` labels need no manifest. Renamed forks resolve
  under their real Hex package name (`{<<"uuid">>,{pkg,<<"uuid_erl">>,…}}`
  is reported as `uuid_erl` — the name hex.pm and OSV actually know);
  `{git,…}` / `{path,…}` entries pin a commit, not a release, and are
  exempt from registry judgement. `pkg_hash` / `pkg_hash_ext` checksums
  become integrity pins: a same-version hash change surfaces as
  `‼ REPINNED` (hex.pm tarballs are immutable — a changed hash means the
  artifact this pin expects was replaced). Works in every mode: diff, PR
  URLs, `audit`, `queue`, MCP, pre-commit, and the browser playground
  (hex.pm is CORS-open). Replayed 220 rebar.lock commits from rebar3 and
  VerneMQ history: zero false flags.

## v0.5.13 — 2026-08-08

- **pre-commit configs: format #39.** `.pre-commit-config.yaml` is a
  lockfile too: every `repos:` entry pins a hook repository at an exact
  `rev:` — code pre-commit clones and runs on every commit on every
  contributor's machine, bumped by `pre-commit autoupdate` and Renovate
  like any other dependency. Names keep their host
  (`github.com/psf/black`), so hooks on any git forge work. Revs get the
  same treatment as GitHub Actions workflow pins: SHA revs resolve to
  the release they equal, jumps are classified from the real versions,
  verified compare links + `-changelogs` release notes, and a rev that
  matches no tag in the hook repository raises `▲ not a release`
  (`-fail-on unlisted` gates; `repo: local` / `repo: meta` exempt).
  Works in every mode: diff, PR URLs, `audit`, `queue`, MCP, the
  playground, and the pre-commit hook itself now watches the config that
  runs it.
- **`lockvet pkg pre-commit:owner/repo`** vets a hook repo before you add
  it (`github.com` implied; any `host/owner/repo` works), resolving
  "latest" to the newest stable tag — what `pre-commit autoupdate` would
  pin.

## v0.5.12 — 2026-08-08

- **Container base images: formats #37 and #38.** `Dockerfile` /
  `Containerfile` (variant names like `Dockerfile.alpine` and
  `dev.Dockerfile` included) and Compose files (`docker-compose.yml`,
  `compose.yaml`, overrides) are lockfiles now: every `FROM` base image
  (multi-stage aware, `ARG` defaults expanded, `--platform` flags and
  stage references skipped), `COPY --from=` images, the `# syntax=`
  BuildKit parser directive Renovate manages, and every `image:` under
  Compose `services:` (local `build:` contexts skipped) — in every mode:
  diff, PR URLs, `audit`, `queue`, MCP, the pre-commit hook.
- **Verified against the image registry itself** (new `ocireg` layer —
  whole images have no OSV ecosystem and no deps.dev system): digest
  pins (`image:tag@sha256:…`) are checked against what the tag serves
  *today* — exact match shows `✔ digest verified`, a pin the tag no
  longer serves lands in the `‼ tag mismatch` lane, a digest the
  registry has never seen is `▲` unlisted; a tag the registry doesn't
  serve (while the repository is known) is `▲ not in the registry`
  (`-fail-on unlisted` gates); release ages + the ⏱ fresh flag come
  from Docker Hub's per-tag `last_updated` for Hub images. Lookups run
  only against a fixed allowlist of public registries (Docker Hub,
  ghcr.io, quay.io, mcr.microsoft.com, gcr.io, registry.k8s.io,
  public.ecr.aws, registry.gitlab.com) — private hosts are never
  queried.
- Same-tag digest bumps (the routine Renovate "update digest" PR) render
  as a neutral `↻ digest a → b` row — with the new pin verified — not as
  an alarming repin.
- Cache honesty fix (found pre-release): anonymous registry pull tokens
  are short-lived credentials and are now **never cached** — the response
  cache had been storing them, so a warm run could replay an expired
  token, get 401s, and silently drop every digest claim. Registry answers
  fetched with an anonymous token are cached keyed as anonymous (they are
  what any anonymous client gets), so warm runs stay fast; no credential
  is ever written to disk.

## v0.5.11 — 2026-08-08

- **Native Linux packages.** Every release now ships `.deb`, `.rpm`, and
  `.apk` packages for amd64 and arm64 alongside the tarballs — binary,
  bash/zsh/fish completions, and the man page, installable with
  `dpkg -i` / `rpm -i` / `apk add --allow-untrusted`. Packages are
  checksummed in `checksums.txt` and carry Sigstore build provenance
  like every other artifact (`gh attestation verify <pkg> --owner
  matteo-sung`). Built with [nfpm](https://nfpm.goreleaser.com/);
  config lives in `packaging/nfpm.yaml`.
- Playground: new **"Vet a package" tab** — `lockvet pkg` fully
  in-browser, with `#pkg=` share links
  ([try `npm:chakl`](https://matteo-sung.github.io/lockvet/#pkg=npm%3Achakl)).
  Composer `latest` resolution now works in the browser too.

## v0.5.10 — 2026-08-08

- **Zig `build.zig.zon` — format #36.** Zig has no lockfile beyond the
  manifest and no central registry: every dependency pins a source archive
  URL plus the content hash `zig build` verifies. lockvet now reads both:
  - **Versions worth diffing**: the URL's commit revision when it has one
    (the true content identity — upstreams move revisions for months
    without bumping the version embedded in the hash), else the semver
    from a 0.14+ `name-1.2.3-<digest>` hash, else the release tag from
    `/archive/refs/tags/…` / `git+…#tag` URLs, else a digest prefix.
    Rev/digest bumps render as `changed ?` — hex doesn't order.
  - **‼ integrity changed**: same version, different hash — the archive
    this pin expects was replaced (a moved tag, a re-cut tarball, a
    hijacked mirror, or a hand-edited manifest). The smuggle shape: an
    attacker who swaps the URL's content *must* also edit the hash.
  - **⇄ resolution moved**: a dependency re-pointed at a different repo
    or mirror *while the version claims nothing moved*. Deliberate
    fork/mirror switches with a new pin — a fifth of real
    ghostty/libvaxis history — stay quiet, as does any move whose
    unchanged hash proves the content identical.
  - **Verified links**: tag pins get compare links + `-changelogs`
    release notes verified against the dependency's own repo (Zig-only
    diffs now run the tag layer; there is no registry to consult, so the
    repo's tags ARE the metadata source); rev pins get rev…rev compare
    links fully offline. `.path` dependencies are local source and are
    skipped. Old (`1220…` multihash) and new hash formats, `.@"quoted"`
    names, comments and tuple fields all parse; 123 real
    ghostty/zls/libvaxis/bun manifest changes replay with zero noise.
- audit walk, pre-commit hook files regex, playground (drop a
  `build.zig.zon` — parsing and both pin checks run in-browser) and MCP
  all pick the format up automatically.

## v0.5.9 — 2026-08-07

- **Gradle version catalogs and dependency verification — formats #33 and
  #34.**
  - **`libs.versions.toml`** (any `*.versions.toml` beside it): the file
    Renovate and Dependabot actually bump in Gradle and Android projects.
    Exact pins from `[versions]` / `[libraries]` / `[plugins]` (string
    shorthand, inline tables, `version.ref`, rich versions by Gradle's
    strictly > require > prefer precedence); dynamic versions (`1.+`,
    ranges, `latest.release`) skipped. Plugins are resolved as their
    plugin-marker coordinate (`id:id.gradle.plugin`) — what Gradle itself
    resolves — against the Gradle Plugin Portal, with Maven Central and
    Google Maven fallbacks; ages, unlisted re-verification and
    `pkg maven:…` latest lookups all work for markers.
  - **`verification-metadata.xml`**: the wall-of-XML diff nobody reviews
    becomes ordinary package changes with the full registry treatment,
    and every artifact's checksums become integrity pins scoped per file —
    a component's SAME artifact changing its accepted hashes at an
    unchanged version surfaces as ‼ REPINNED (the exact tampering the
    file exists to catch), while Gradle ADDING an artifact entry because
    a new configuration resolved another variant stays quiet (that was
    the noisy case on real Signal-Android history), as do `also-trust`
    additions and SNAPSHOT re-resolutions.
  - Maven unlisted-version claims got a repository-honesty gate: Gradle
    files don't record which repositories a build declares, so a bump
    whose OUTGOING version already wasn't on the public registry (a
    custom-repo dependency, like Signal's libsignal) no longer flags —
    absence proves nothing there. A bump FROM a registry-listed version
    onto a missing one, and `-SNAPSHOT` versions never claiming
    unlisted, keep the signal honest. Validated on 80+ real
    nowinandroid + Signal-Android history replays: zero noise, true
    positives kept.
- **`pylock.toml` (PEP 751) — format #35.** Python's standardized
  lockfile — written by `uv export`, `pip lock`, pipenv and pdm — gets
  the full PyPI treatment (advisories incl. malware records, release
  ages, deprecations/yanks, registry-verified unlisted versions,
  provenance-drop and install-script checks, typosquat suspects), plus:
  - **integrity + resolution pins**: every artifact hash (inline uv/
    pipenv `hashes = { sha256 = … }` tables and pip's
    `[packages.wheels.hashes]` sub-tables both parse) and the index or
    artifact host become pins — a same-version hash change flags
    ‼ REPINNED, and a package moving from a private index onto PyPI
    flags the dependency-confusion lane ⇄.
  - `vcs` / `directory` / `archive` sources and local-path-only wheels
    are exempt from registry judgement; wheel-filename `name` keys in
    sub-tables never masquerade as package names; the optional PEP 751
    `dependencies` arrays become `via …` chains when a locker records
    them. Named lockfiles (`pylock.dev.toml`) are recognized everywhere,
    including `audit`'s tree walk and the pre-commit hook.
- **Air-gapped vulnerability checks: `-osv-db DIR`.** Point lockvet at a
  directory of local OSV databases — the per-ecosystem `all.zip` files
  [OSV.dev publishes](https://google.github.io/osv.dev/data/#data-dumps) —
  and the vulnerability check runs entirely from disk, so `-offline`
  (air-gapped CI, locked-down build environments) still gets real
  advisories, including `MAL-…` malware records. Missing or stale
  ecosystems are downloaded automatically when network is available
  (conditional GET: an unchanged database costs one 304); hand-copied
  `all.zip` files are indexed locally on first use; withdrawn records are
  excluded and ranges are evaluated client-side, matching the API's
  answers (byte-identical output on real repos). A missing database fails
  loud with instructions, never a silent "no vulnerabilities".
  `LOCKVET_OSV_DB` sets a default directory. Works in every mode —
  diff, `pr`/`mr`, `compare`, `audit`, `pkg`, `queue`, MCP.
- Friendlier error when the default mode runs outside a git repository:
  points at `lockvet audit .`, `lockvet pr <url>`, and `lockvet diff`.

## v0.5.8 — 2026-08-07

- **Bazel modules (bzlmod) — format #32.** Two files, one ecosystem:
  - **`MODULE.bazel.lock`**: the modern registry-hash shape (Bazel 7.2+;
    the selected version of each module is the one whose `source.json`
    hash the lockfile records) and the Bazel 7.0/7.1 `moduleDepGraph`
    shape (full dependency edges → via-chains, root deps, and the
    archive's own SRI integrity). Same-version `source.json`-hash changes
    flag the integrity lane ‼; a module whose resolution moves from a
    private registry onto the public BCR flags the dependency-confusion
    lane ⇄. Modules under `git_override`/`local_path_override`/private
    registries are exempt from registry judgement.
  - **`MODULE.bazel`** itself: `bazel_dep` pins exact versions and update
    bots bump them in place (go.mod-style) — and most repos commit the
    manifest, not the lockfile, so Renovate "Update bazel modules" PRs
    now get full analysis. `single_version_override` wins over the
    `bazel_dep` version; commented-out deps never parse.
- **The Bazel Central Registry is registry #18** (`internal/bzlreg`) —
  deps.dev has no Bazel system, so like Packagist/Hex/pub.dev/CRAN/
  Hackage/conda this IS the metadata layer: **yanked versions** land in
  the deprecation lane with the registry's own reason (protobuf 3.19.0:
  "CVE-2022-3171"; 33.3: "Incorrect release artifacts"), the
  **registry-verified unlisted check** (yanked versions stay listed and
  the registry is a git repo — versions are never silently dropped — so
  absence is real evidence; re-proven live, with a per-version
  `MODULE.bazel` probe to clear CDN lag), and **source repositories**
  from `metadata.json` → verified compare links and `-changelogs`
  release notes. A lockfile built with `--allow_yanked_versions` admits
  its yanked selections in `selectedYankedVersions` — read even with
  `-offline`. BCR records no publish timestamps, so ages/⏱ are honestly
  absent; no CORS on bcr.bazel.build, so the browser playground skips
  the registry layer (parsing, diffing and offline signals still work).
- **`lockvet pkg bazel:<module>`** — pre-install vetting with
  latest-version lookup from BCR (`lockvet pkg bazel:protobuf@3.19.0`
  answers with the yank reason before you build).
- **`.bcr.N` re-cut versions order correctly** (`1.83.0 <
  1.83.0.bcr.1`): previously the registry's re-cut suffix parsed as a
  pre-release, so a `boost.foreach 1.83.0.bcr.2 → 1.90.0.bcr.1` bump
  could classify as a downgrade.
- Validated against 180+ replayed `MODULE.bazel(.lock)` commits across
  bazelbuild/bazel, rules_go, rules_python, protobuf and grpc-java:
  0 parse failures, 0 false flags.

## v0.5.7 — 2026-08-07

- **Nix `flake.lock` inputs get the full treatment** — everything below
  is computed from the lockfile itself, fully offline (works with
  `-offline`, in air-gapped CI, and in the browser playground):
  - **ages & the ⏱ cooldown flag**: each input's `lastModified` is the
    pinned commit's own timestamp, so `update-flake-lock` PRs now show
    "published 3 days ago" and `-fail-on fresh` works — with zero
    registry requests;
  - **`rev...rev` compare links**: every bump links to the forge's
    compare page (`github:`/`gitlab:`/https `git:` inputs), so "what
    did nixpkgs actually change this week" is one click from the
    report. Commit revisions address themselves — no tag verification,
    no fetches;
  - **narHash tampering** ‼: a same-revision `narHash` change means the
    tree this pin fetches was replaced — a git revision's content never
    changes. Flags the integrity lane (`-fail-on integrity`, SARIF
    `integrity-changed`, queue top tier);
  - **re-pointed inputs** ⇄: an input that silently changes repository
    (`NixOS/nixpkgs` → someone's fork) flags the resolution-moved lane
    (`-fail-on registry`). A re-point whose narHash proves the content
    identical — like the `pre-commit-hooks.nix` → `git-hooks.nix`
    rename — stays quiet, and no cross-repo compare link is written.
  Replayed 60+ real flake.lock commits (Hyprland, helix, lanzaboote,
  devshell): zero false flags.

## v0.5.6 — 2026-08-07

- **`-changelogs` now reads changelog files, not just GitHub Releases.**
  Plenty of projects never publish releases — Phoenix stopped at v1.5.3,
  `regex`/`once_cell`/`tempfile` keep a `CHANGELOG.md` instead, and
  GitLab-, Gitea/Codeberg- and Bitbucket-hosted repos don't have GitHub
  Releases at all. When the release list doesn't cover a bump, lockvet
  now fetches the repository's changelog file (`CHANGELOG.md`,
  `CHANGES.md`, `NEWS.md`, `HISTORY.md`) at the *verified* tag via the
  forge's raw endpoint and slices out the exact version sections the
  bump pulls in — same intermediate-release coverage, same excerpting
  and sanitizing, one extra request per repository, no API rate limits.
  Keep-a-Changelog, ATX (`## 1.2.3 (2024-01-01)`) and setext-underlined
  headings are recognized, `Version`/`Release`/package-name prefixes
  tolerated, link-reference lines stripped. Monorepo-style tags
  (`pkg@1.2.3`, `pkg-v1.2.3`, `dir/v1.2.3`) are excluded on purpose: a
  root changelog describes one package, and guessing would attach the
  wrong notes. GitHub Releases still win when they exist; the file is
  only consulted for what they don't cover.

## v0.5.5 — 2026-08-07

- **Every open advisory now names its fix version.** Introduced and
  unresolved (affects-both-versions) findings read the advisory's own
  OSV ranges and report the smallest release that clears it for your
  exact pin — `· fixed in 4.17.21` on the terminal line, **fixed in
  4.17.21** in Markdown, `Fixed in 4.17.21.` appended to SARIF alert
  messages, `fixed_in` on every vuln object in JSON. Aggregated
  "N advisories affect both versions" lines add `— all fixed in ≥ X`
  when every advisory in the group has a released fix (the ≥ version
  clears them all). Works across every ecosystem lockvet queries OSV
  for, including RUSTSEC unmaintained-crate notices with successor
  ranges and GitHub Actions (evaluated against the release each pin
  resolves to; SHA and floating-major pins make no claim). No fix
  released, ranges silent, or a multi-version pin only partially
  fixable → no claim, honestly. Zero extra network requests — the
  ranges were already fetched.

## v0.5.4 — 2026-08-07

- **SwiftPM pins verified against upstream tags.** `Package.resolved`
  records a version, the commit its tag resolved to, and the repository
  it came from — so lockvet now fetches each repository's real tag list
  (one anonymous git smart-HTTP request, no API, no rate limits) and
  verifies every incoming pin:
  - **‼ tag mismatch** — the pinned commit is not what the upstream tag
    points at today. Released tags are supposed to be immutable: either
    the tag was re-pointed since resolution (how the tj-actions attack
    shipped), or the lockfile was edited to fetch a different commit
    while displaying an innocent version. Gates with `-fail-on
    integrity`; SARIF rule `tag-mismatch` (error); JSON `tag_mismatch` /
    `tag_mismatches`.
  - **▲ not a release** — the pinned version matches no tag upstream.
    Version pins only ever resolve from tags, so the tag was deleted or
    renamed after resolution. Gates with `-fail-on unlisted`.
  - Annotated tags are peeled to their commit, `v`-prefixed tags match
    unprefixed versions, and unreachable (private/moved) repositories
    produce no claims. Verified-changelog compare links and
    `-changelogs` now work for Swift diffs too, and `lockvet audit`
    verifies every Swift pin you currently hold.
- **`lockvet pkg swift:host/owner/repo`** vets a Swift package before you
  add it (`swift:owner/repo` implies github.com; latest = the highest
  stable semver tag).
- **pre-commit hook: gate by default.** The hook definition now fails
  the commit on the alarming tier (vuln, unlisted, scripts, provenance,
  typosquat, integrity, registry) instead of being purely informational,
  covers all 31 formats plus workflow `uses:` pins, and still prints the
  full explanation every time. Override `args` to tune.

## v0.5.3 — 2026-08-07

- **conda registry signals — pixi and conda-lock join the metadata
  lineup.** Conda has no OSV ecosystem and no deps.dev coverage, so
  `pixi.lock` and `conda-lock.yml` diffs used to show version changes
  with no registry data at all. lockvet now asks anaconda.org — keyed on
  the channel each artifact URL in the lockfile actually resolves from,
  so conda-forge, bioconda and every other anaconda.org channel work
  (pixi's prefix.dev mirror URLs for conda-forge/bioconda included):
  - **Release ages and the ⏱ cooldown flag** from the per-release upload
    times on api.anaconda.org.
  - **Broken releases** land in the deprecation lane: conda-forge pulls a
    bad or malicious build by moving its artifacts to the `broken` label,
    and a bump onto one is flagged (`● deprecated upstream: marked broken
    on conda-forge (artifacts moved to the broken label)`) —
    all-builds-broken and some-builds-broken worded apart.
  - **License changes** old → new from the artifacts' recipe metadata.
  - **Registry-verified unlisted:** an incoming version anaconda.org has
    never seen, while the package itself provably exists (another release
    answers, or an uncached HEAD on the package document does) gets the
    ▲ flag — channels pull malicious uploads outright, so a lockfile
    still pinning one is a red flag. Packages the API doesn't know at
    all are never flagged; `repo.anaconda.com` defaults-channel and
    private-mirror artifacts carry no channel lockvet can ask about and
    are honestly skipped.
  - **`lockvet pkg conda:[channel/]name[@version]`** — pre-install vetting
    with a latest-version resolver (`lockvet pkg conda:smmap` resolves
    anaconda.org's `latest_version` and immediately flags it: that
    release is marked broken on conda-forge).
- **Fixed:** `pypi: git+…` / path / direct-URL entries inside `pixi.lock`
  and `conda-lock.yml` are now marked non-registry — a git-sourced
  package with a local version string (pixi's own lockfile pins `mike`
  from a fork) no longer trips the PyPI unlisted check.

## v0.5.2 — 2026-08-07

- **Hackage registry signals — Haskell joins the metadata lineup.**
  deps.dev has no Hackage system, so `stack.yaml.lock` and
  `cabal.project.freeze` diffs used to get OSV advisories (`HSEC-…`) but
  no release metadata at all. lockvet now asks hackage.haskell.org — the
  canonical registry, no mirror in between — directly:
  - **Release ages and the ⏱ cooldown flag** from Hackage's per-version
    upload-time endpoint.
  - **Deprecated packages** land in the deprecation lane with the
    maintainer's suggested replacements from Hackage's registry-wide
    deprecation list (`● deprecated upstream: deprecated on Hackage; use
    crypton, cryptohash-md5 or cryptohash-sha1 instead` — the
    `cryptonite` story).
  - **Deprecated versions** too: Hackage's preferred-versions mechanism
    (its yank equivalent — the tarball stays but solvers avoid it) flags
    a bump onto an individually deprecated release.
  - **Registry-verified unlisted check**: Hackage never deletes versions
    — deprecated ones stay in the package's version map — so a version
    absent from the map while the package is known is real evidence.
    Absence is re-proven with an uncached fetch before any claim, so a
    same-hour release can never be flagged off a stale cache.
  - **Verified changelog links and `-changelogs` release notes** via the
    release's own `.cabal` file (`source-repository head`, homepage
    fallback).
  - **`lockvet pkg hackage:<name>`** now resolves the latest
    (non-deprecated) version by itself — `lockvet pkg hackage:cryptonite`
    is a one-line demo: deprecation, replacements, and a real `HSEC`
    advisory on the current release.
- License-change detection is honestly skipped for Hackage: per-version
  license metadata straddles the legacy/SPDX migration and comparing
  `.cabal` files both ways would double the request budget for a noisy
  signal.
- hackage.haskell.org sends no CORS headers, so the browser playground
  skips this layer (like RubyGems, Maven and CRAN); the native CLI is
  unaffected.

## v0.5.1 — 2026-08-07

- **CRAN registry signals — R joins the metadata lineup.** deps.dev has
  no CRAN system, so `renv.lock` diffs used to get OSV advisories but no
  release metadata at all. lockvet now asks CRAN itself (via
  [METACRAN's crandb](https://crandb.r-pkg.org), the JSON API behind
  r-pkg.org):
  - **Release ages and the ⏱ cooldown flag** from CRAN's per-version
    publication timeline — every version ever released is dated.
  - **Archived packages** land in the deprecation lane
    (`● deprecated upstream: archived on CRAN (no longer installable
    from the index)`) — real catches: `rgdal`, `ffbase`, `DataCombine`.
  - **License changes** between the two pinned versions, from each
    release's own DESCRIPTION.
  - **Mirror-lag-safe unlisted check**: a version missing from crandb is
    double-checked against cran.r-project.org itself (current release
    *and* the Archive) before lockvet claims anything — a release cut
    minutes ago never flags.
  - **Verified changelog links and `-changelogs` release notes** via the
    DESCRIPTION URL field (`dplyr 1.1.3 → 1.2.1` links the real
    tidyverse tag-to-tag diff and shows the intermediate release notes).
  - **`lockvet pkg cran:<name>`** now resolves the latest version by
    itself (`lockvet pkg cran:dplyr`), like the other 14 ecosystems.
- The `renv.lock` parser now marks GitHub/GitLab/Bitbucket remotes and
  local/URL/git installs as non-registry installs, so dev versions like
  `1.0.0.9000` are exempt from registry judgement (their OSV advisory
  check still runs).
- crandb and cran.r-project.org send no CORS headers, so the browser
  playground skips this layer (like RubyGems and Maven); the native CLI
  is unaffected.

## v0.5.0 — 2026-08-07

- **Format #31: GitHub Actions workflows.** Every `uses:` line is a
  dependency pin, and Dependabot/Renovate bump them like any other —
  lockvet now reads `.github/workflows/*.yml`, composite
  `action.yml`/`action.yaml` files, and `.gitea`/`.forgejo` workflow dirs
  in every mode: local diffs, `pr`/`mr`/`compare`, `queue` (actions-bump
  PRs no longer show "no lockfile changes"), `audit`, `diff`, SARIF,
  `-comment`, the GitHub Action, MCP tools, and the playground.
- **SHA pins resolve to releases** via one anonymous git smart-HTTP GET
  per action repo (no API, no rate limits): Renovate digest bumps read
  `df4cb1c (=v6.0.3) → d23441a (=v6.1.0)  minor`, floating majors like
  `v4` resolve to the release they point at today, and jumps are
  classified from the resolved versions. Verified compare links and
  `-changelogs` release notes work for actions too.
- **Advisories evaluated client-side.** OSV.dev's "GitHub Actions"
  ecosystem cannot be queried by version (the API returns nothing);
  lockvet fetches the affected ranges and evaluates them itself against
  the resolved release — so a SHA pin affected by a GHSA is caught, a
  floating tag isn't false-flagged for an advisory fixed inside its
  major, and open-ended ranges the OSV export truncated (GHSA records
  per-major lines) are capped at the next major when a sibling range
  carries the fix.
- **▲ not a release** — the unlisted flag now covers workflow pins: an
  incoming commit SHA (or version-shaped ref) that matches no tag in the
  action's repository. That is the exact shape of the March 2025
  tj-actions/changed-files attack, whose malicious commit `0e58ed86`
  lockvet flags today (case study). Branch refs and branch-head SHAs stay
  quiet; repos with no reachable tag data produce no claims.
- **`lockvet pkg actions:owner/repo`** now resolves the latest release
  from the action repository's tags (previously an explicit `@version`
  was required), and version specs tolerate the `v` prefix both ways.
- `lockvet diff` and playground file drops accept any `*.yml`/`*.yaml`
  as a workflow when the name isn't a known lockfile (strict: at least
  one `uses:` pin).
- Honest classification offline: SHA→SHA bumps say "changed ?" instead
  of a meaningless hex-string DOWNGRADE verdict when tags can't be
  checked (`-offline`/`-no-meta`).

## v0.4.8 — 2026-08-07

- **New mode: `lockvet pkg <eco>:<name>[@version]` — vet a package BEFORE
  you install it.** The riskiest moment in dependency management is
  installing a package you've never seen; `lockvet pkg npm:left-pad`
  answers *should I?* first: advisories affecting the version (including
  `MAL-*` malicious-package records — `lockvet pkg npm:chakl` surfaces the
  malware squatting the chalk typo), release age with the ⏱ fresh flag,
  deprecation/retraction/yank with the upstream reason, versions missing
  from the registry index, and ≈ typosquat suspicion. Multiple specs per
  run; `-md`/`-json`/`-fail-on`/`-only` compose as everywhere else.
- **Latest-version lookup from the package's own registry** when no
  version is given (shown as `@X.Y.Z (latest)`): npm, PyPI, crates.io,
  RubyGems, Packagist, Go module proxy (GOPROXY honoured), Hex, pub.dev,
  JSR, NuGet, Maven Central/Google Maven, CocoaPods, and the Terraform
  registry. Ecosystems without a resolver (`conan:`, `cran:`, `julia:`,
  `hackage:`, `actions:`) take an explicit `@version`.
- **New MCP tool `vet_package`** — coding agents can vet a dependency at
  the moment they're about to add it (the tool description tells them to).
- Spec ergonomics: scoped npm names (`npm:@types/node@24`), `jsr:@std/http`,
  `maven:group:artifact`, `go:` versions with or without the `v`,
  case-insensitive ecosystem aliases (`pip:`, `rust:`, `golang:`,
  `dotnet:`, `php:`, …).

## v0.4.7 — 2026-08-07

- **Integrity & resolution tampering detection now covers 11 more formats**
  (was 9). New pin sources for the v0.4.6 `‼ REPINNED` / `⇄ resolution
  moved` signals:
  - **Artifact hashes**: mix.lock (both Hex checksums), Gleam manifest.toml
    (`outer_checksum`), pubspec.lock (`sha256` + hosted URL — the Dart
    private→pub.dev dependency-confusion shape now flags), bun.lock,
    deno.lock (npm + jsr integrity), Podfile.lock (trunk podspec
    checksums; local/external pods exempt), `.terraform.lock.hcl`
    (provider `h1:`/`zh:` hashes — a provider whose version stays but
    whose hashes fully change is a registry-side replacement), conda/pixi
    locks (PyPI wheel hashes + channel hosts).
  - **Release-tag pins**: Package.resolved (Swift) and composer.lock
    record the commit a released tag resolved to; Julia's Manifest.toml
    records the registry's `git-tree-sha1`. A version that keeps its
    number but changes its commit/tree = **the upstream tag was moved** —
    flagged as REPINNED. Composer branch pins (`dev-*`) and Julia
    `repo-url` dev pins legitimately move and are never recorded.
  - Deliberately **omitted after real-history sweeps said no**: NuGet
    `contentHash` (the 2018 repository-resigning changed every pre-2018
    package's hash — seen live on `runtime.native.*` 4.3.0) and conda
    artifact hashes (same-version build-number rebuilds are routine).
    A package that switches managers between conda and PyPI in one diff
    (pixi manager change) is also recognized and stays quiet.
  - Validated against 610 historical lockfile commits across 20 repos
    (AppFlowy, localsend, Signal-iOS, eigen, pixi, monica, koel, realtime,
    plausible, lustre, fresh, deno std, MonoMod, PluralKit, SolrNet,
    mirrorsharp, atmos, TCA, MIT computational-thinking, EmailThing):
    zero false positives after the exemptions above.

## v0.4.6 — 2026-08-07

- **Lockfiles pin bytes and sources, not just versions — lockvet now reads
  them.** Two new fully-offline signals from the integrity hashes and
  resolution URLs the lockfiles already carry
  ([docs](https://github.com/matteo-sung/lockvet#integrity--resolution-changes)):
  - **`‼` integrity changed, version didn't**: a pin keeps its version but
    swaps its content hash — registries never change a published artifact,
    so the expected tarball was replaced (registry-side tampering, a
    hijacked mirror, or a hand-edited lockfile). Rendered as a `REPINNED`
    row even though no version moved. Hashes compare per algorithm
    (sha1→sha512 lockfile upgrades and yarn-berry cache-key bumps never
    flag) and Python hash sets may grow — only fully disjoint sets flag.
  - **`⇄` resolution moved to the public registry**: a package that used
    to resolve from a private host now resolves from npmjs / PyPI /
    crates.io / rubygems.org — the shape of a dependency-confusion
    attack. Only the private→public direction flags; provably identical
    bytes stay quiet; ≥5 packages moving between the same two hosts is
    recognized as a registry migration and stays quiet.
  - Formats: npm lockfiles v1–v3, pnpm, yarn classic + berry, Cargo,
    poetry, uv, Pipfile.lock, `requirements.txt --hash`, Gemfile.lock
    (hosts). Surfaces everywhere: terminal/markdown rows, JSON
    (`integrity_changed`, `old_host`/`new_host`, `registry_moved`), SARIF
    (`integrity-changed` error, `registry-moved` warning), `-fail-on
    integrity,registry`, `.lockvetignore` kinds, queue top tier, MCP.
  - Validated against ~400 historical lockfile commits across fd, npm/cli,
    mastodon, grafana, poetry, pnpm and uv: zero false positives.
- Release assets now include the Sigstore bundle (`lockvet_<tag>.intoto.jsonl`)
  for offline verification: `gh attestation verify <file> --owner
  matteo-sung --bundle lockvet_<tag>.intoto.jsonl`.

## v0.4.5 — 2026-08-07

- **lockvet's own releases are now attested.** Every release artifact —
  each binary archive, `checksums.txt`, and the multi-arch Docker image —
  carries [Sigstore build provenance](https://github.com/matteo-sung/lockvet#verifying-a-release)
  generated at build time by the release workflows. lockvet flags
  dependencies that drop provenance; it now meets the same bar it checks
  others against. Verify any download with
  `gh attestation verify <file> --owner matteo-sung`.
- **OpenSSF Scorecard** now runs weekly and on every push to `main`,
  with results published to the OpenSSF API and code scanning.
- No code changes; binaries are functionally identical to v0.4.4.

## v0.4.4 — 2026-08-06

- **`≈` typosquat suspects now cover RubyGems and Packagist.** Two more
  embedded popularity lists: RubyGems' 5 000 most-downloaded gems (via
  the [ecosyste.ms](https://ecosyste.ms) packages API, data CC BY-SA 4.0)
  and Packagist's 4 000 most popular packages (their official explore
  API). Separator swaps flag on both — `-` and `_` are genuinely distinct
  names there (`rack_cache` next to `rack-cache` is exactly how the
  most-downloaded gem of the Feb 2020 RubyGems campaign was squatted),
  and the campaign's lead example `rspec-mokcs` → `rspec-mocks` replays.
  Composer names match across the full `vendor/package` string, so
  vendor-level squats (`symfonny/console`) flag too. Validation: 140
  historical Gemfile.lock/composer.lock diffs (mastodon, gitlab-foss,
  monica) plus mastodon's live Renovate queue — zero false flags.
- **Fix: the typosquat check now actually runs with `-no-meta`/`-offline`**,
  as documented — it needs no network. Previously it was silently skipped
  alongside the registry metadata layers; with metadata off, release ages
  are unknown and the young-release gate honestly passes everything
  through to the name check. Verified noise-free offline across 230
  historical diffs (npm/cli, fd, uv, mastodon, gitlab-foss, monica).

## v0.4.3 — 2026-08-06

- **`≈` typosquat suspects — the oldest registry attack, caught offline.**
  A new dependency whose name is at most one edit away (insertion,
  deletion, substitution, or adjacent transposition — separator swaps
  included) from a popular package on the same registry, and whose release
  is young (≤ 30 days) or of unknown age, is flagged as the shape of a
  typosquat. Historical replays: the 2019 PyPI `python3-dateutil` attack
  (which never received an OSV advisory — this flag is the only catch),
  crates.io's 2022 `rustdecimal`, npm's `lodahs`. Entirely local: the
  popularity lists (npm high-impact by Titus Wormer, Top PyPI Packages by
  Hugo van Kemenade, crates.io most-downloaded) are embedded in the
  binary — zero network requests, works in the browser playground.
  Noise design: only packages *entering* the tree are checked; name pairs
  the registry treats as one package never flag (PyPI `-`/`_`/`.`
  equivalence, crates.io `-`/`_` collision ban) while npm separator
  swaps — genuinely distinct packages — do; popular packages themselves
  and very short names are skipped; the age gate mutes long-coexisting
  neighbours. Zero flags across live Dependabot/Renovate queues of
  mastodon, grafana, and renovatebot. Surfaces: terminal `≈` + summary,
  markdown row, JSON `typosquat_of`, SARIF `typosquat-suspect` warning,
  `-fail-on typosquat`, `.lockvetignore` kind `typosquat:`, `queue` top
  tier, MCP tool descriptions.

## v0.4.2 — 2026-08-06

- **On-disk response cache — repeat runs are fast and quota-friendly.**
  Registry and advisory answers (OSV.dev, deps.dev, the 14 package
  registries lockvet reads, git tag listings, GitHub release notes) are
  cached for one hour under `os.UserCacheDir()/lockvet` (override:
  `LOCKVET_CACHE_DIR`), so running `lockvet`, then `lockvet -md` for the
  PR comment, no longer asks every registry twice — a warm
  `lockvet compare` run drops from ~3s to ~1s, and tight anonymous rate
  limits (hex.pm 100 req/min, npm, PyPI) stop being a concern for
  repeated local runs. Honesty guarantees: forge data (PR state, compared
  file contents) is **never** cached, so you always vet the live diff;
  only `200` answers are stored — negative registry answers, the evidence
  behind the ▲ unlisted flag, are re-proven on every run so a
  just-published version clears the flag immediately; authenticated and
  anonymous responses never share entries, and credentials are never
  written to disk. New flags: `-no-cache` (bypass), `-cache-ttl D`
  (default `1h`; `0` disables). Cache files are user-private (0600) and
  swept automatically.

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
