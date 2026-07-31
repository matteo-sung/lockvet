# Changelog

All notable changes to lockvet. Versions follow [semver](https://semver.org)
with a 0.x major: minor bumps may consolidate, patch bumps add features and
fixes.

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
