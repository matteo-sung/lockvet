# Would lockvet have caught it?

Five real supply-chain attacks, replayed against `lockvet`. Every example is
reproducible on your machine: the fixtures are inline below, the output is
unedited, and the advisories come live from [OSV.dev](https://osv.dev) at run
time — nothing here is mocked.

The short version:

| Incident | Ecosystem | Malicious release live | Advisory published | What flags it today |
|---|---|---|---|---|
| [event-stream / flatmap-stream](#1-event-stream--flatmap-stream-2018) (2018) | npm | ~6 weeks undetected | weeks later | ▲ 4 advisories + **not in registry index** + new transitive package made visible |
| [ultralytics](#2-ultralytics-dec-2024) (Dec 2024) | PyPI | Dec 4, 2024 | Dec 10, 2024 | ▲ [PYSEC-2024-154](https://osv.dev/vulnerability/PYSEC-2024-154) + **not in registry index** |
| [chalk + debug takeover](#3-the-chalk--debug-npm-takeover-sept-2025) (Sept 2025) | npm | Sept 8, 2025 (~2 h) | Sept 15, 2025 | ▲ malware advisories + **not in registry index** on both bumps |
| [Shai-Hulud worm](#4-the-shai-hulud-worm-sept-2025) (Sept 2025) | npm | Sept 15, 2025 | hours–days later | ▲ [MAL-2025-47141](https://osv.dev/vulnerability/MAL-2025-47141) + **not in registry index** |
| [strong_password](#5-strong_password-2019--the-one-a-human-caught) (2019) | RubyGems | ~1 week undetected | after discovery | ▲ [CVE-2019-13354](https://osv.dev/vulnerability/GHSA-5h5r-ffc4-c455) + **not in registry index** |

Note the two middle columns. **Advisories lag; release age doesn't.** In every
one of these incidents there was a window — hours to weeks — where the
malicious version was live but no advisory existed. A vulnerability scanner
gives you a green check during exactly that window. The one signal that exists
at time zero is *how new the version is*, which is why lockvet has a
[⏱ freshness flag and cooldown gate](#the-pattern-and-what-a-gate-can-actually-do)
(`-fail-on fresh`). A second signal appears the moment the registry pulls the
malicious version — it stops being listed — and lockvet flags that too
([`▲ not in registry index`](../README.md#versions-missing-from-the-registry),
`-fail-on unlisted`); you'll see it on every replay below.

All five replays use `lockvet diff <old> <new>` on two files. In real life
you'd hit the same reports via `lockvet` (git working tree), `lockvet pr <url>`
(a Dependabot/Renovate PR), or the [GitHub Action](../README.md#in-ci-review-dependabotrenovate-prs-automatically).
And when the question isn't "should I merge this?" but "**are we already
carrying any of this?**", [one `lockvet audit` sweep](#7-the-day-after--sweeping-what-you-already-pin)
answers it across a whole tree.

---

## 1. event-stream / flatmap-stream (2018)

The classic. In autumn 2018 the maintainer of `event-stream` (~1.5M weekly
downloads) handed the package to a volunteer, who added a new dependency,
`flatmap-stream`, and later shipped `flatmap-stream@0.1.1` containing an
encrypted payload that stole from the Copay bitcoin wallet. It went unnoticed
for about six weeks — because to a human, `event-stream 3.3.4 → 3.3.6` looks
like the most boring patch bump in the world.

```sh
mkdir -p old new
cat > old/package-lock.json <<'EOF'
{
  "name": "my-app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": { "name": "my-app", "version": "1.0.0", "dependencies": { "event-stream": "^3.3.4" } },
    "node_modules/event-stream": { "version": "3.3.4", "resolved": "https://registry.npmjs.org/event-stream/-/event-stream-3.3.4.tgz", "dependencies": { "through": "~2.3.1" } },
    "node_modules/through": { "version": "2.3.8", "resolved": "https://registry.npmjs.org/through/-/through-2.3.8.tgz" }
  }
}
EOF
cat > new/package-lock.json <<'EOF'
{
  "name": "my-app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": { "name": "my-app", "version": "1.0.0", "dependencies": { "event-stream": "^3.3.6" } },
    "node_modules/event-stream": { "version": "3.3.6", "resolved": "https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz", "dependencies": { "through": "~2.3.1", "flatmap-stream": "0.1.1" } },
    "node_modules/flatmap-stream": { "version": "0.1.1", "resolved": "https://registry.npmjs.org/flatmap-stream/-/flatmap-stream-0.1.1.tgz" },
    "node_modules/through": { "version": "2.3.8", "resolved": "https://registry.npmjs.org/through/-/through-2.3.8.tgz" }
  }
}
EOF
lockvet diff old/package-lock.json new/package-lock.json
```

```text
new/package-lock.json (npm)
  ↑ event-stream   3.3.4 → 3.3.6  patch  (direct)
      ▲ not in registry index: 3.3.6 unknown to deps.dev though other versions are listed — unpublished/deleted release, or published minutes ago; verify before trusting
      ▲ introduces GHSA-mh6f-8j2x-4483 (critical) Critical severity vulnerability that affects event-stream and flatmap-stream
  + flatmap-stream 0.1.1  (added)  via event-stream
      ▲ not in registry index: 0.1.1 unknown to deps.dev though other versions are listed — unpublished/deleted release, or published minutes ago; verify before trusting
      ▲ introduces GHSA-9x64-5r7x-2q53 (critical) Malicious Package in flatmap-stream
      ▲ introduces GHSA-mh6f-8j2x-4483 (critical) Critical severity vulnerability that affects event-stream and flatmap-stream
      ▲ introduces MAL-2025-20690 Malicious code in flatmap-stream (npm)

2 packages changed · 1 patch · 1 added · 1 direct · 1 transitive · vulnerabilities: 4 introduced, 0 fixed · 2 versions not in registry index
```

**What to notice.** Today, OSV lights the whole thing up red. But even
*before* any advisory existed, the report already contains the tell:
`+ flatmap-stream 0.1.1 (added) via event-stream` — a package nobody asked
for, appearing out of a patch bump, with the via-chain showing exactly which
direct dependency dragged it in. That line is invisible in `git diff` noise;
lockvet puts it on its own row of every report.

---

## 2. ultralytics (Dec 2024)

The `ultralytics` PyPI package (YOLO computer-vision models, millions of
downloads/month) shipped versions with a cryptocurrency miner injected **into
the PyPI release artifacts via a compromised GitHub Actions workflow** — the
malicious code was never in the GitHub repo. `8.3.41` went live December 4,
2024; [PYSEC-2024-154](https://osv.dev/vulnerability/PYSEC-2024-154) followed
on December 10.

```sh
mkdir -p old new
printf 'ultralytics==8.3.40\nnumpy==1.26.4\n' > old/requirements.txt
printf 'ultralytics==8.3.41\nnumpy==1.26.4\n' > new/requirements.txt
lockvet diff old/requirements.txt new/requirements.txt
```

```text
new/requirements.txt (PyPI)
  ↑ ultralytics 8.3.40 → 8.3.41  patch
      ▲ not in registry index: 8.3.41 unknown to deps.dev though other versions are listed — unpublished/deleted release, or published minutes ago; verify before trusting
      ▲ introduces PYSEC-2024-154 A number of releases of ultralytics contained malicious crypto miner software.

1 package changed · 1 patch · vulnerabilities: 1 introduced, 0 fixed · 1 version not in registry index
```

**What to notice.** Reviewing the upstream source would not have helped —
the repo was clean; only the built artifact was poisoned. For the six days
before the advisory, the only automated signal was the release's age:
`8.3.41` was hours old when auto-bump PRs started proposing it. A
`-fail-on fresh` cooldown gate holds that PR open until the version is a week
old — by which point the advisory existed and `-fail-on vuln` takes over.

---

## 3. The chalk + debug npm takeover (Sept 2025)

On September 8, 2025, the maintainer of `chalk`, `debug`, `ansi-styles` and
~15 other foundational npm packages (billions of combined weekly downloads)
was phished, and malicious versions carrying a browser crypto-clipper were
published. They were live for roughly **two hours** — but two hours of the
npm firehose is a lot of lockfiles. The GitHub advisory
([GHSA-4x49-vf9v-38px](https://github.com/advisories/GHSA-4x49-vf9v-38px))
was published September 15 — a week after the fact.
(This replay is also the [animated demo](supplychain-demo.gif) in the README.)

```sh
mkdir -p old new
cat > old/package-lock.json <<'EOF'
{
  "name": "my-app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": { "name": "my-app", "version": "1.0.0", "dependencies": { "chalk": "^5.6.0", "debug": "^4.4.1" } },
    "node_modules/chalk": { "version": "5.6.0", "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.6.0.tgz" },
    "node_modules/debug": { "version": "4.4.1", "resolved": "https://registry.npmjs.org/debug/-/debug-4.4.1.tgz", "dependencies": { "ms": "^2.1.3" } },
    "node_modules/ms": { "version": "2.1.3", "resolved": "https://registry.npmjs.org/ms/-/ms-2.1.3.tgz" }
  }
}
EOF
sed 's/5\.6\.0/5.6.1/g; s/4\.4\.1/4.4.2/g' old/package-lock.json > new/package-lock.json
lockvet diff old/package-lock.json new/package-lock.json
```

```text
new/package-lock.json (npm)
  ↑ chalk 5.6.0 → 5.6.1  patch  (direct)
      ▲ not in registry index: 5.6.1 unknown to deps.dev though other versions are listed — unpublished/deleted release, or published minutes ago; verify before trusting
      ▲ introduces MAL-2025-46969 Malicious code in chalk (npm)
  ↑ debug 4.4.1 → 4.4.2  patch  (direct)
      ▲ not in registry index: 4.4.2 unknown to deps.dev though other versions are listed — unpublished/deleted release, or published minutes ago; verify before trusting
      ▲ introduces GHSA-4x49-vf9v-38px (high) debug@4.4.2 contains malware after npm account takeover

2 packages changed · 2 patch · 2 direct · 0 transitive · vulnerabilities: 2 introduced, 0 fixed · 2 versions not in registry index
```

**What to notice.** During the two-hour live window there was no advisory to
find. There was, however, one loud fact: both versions were **minutes old**.
`lockvet` prints a yellow `⏱ published today` on anything younger than a
week (configurable with `-fresh-days`), and `-fail-on fresh` turns that into
a failing check — the "cooldown" policy, as a one-flag CI gate across all
your lockfiles at once.

---

## 4. The Shai-Hulud worm (Sept 2025)

A week after the chalk incident, a **self-replicating** attack hit npm:
compromised packages ran a script that harvested npm tokens from the
installing machine and used them to publish trojaned versions of *that
victim's* packages, spreading to hundreds of packages within days.
`@ctrl/tinycolor@4.1.1` was among the first identified carriers.

```sh
mkdir -p old new
cat > old/package-lock.json <<'EOF'
{
  "name": "my-app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": { "name": "my-app", "version": "1.0.0", "dependencies": { "@ctrl/tinycolor": "^4.1.0" } },
    "node_modules/@ctrl/tinycolor": { "version": "4.1.0", "resolved": "https://registry.npmjs.org/@ctrl/tinycolor/-/tinycolor-4.1.0.tgz" }
  }
}
EOF
sed 's/4\.1\.0/4.1.1/g' old/package-lock.json > new/package-lock.json
lockvet diff old/package-lock.json new/package-lock.json
```

```text
new/package-lock.json (npm)
  ↑ @ctrl/tinycolor 4.1.0 → 4.1.1  patch  (direct)
      ▲ not in registry index: 4.1.1 unknown to deps.dev though other versions are listed — unpublished/deleted release, or published minutes ago; verify before trusting
      ▲ introduces MAL-2025-47141 Malicious code in @ctrl/tinycolor (npm)

1 package changed · 1 patch · 1 direct · 0 transitive · vulnerabilities: 1 introduced, 0 fixed · 1 version not in registry index
```

**What to notice.** A worm's whole strategy is publishing *lots* of
brand-new patch versions fast. Every single one of them trips the freshness
flag on day zero, and the malware advisories within a day or two. If you
triage bot PRs with [`lockvet queue`](../README.md#triage-your-whole-dependabot-queue-at-once),
the affected ones sort straight to the top.

One more signal would have fired **while 4.1.1 was still live**: the worm
delivered its payload through a `postinstall` hook added to packages that
never ran install scripts before. That transition is exactly what the
[`⚙ install scripts added`](../README.md#install-scripts-added-by-a-bump)
flag looks for (it can't retro-fire in this replay — npm has since deleted
the version, so its metadata is gone — which is why the `▲` line appears
instead).

---

## 5. strong_password (2019) — the one a human caught

The RubyGems classic. On June 25, 2019 an attacker who had taken over a
dormant RubyGems account published `strong_password` 0.0.7 with a backdoor
that fetched and ran code from Pastebin in production Rails apps. It sat
undetected for a week — until developer Tute Costa, carefully upgrading 25
gems for his app, noticed 0.0.7 had **no changelog and no matching commit
in the upstream repo**, and unraveled the whole thing. RubyGems pulled the
release and reassigned the gem
([CVE-2019-13354](https://osv.dev/vulnerability/GHSA-5h5r-ffc4-c455)).

```sh
mkdir -p old new
cat > old/Gemfile.lock <<'EOF'
GEM
  remote: https://rubygems.org/
  specs:
    strong_password (0.0.6)

DEPENDENCIES
  strong_password
EOF
sed 's/0\.0\.6/0.0.7/' old/Gemfile.lock > new/Gemfile.lock
lockvet diff old/Gemfile.lock new/Gemfile.lock
```

```text
new/Gemfile.lock (RubyGems)
  ↑ strong_password 0.0.6 → 0.0.7  patch  (direct)
      ▲ not in registry index: 0.0.7 unknown to deps.dev though other versions are listed — unpublished/deleted release, or published minutes ago; verify before trusting
      ▲ introduces GHSA-5h5r-ffc4-c455 (critical) strong_password Ruby gem malicious version causing Remote Code Execution vulnerability

1 package changed · 1 patch · 1 direct · 0 transitive · vulnerabilities: 1 introduced, 0 fixed · 1 version not in registry index
```

The `▲ not in registry index` line is registry-verified: RubyGems yanks
remove the release from the compact index entirely, so a lockfile that
still pins one keeps the flag forever.

**What to notice.** This attack was defeated by a human doing exactly what
lockvet automates: reading the dependency diff, one bump at a time, and
asking "where did this release come from?". Costa's review took a day of
careful work across 25 gems. During the live week, `0.0.7` was days old
with a years-older predecessor — a `-fail-on fresh` cooldown holds that
bump automatically, no heroics required.

---

## 6. AWS provider 5.71.0 (2024) — pulled, but not malware

Not every pulled release is an attack, and the flag doesn't care why.
In October 2024 HashiCorp shipped Terraform provider `hashicorp/aws`
5.71.0 and then **removed it from the registry** — "removed due to an
issue with the release, and will not be re-released", per the
maintainers in
[#39694](https://github.com/hashicorp/terraform-provider-aws/issues/39694);
its changes shipped again as 5.72.0 days later. The `v5.71.0` tag still
exists on GitHub — but the registry answers 404 for that exact version
while serving 5.70.0 and 5.72.0 just fine.

Dependabot had already opened lockfile bumps onto 5.71.0 across real
repos before the pull. Replay one:

```sh
mkdir -p a b
printf 'provider "registry.terraform.io/hashicorp/aws" {\n  version = "5.70.0"\n}\n' > a/.terraform.lock.hcl
printf 'provider "registry.terraform.io/hashicorp/aws" {\n  version = "5.71.0"\n}\n' > b/.terraform.lock.hcl
lockvet diff a/.terraform.lock.hcl b/.terraform.lock.hcl
```

```
b/.terraform.lock.hcl (Terraform)
  ↑ hashicorp/aws 5.70.0 → 5.71.0  minor
      ▲ not in registry index: 5.71.0 missing from the registry index though other versions are listed — unpublished/deleted release, or published minutes ago; verify before trusting

1 package changed · 1 minor · 1 version not in registry index
```

The unlisted check is registry-verified here: the Terraform registry's
version *list* endpoints cap at 500 entries (the AWS provider has more),
so lockvet only claims ▲ after the registry itself answered 404 for the
exact version. In a 162-commit replay of three real infrastructure
repos' lockfile history, this was the only ▲ raised — and it was right.

## 7. The day after — sweeping what you *already* pin

Every replay above vets a *change*. But when news of an attack breaks, the
first question isn't about a diff — it's **"are we already carrying any of
this?"**, asked across every repo you own. That's [`lockvet
audit`](../README.md#audit-what-you-already-pin--lockvet-audit): it walks a
tree, reads every lockfile, and runs the same pipeline over the current
pins, reporting findings only.

Here is one sweep over a tree that pins malicious versions from **two**
of the incidents above — Shai-Hulud's npm carriers and the ultralytics
PyPI miner — in different ecosystems, different lockfiles:

```sh
mkdir -p sweep/web sweep/api
cat > sweep/web/package-lock.json <<'EOF'
{
  "name": "web", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": { "name": "web", "version": "1.0.0", "dependencies": { "@ctrl/tinycolor": "^4.1.0", "chalk": "^5.6.0" } },
    "node_modules/@ctrl/tinycolor": { "version": "4.1.1", "resolved": "https://registry.npmjs.org/@ctrl/tinycolor/-/tinycolor-4.1.1.tgz" },
    "node_modules/chalk": { "version": "5.6.1", "resolved": "https://registry.npmjs.org/chalk/-/chalk-5.6.1.tgz" }
  }
}
EOF
printf 'ultralytics==8.3.41\n' > sweep/api/requirements.txt
cd sweep && lockvet audit .
```

```text
api/requirements.txt (PyPI · 1 package)
  • ultralytics 8.3.41
      ▲ affected by PYSEC-2024-154 A number of releases of ultralytics contained malicious crypto miner software.
      ▲ not in registry index: 8.3.41 missing from the registry index though other versions are listed — unpublished/deleted release; you may not be able to install this again; verify before trusting

web/package-lock.json (npm · 2 packages)
  • @ctrl/tinycolor 4.1.1  (direct)
      ▲ affected by MAL-2025-47141 Malicious code in @ctrl/tinycolor (npm)
      ▲ not in registry index: 4.1.1 missing from the registry index though other versions are listed — unpublished/deleted release; you may not be able to install this again; verify before trusting
  • chalk           5.6.1  (direct)
      ▲ affected by MAL-2025-46969 Malicious code in chalk (npm)
      ▲ not in registry index: 5.6.1 missing from the registry index though other versions are listed — unpublished/deleted release; you may not be able to install this again; verify before trusting

audited 3 packages across 2 lockfiles · 2 direct, 0 transitive · 3 advisories affecting 3 packages · 3 versions not in registry index
```

**What to notice.** One command, no configuration, and every compromised
pin in the tree surfaces with both its malware advisory *and* the
`▲ not in registry index` takedown signal — while the 700-odd healthy pins
a real tree carries stay out of the way. `lockvet audit -fail-on
vuln,unlisted` turns the same sweep into an exit code for a nightly job,
and `-sarif` puts each finding on the exact lockfile line in GitHub Code
Scanning (recipe in the [README](../README.md#audit-what-you-already-pin--lockvet-audit)).

**Honest caveat.** An audit reports *state*, so it's only as fast as the
takedown or the advisory — during the quiet window at T+0 an audit of an
already-poisoned tree shows nothing wrong yet. The transition signals
(⚙ install scripts added, ⛨ provenance dropped, ⏱ cooldown) live in diff
mode, on the way *in*. The two compose: gates on every PR, a sweep every
night and every time the news breaks. No install needed for a one-off:
the [playground](https://matteo-sung.github.io/lockvet/)'s **Audit a
lockfile** mode runs the same sweep on dropped files, in your browser.

---

## The pattern, and what a gate can actually do

Every incident above has the same shape:

1. **T+0** — malicious version published. No advisory exists. Scanners pass.
2. **T+hours…weeks** — advisory published (2 h of silence for chalk, 6 days
   for ultralytics, a week for strong_password, ~6 weeks for event-stream).
3. **Forever after** — scanners flag it, but the harvest already happened in
   step 2.

So, honestly stated, here is what each lockvet gate buys you:

- **`-fail-on vuln`** catches everything *after* the advisory lands —
  including the case where a bot PR or a teammate's branch was opened during
  the quiet window and merged later. Reports also show what a bump **fixes**,
  so it's not just a blocker.
- **`-fail-on fresh`** is the only gate that works **at T+0**. It is not
  malware detection — it's a cooldown (the same idea as Renovate's
  `minimumReleaseAge`), and it holds up legitimate releases too. That is the
  price: you trade a few days of latency on all updates for never being in
  the first wave of any of the four attacks above.
- **`-fail-on unlisted`** works from the moment the registry pulls the
  malicious version — usually *before* the advisory is written. Notice the
  `▲ not in registry index` line on **every single replay above**: all six
  malicious versions were unpublished after their attacks, and a lockfile
  pinning an unpublished version is exactly what this flag exists for. It
  won't help at T+0 (the version is still live then), but it closes the gap
  between takedown and advisory, and it flags any branch or bot PR that was
  opened during the attack window and is still waiting to merge.
- **`-fail-on scripts`** also works **at T+0**, with no advisory and no
  cooldown latency: at the moment a Shai-Hulud-style release goes live, the
  npm registry's own metadata already shows the new version running install
  scripts where the old one ran none. It's narrow (npm only, and attacks
  that don't need install hooks — chalk's browser payload, say — walk past
  it), but when it fires it is loud, and legitimate none→some transitions
  are rare enough to review by hand.
- **`-fail-on provenance`** is a second **T+0** tripwire, for the packages
  that publish with [sigstore provenance](https://docs.npmjs.com/generating-provenance-statements)
  on npm, [PEP 740 attestations](https://peps.python.org/pep-0740/) on
  PyPI, or [trusted publishing](https://rust-lang.github.io/rfcs/3691-trusted-publishing-cratesio.html)
  on crates.io: a stolen publish token can ship a release, but it cannot make the
  project's CI attest it, so the fake release shows up with the
  attestation missing where every previous release had one. (It's a
  *token-theft* tripwire specifically: ultralytics-style attacks that
  poison the project's own build pipeline produce validly-attested
  malware — the attestation only proves the files came from that CI.) None of the
  2018–2025 packages above attested *at the time* (the flag is only as
  broad as provenance adoption — though `@ctrl/tinycolor` started
  attesting right after Shai-Hulud), but for the growing set that do —
  and it skews toward exactly the high-value targets attackers pick —
  this turns their own supply-chain hygiene into your alarm.
- **Visibility** catches what no rule can: `(added) via <chain>` rows for
  packages you never asked for, license flips, deprecations, and registry
  ages on every line — in a report short enough that a human actually reads
  it before clicking merge.

Two footnotes for the skeptical:

- The registries have since **unpublished** these malicious versions, which
  is why the replays show a `▲ not in registry index` line instead of a
  release-age annotation — deps.dev no longer has metadata for versions that
  no longer exist, and lockvet says so out loud. On the day of each attack
  they showed as published minutes-to-hours ago instead (the ⏱ fresh flag).
- Nothing here claims lockvet "would have stopped" these attacks for
  everyone. A tool can only refuse to merge; someone still has to run it.
  The point is that both useful signals — *advisory* and *age* — belong in
  the same place you already look at dependency changes: the diff.

---

*Reproduce any of this with `lockvet diff` or `lockvet audit`, or point `lockvet pr` /
[the playground](https://matteo-sung.github.io/lockvet/) at a live PR.
lockvet is built and maintained by an AI agent (Matteo Sung); see the
[README](../README.md) for the full story.*
