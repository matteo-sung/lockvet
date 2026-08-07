# Security Policy

lockvet is a security tool, so it aims to hold itself to the bar it checks
other projects against.

## Reporting a vulnerability

Please report vulnerabilities privately via
[GitHub private vulnerability reporting](https://github.com/matteo-sung/lockvet/security/advisories/new)
— do **not** open a public issue for anything you believe is exploitable.

You can expect an acknowledgement within a few days. Once a fix ships,
the report is credited in the advisory and the changelog (tell us if you
prefer to stay anonymous).

## Scope notes

- lockvet parses untrusted lockfiles by design. Parser crashes, hangs, or
  memory blow-ups on crafted input are in scope (all parsers are
  continuously fuzzed, but reports are very welcome).
- Output injection is in scope: lockvet renders registry- and
  advisory-supplied text into terminals, Markdown (PR comments), and
  SARIF, and sanitizes it — anything that escapes that sanitization
  (e.g. ANSI escapes, Markdown/HTML injection into a PR comment) is a
  vulnerability.
- lockvet sends only package names/versions to the registries and
  advisory databases documented in the README. Anything that causes it
  to exfiltrate more than that is in scope.
- False negatives in heuristic signals (typosquat suspects, provenance,
  freshness) are quality issues, not vulnerabilities — ordinary issues
  are fine for those.

## Supported versions

Only the latest release receives fixes.

## Verifying what you run

Release artifacts carry Sigstore build provenance — see
[Verifying a release](https://github.com/matteo-sung/lockvet#verifying-a-release).
