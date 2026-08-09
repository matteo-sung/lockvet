package render

// audit.go — renderers for `lockvet audit`. An audit reports on the full
// dependency set, so unlike the diff renderers these show findings only:
// listing 700 healthy pins helps nobody.

import (
	"fmt"
	"io"
	"strings"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// hasAuditFinding reports whether a pinned package is worth a row in the
// audit report. (In audit mode every package arrives as an Added change, so
// vulnerabilities land in IntroducedVulns and the transition-based signals —
// install scripts, provenance — never fire.)
func hasAuditFinding(c diffx.Change) bool {
	return len(c.IntroducedVulns)+len(c.ExistingVulns) > 0 ||
		c.Deprecated || c.Unlisted || c.Fresh || c.TyposquatOf != "" ||
		c.ScriptsAdded || c.ProvenanceDropped || c.LicenseChanged ||
		c.TagMismatch
}

// auditCounts tallies the package-level numbers the summaries use.
type auditCounts struct {
	pkgs, files, findings, vulnerable int
}

func countAudit(diffs []diffx.FileDiff) auditCounts {
	var n auditCounts
	n.files = len(diffs)
	for _, fd := range diffs {
		for _, c := range fd.Changes {
			n.pkgs++
			if hasAuditFinding(c) {
				n.findings++
			}
			if len(c.IntroducedVulns)+len(c.ExistingVulns) > 0 {
				n.vulnerable++
			}
		}
	}
	return n
}

func pluralAdvisories(n int) string {
	if n == 1 {
		return "1 advisory"
	}
	return fmt.Sprintf("%d advisories", n)
}

// AuditTerminal renders an audit for the terminal: per lockfile, only the
// packages with findings, then a one-line summary.
func AuditTerminal(w io.Writer, diffs []diffx.FileDiff, sum diffx.Summary, color, vulnsChecked, metaChecked bool, freshDays int) {
	s := styler{on: color}
	for _, fd := range diffs {
		fmt.Fprintf(w, "\n%s %s\n", s.bold(fd.Path), s.dim("("+fd.Ecosystem+" · "+plural(len(fd.Changes), "package")+")"))
		var rows []diffx.Change
		for _, c := range fd.Changes {
			if hasAuditFinding(c) {
				rows = append(rows, c)
			}
		}
		if len(rows) == 0 {
			fmt.Fprintf(w, "  %s\n", s.green("✓")+s.dim(" no findings"))
			continue
		}
		nameW := 0
		for _, c := range rows {
			nameW = max(nameW, len(c.Name))
		}
		for _, c := range rows {
			ver := dispVers(c, c.New)
			if u := changesLink(c); u != "" {
				ver = s.href(u, ver)
			}
			fmt.Fprintln(w, "  "+s.cyan("•")+" "+pad(c.Name, nameW)+" "+ver+originSuffix(s, c)+ageSuffix(s, c))
			for _, v := range c.IntroducedVulns {
				fix := ""
				if v.FixedIn != "" {
					fix = " " + s.green("· fixed in "+v.FixedIn)
				}
				fmt.Fprintf(w, "      %s %s%s\n", s.bred("▲ affected by "+v.ID+sev(v)), s.dim(v.Summary), fix)
			}
			if n := len(c.ExistingVulns); n > 0 {
				note := fmt.Sprintf("● %s this version (worst: %s)", pluralVerb(n, "known advisory affects", "known advisories affect"), worst(c.ExistingVulns))
				if fx := allFixedIn(c.ExistingVulns); fx != "" {
					note += " — all fixed in ≥ " + fx
				}
				fmt.Fprintf(w, "      %s\n", s.yellow(note))
			}
			if c.Deprecated {
				reason := c.DeprecatedReason
				if reason == "" {
					reason = "no reason given"
				}
				fmt.Fprintf(w, "      %s %s\n", s.yellow("● deprecated upstream:"), s.dim(reason))
			}
			if c.Unlisted {
				if c.Ecosystem == "GitHub Actions" {
					fmt.Fprintf(w, "      %s %s\n", s.bred("▲ not a release: "+dispVers(c, c.UnlistedVersions)), s.dim("pinned ref matches no tag in the action's repository — release tags are how actions ship; verify where the commit comes from"))
				} else if c.Ecosystem == "pre-commit" {
					fmt.Fprintf(w, "      %s %s\n", s.bred("▲ not a release: "+dispVers(c, c.UnlistedVersions)), s.dim("pinned rev matches no tag in the hook repository — pre-commit runs this rev on every commit; verify where it comes from"))
				} else if c.Ecosystem == "GitLab CI" {
					fmt.Fprintf(w, "      %s %s\n", s.bred("▲ not a release: "+dispVers(c, c.UnlistedVersions)), s.dim("pinned version matches no tag in the component's project — catalog releases are cut from tags; verify what the include fetches"))
				} else if c.Ecosystem == "mise/asdf" {
					fmt.Fprintf(w, "      %s %s\n", s.bred("▲ not a release: "+dispVers(c, c.UnlistedVersions)), s.dim("pinned version matches no tag in the tool's repository — mise/asdf installs exactly what the pin names; verify what gets installed"))
				} else if c.Ecosystem == "SwiftURL" {
					fmt.Fprintf(w, "      %s %s\n", s.bred("▲ not a release: "+join(c.UnlistedVersions)), s.dim("no matching tag in the package's repository — version pins only ever resolve from tags; verify what this pin fetches"))
				} else if vcpkgBaseline(c) {
					fmt.Fprintf(w, "      %s %s\n", s.bred("▲ not a commit in the registry: "+join(c.UnlistedVersions)), s.dim("this baseline is not a commit in the registry's repository — a baseline only reachable in a fork is the poisoned-registry shape; verify where it comes from"))
				} else if c.Ecosystem == "Docker" {
					fmt.Fprintf(w, "      %s %s\n", s.bred("▲ not in the registry: "+join(c.UnlistedVersions)), s.dim("the registry does not serve this for the image — a deleted tag, the wrong repository, or a fabricated pin; verify before trusting"))
				} else {
					fmt.Fprintf(w, "      %s %s\n", s.bred("▲ not in registry index: "+join(c.UnlistedVersions)), s.dim("missing from the registry index though other versions are listed — unpublished/deleted release; you may not be able to install this again; verify before trusting"))
				}
			}
			if c.TagMismatch {
				mismatchWhy := "the pinned commit is not what the upstream tag points at today — released tags are immutable; either the tag has been moved since this was resolved, or the lockfile was edited; verify the commit before trusting it"
				if c.Ecosystem == "Gradle" {
					mismatchWhy = "the pinned distributionSha256Sum is not any checksum Gradle publishes for this version — the wrapper would happily verify a poisoned distribution against a poisoned checksum; do not run this build until you know why"
				}
				fmt.Fprintf(w, "      %s %s\n", s.bred("‼ tag mismatch: "+join(c.TagMismatches)), s.dim(mismatchWhy))
			}
			if c.TyposquatOf != "" {
				fmt.Fprintf(w, "      %s %s\n", s.bred("≈ name resembles "+c.TyposquatOf+":"), s.dim("pinned recently and one edit away from a popular package — the shape of a typosquat; make sure this is the package you meant"))
			}
			if c.LicenseChanged {
				fmt.Fprintf(w, "      %s %s\n", s.yellow("● license change:"), s.dim(c.OldLicense+" → "+c.NewLicense))
			}
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, auditSummaryLine(s, diffs, sum, vulnsChecked, metaChecked, freshDays))
}

func auditSummaryLine(s styler, diffs []diffx.FileDiff, sum diffx.Summary, vulnsChecked, metaChecked bool, freshDays int) string {
	n := countAudit(diffs)
	out := fmt.Sprintf("audited %s across %s", plural(n.pkgs, "package"), plural(n.files, "lockfile"))
	if sum.Direct+sum.Transitive > 0 {
		out += fmt.Sprintf(" · %d direct, %s", sum.Direct, s.dim(fmt.Sprintf("%d transitive", sum.Transitive)))
	}
	if vulnsChecked {
		adv := sum.VulnsIntroduced + sum.VulnsExisting
		part := fmt.Sprintf("%s affecting %s", pluralAdvisories(adv), plural(n.vulnerable, "package"))
		if adv > 0 {
			part = s.bred(part)
		}
		out += " · " + part
	}
	if metaChecked {
		if sum.Fresh > 0 {
			out += " · " + s.yellow(fmt.Sprintf("%d published <%dd ago", sum.Fresh, freshDays))
		}
		if sum.Deprecated > 0 {
			out += " · " + s.yellow(fmt.Sprintf("%d deprecated", sum.Deprecated))
		}
		if sum.Unlisted > 0 {
			out += " · " + s.bred(pluralVerb(sum.Unlisted, "version", "versions")+" not in registry index")
		}
		if sum.Typosquats > 0 {
			out += " · " + s.bred(pluralVerb(sum.Typosquats, "name resembles", "names resemble")+" a popular package")
		}
		if sum.TagMismatch > 0 {
			out += " · " + s.bred(pluralVerb(sum.TagMismatch, "pin doesn't", "pins don't")+" match the upstream tag")
		}
	}
	if sum.Ignored > 0 {
		out += " · " + s.dim(plural(sum.Ignored, "finding")+" ignored (.lockvetignore)")
	}
	if n.findings == 0 {
		out += " · " + s.green("no findings")
	}
	return out
}

// AuditMarkdown renders an audit report suited for issues, PR comments, or
// pasting into a chat.
func AuditMarkdown(w io.Writer, diffs []diffx.FileDiff, sum diffx.Summary, vulnsChecked, metaChecked bool, freshDays int) {
	n := countAudit(diffs)
	fmt.Fprintf(w, "### 🔍 lockvet audit\n\n")
	fmt.Fprintf(w, "**%s audited** across %s", plural(n.pkgs, "package"), plural(n.files, "lockfile"))
	if sum.Direct+sum.Transitive > 0 {
		fmt.Fprintf(w, ": %d direct, %d transitive", sum.Direct, sum.Transitive)
	}
	fmt.Fprintln(w)
	if vulnsChecked {
		adv := sum.VulnsIntroduced + sum.VulnsExisting
		if adv > 0 {
			fmt.Fprintf(w, "\nVulnerabilities: **%s** affecting **%s** (via [OSV.dev](https://osv.dev))\n", pluralAdvisories(adv), plural(n.vulnerable, "package"))
		} else {
			fmt.Fprintf(w, "\nVulnerabilities: none known (via [OSV.dev](https://osv.dev))\n")
		}
	}
	if metaChecked && (sum.Fresh > 0 || sum.Deprecated > 0 || sum.Unlisted > 0 || sum.LicenseChanged > 0 || sum.Typosquats > 0 || sum.TagMismatch > 0) {
		var bits []string
		if sum.Fresh > 0 {
			bits = append(bits, fmt.Sprintf("**%s published <%dd ago** ⏱", plural(sum.Fresh, "version"), freshDays))
		}
		if sum.Deprecated > 0 {
			bits = append(bits, fmt.Sprintf("**%d deprecated**", sum.Deprecated))
		}
		if sum.Unlisted > 0 {
			bits = append(bits, fmt.Sprintf("**%s not in the registry index** ❗", plural(sum.Unlisted, "version")))
		}
		if sum.Typosquats > 0 {
			bits = append(bits, fmt.Sprintf("**%s a popular package** ≈", pluralVerb(sum.Typosquats, "name resembles", "names resemble")))
		}
		if sum.TagMismatch > 0 {
			bits = append(bits, fmt.Sprintf("**%s not what the upstream tag points at** ‼", pluralVerb(sum.TagMismatch, "pinned commit is", "pinned commits are")))
		}
		fmt.Fprintf(w, "\nRelease metadata: %s (via [deps.dev](https://deps.dev) and the package registries)\n", strings.Join(bits, ", "))
	}
	if sum.Ignored > 0 {
		fmt.Fprintf(w, "\nIgnored: %s acknowledged via `.lockvetignore`\n", plural(sum.Ignored, "finding"))
	}
	if n.findings == 0 {
		fmt.Fprintf(w, "\nNo findings. 🎉\n")
	}

	ageCol := ""
	if metaChecked {
		ageCol = " Age |"
	}
	for _, fd := range diffs {
		var rows []diffx.Change
		for _, c := range fd.Changes {
			if hasAuditFinding(c) {
				rows = append(rows, c)
			}
		}
		if len(rows) == 0 {
			fmt.Fprintf(w, "\n<details>\n<summary><code>%s</code> — %s, no findings ✓</summary>\n\n</details>\n", fd.Path, plural(len(fd.Changes), "package"))
			continue
		}
		fmt.Fprintf(w, "\n<details open>\n<summary><code>%s</code> — %s, %s</summary>\n\n", fd.Path, plural(len(fd.Changes), "package"), plural(len(rows), "finding"))
		fmt.Fprintln(w, "| | Package | Version |"+ageCol)
		fmt.Fprintln(w, "|---|---|---|"+strings.Repeat("---|", strings.Count(ageCol, "|")))
		padCell := ""
		if metaChecked {
			padCell = " |"
		}
		for _, c := range rows {
			pkgCell := "`" + c.Name + "`"
			if u := registryLink(c); u != "" {
				pkgCell = "[" + pkgCell + "](" + u + ")"
			}
			switch c.Origin {
			case "direct":
				pkgCell += " <sub>**direct**</sub>"
			case "transitive":
				if len(c.Via) > 0 {
					pkgCell += " <sub>via " + esc(strings.Join(c.Via, " › ")) + "</sub>"
				} else {
					pkgCell += " <sub>transitive</sub>"
				}
			}
			verCell := dispVers(c, c.New)
			if u := changesLink(c); u != "" && verCell != "" {
				verCell = "[" + verCell + "](" + u + ")"
			}
			extra := ""
			if metaChecked {
				switch {
				case c.Fresh:
					extra = fmt.Sprintf(" **%s** ⏱ |", age(c.AgeDays))
				case c.PublishedAt != "":
					extra = " " + age(c.AgeDays) + " |"
				default:
					extra = " |"
				}
			}
			fmt.Fprintf(w, "| 📦 | %s | %s |%s\n", pkgCell, verCell, extra)
			for _, v := range c.IntroducedVulns {
				fix := ""
				if v.FixedIn != "" {
					fix = " — **fixed in " + esc(v.FixedIn) + "**"
				}
				fmt.Fprintf(w, "| ⚠️ | ↳ affected by [%s](%s)%s | %s%s |%s\n", v.ID, v.URL, sev(v), esc(v.Summary), fix, padCell)
			}
			if k := len(c.ExistingVulns); k > 0 {
				note := "worst: " + worst(c.ExistingVulns)
				if fx := allFixedIn(c.ExistingVulns); fx != "" {
					note += " — all fixed in ≥ " + esc(fx)
				}
				fmt.Fprintf(w, "| 🟡 | ↳ %s this version | %s |%s\n", pluralVerb(k, "known advisory affects", "known advisories affect"), note, padCell)
			}
			if c.Deprecated {
				reason := esc(c.DeprecatedReason)
				if reason == "" {
					reason = "no reason given"
				}
				fmt.Fprintf(w, "| 🟠 | ↳ deprecated upstream | %s |%s\n", reason, padCell)
			}
			if c.Unlisted {
				if c.Ecosystem == "GitHub Actions" {
					fmt.Fprintf(w, "| ❗ | ↳ not a release | %s — pinned ref matches no tag in the action's repository; verify where the commit comes from |%s\n", esc(dispVers(c, c.UnlistedVersions)), padCell)
				} else if c.Ecosystem == "pre-commit" {
					fmt.Fprintf(w, "| ❗ | ↳ not a release | %s — pinned rev matches no tag in the hook repository; pre-commit runs this rev on every commit |%s\n", esc(dispVers(c, c.UnlistedVersions)), padCell)
				} else if c.Ecosystem == "GitLab CI" {
					fmt.Fprintf(w, "| ❗ | ↳ not a release | %s — pinned version matches no tag in the component's project; catalog releases are cut from tags |%s\n", esc(dispVers(c, c.UnlistedVersions)), padCell)
				} else if c.Ecosystem == "mise/asdf" {
					fmt.Fprintf(w, "| ❗ | ↳ not a release | %s — pinned version matches no tag in the tool's repository; mise/asdf installs exactly what the pin names |%s\n", esc(dispVers(c, c.UnlistedVersions)), padCell)
				} else if c.Ecosystem == "SwiftURL" {
					fmt.Fprintf(w, "| ❗ | ↳ not a release | %s — no matching tag in the package's repository; version pins only resolve from tags |%s\n", esc(join(c.UnlistedVersions)), padCell)
				} else if vcpkgBaseline(c) {
					fmt.Fprintf(w, "| ❗ | ↳ not a commit in the registry | %s — the baseline is not a commit in the registry's repository; verify where it comes from |%s\n", esc(join(c.UnlistedVersions)), padCell)
				} else if c.Ecosystem == "Docker" {
					fmt.Fprintf(w, "| ❗ | ↳ not in the registry | %s — the registry does not serve this for the image; deleted tag, wrong repository, or fabricated pin |%s\n", esc(join(c.UnlistedVersions)), padCell)
				} else {
					fmt.Fprintf(w, "| ❗ | ↳ not in registry index | %s — missing from the registry index though other versions are listed; unpublished/deleted release |%s\n", esc(join(c.UnlistedVersions)), padCell)
				}
			}
			if c.TagMismatch {
				fmt.Fprintf(w, "| ‼ | ↳ tag mismatch | %s — released tags are immutable; the tag was moved since resolution or the lockfile was edited |%s\n", esc(join(c.TagMismatches)), padCell)
			}
			if c.TyposquatOf != "" {
				fmt.Fprintf(w, "| ≈ | ↳ name resembles `%s` | pinned recently and one edit away from a popular package — make sure this is the package you meant |%s\n", esc(c.TyposquatOf), padCell)
			}
			if c.LicenseChanged {
				fmt.Fprintf(w, "| ⚖️ | ↳ license change | %s |%s\n", esc(c.OldLicense+" → "+c.NewLicense), padCell)
			}
		}
		fmt.Fprintln(w, "\n</details>")
	}
	fmt.Fprintf(w, "\n<sub>generated by <a href=\"https://github.com/matteo-sung/lockvet\">lockvet audit</a></sub>\n")
}
