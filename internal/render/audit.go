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
		c.Deprecated || c.Unlisted || c.Fresh ||
		c.ScriptsAdded || c.ProvenanceDropped || c.LicenseChanged
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
			ver := join(c.New)
			if u := changesLink(c); u != "" {
				ver = s.href(u, ver)
			}
			fmt.Fprintln(w, "  "+s.cyan("•")+" "+pad(c.Name, nameW)+" "+ver+originSuffix(s, c)+ageSuffix(s, c))
			for _, v := range c.IntroducedVulns {
				fmt.Fprintf(w, "      %s %s\n", s.bred("▲ affected by "+v.ID+sev(v)), s.dim(v.Summary))
			}
			if n := len(c.ExistingVulns); n > 0 {
				fmt.Fprintf(w, "      %s\n", s.yellow(fmt.Sprintf("● %s this version (worst: %s)", pluralVerb(n, "known advisory affects", "known advisories affect"), worst(c.ExistingVulns))))
			}
			if c.Deprecated {
				reason := c.DeprecatedReason
				if reason == "" {
					reason = "no reason given"
				}
				fmt.Fprintf(w, "      %s %s\n", s.yellow("● deprecated upstream:"), s.dim(reason))
			}
			if c.Unlisted {
				fmt.Fprintf(w, "      %s %s\n", s.bred("▲ not in registry index: "+join(c.UnlistedVersions)), s.dim("missing from the registry index though other versions are listed — unpublished/deleted release; you may not be able to install this again; verify before trusting"))
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
	if metaChecked && (sum.Fresh > 0 || sum.Deprecated > 0 || sum.Unlisted > 0 || sum.LicenseChanged > 0) {
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
		fmt.Fprintf(w, "\nRelease metadata: %s (via [deps.dev](https://deps.dev) and the package registries)\n", strings.Join(bits, ", "))
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
			verCell := join(c.New)
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
				fmt.Fprintf(w, "| ⚠️ | ↳ affected by [%s](%s)%s | %s |%s\n", v.ID, v.URL, sev(v), esc(v.Summary), padCell)
			}
			if k := len(c.ExistingVulns); k > 0 {
				fmt.Fprintf(w, "| 🟡 | ↳ %s this version | worst: %s |%s\n", pluralVerb(k, "known advisory affects", "known advisories affect"), worst(c.ExistingVulns), padCell)
			}
			if c.Deprecated {
				reason := esc(c.DeprecatedReason)
				if reason == "" {
					reason = "no reason given"
				}
				fmt.Fprintf(w, "| 🟠 | ↳ deprecated upstream | %s |%s\n", reason, padCell)
			}
			if c.Unlisted {
				fmt.Fprintf(w, "| ❗ | ↳ not in registry index | %s — missing from the registry index though other versions are listed; unpublished/deleted release |%s\n", esc(join(c.UnlistedVersions)), padCell)
			}
			if c.LicenseChanged {
				fmt.Fprintf(w, "| ⚖️ | ↳ license change | %s |%s\n", esc(c.OldLicense+" → "+c.NewLicense), padCell)
			}
		}
		fmt.Fprintln(w, "\n</details>")
	}
	fmt.Fprintf(w, "\n<sub>generated by <a href=\"https://github.com/matteo-sung/lockvet\">lockvet audit</a></sub>\n")
}
