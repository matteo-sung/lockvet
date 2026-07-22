// Package render prints diffs as colored terminal output or markdown.
package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// maxFixedShown caps per-package "fixes" lines in human output.
const maxFixedShown = 3

func pluralVerb(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", n, plural)
}

// worst returns the highest severity present, or the first ID as fallback.
func worst(vs []diffx.Vuln) string {
	// vs is pre-sorted by severity (critical first).
	if len(vs) == 0 {
		return ""
	}
	if vs[0].Severity != "" {
		return vs[0].Severity + ", " + vs[0].ID
	}
	return vs[0].ID
}

// ANSI helpers (disabled when Color is false).
type styler struct{ on bool }

func (s styler) c(code, str string) string {
	if !s.on || str == "" {
		return str
	}
	return "\x1b[" + code + "m" + str + "\x1b[0m"
}
func (s styler) red(x string) string    { return s.c("31", x) }
func (s styler) bred(x string) string   { return s.c("1;31", x) }
func (s styler) green(x string) string  { return s.c("32", x) }
func (s styler) yellow(x string) string { return s.c("33", x) }
func (s styler) dim(x string) string    { return s.c("2", x) }
func (s styler) bold(x string) string   { return s.c("1", x) }
func (s styler) cyan(x string) string   { return s.c("36", x) }

// Terminal writes a colored human report.
func Terminal(w io.Writer, diffs []diffx.FileDiff, sum diffx.Summary, color bool, vulnsChecked bool) {
	s := styler{on: color}
	for _, fd := range diffs {
		fmt.Fprintf(w, "\n%s %s\n", s.bold(fd.Path), s.dim("("+fd.Ecosystem+")"))
		if len(fd.Changes) == 0 {
			fmt.Fprintf(w, "  %s\n", s.dim("no package changes"))
			continue
		}
		nameW, fromW := 0, 0
		for _, c := range fd.Changes {
			nameW = max(nameW, len(c.Name))
			fromW = max(fromW, len(join(c.Old)))
		}
		for _, c := range fd.Changes {
			fmt.Fprintln(w, "  "+line(s, c, nameW, fromW))
			for _, v := range c.IntroducedVulns {
				fmt.Fprintf(w, "      %s %s\n", s.bred("▲ introduces "+v.ID+sev(v)), s.dim(v.Summary))
			}
			for k, v := range c.FixedVulns {
				if k == maxFixedShown {
					fmt.Fprintf(w, "      %s\n", s.green(fmt.Sprintf("▼ …and %d more fixed", len(c.FixedVulns)-maxFixedShown)))
					break
				}
				fmt.Fprintf(w, "      %s %s\n", s.green("▼ fixes "+v.ID+sev(v)), s.dim(v.Summary))
			}
			if n := len(c.ExistingVulns); n > 0 {
				fmt.Fprintf(w, "      %s\n", s.yellow(fmt.Sprintf("● %s both versions (worst: %s)", pluralVerb(n, "known advisory affects", "known advisories affect"), worst(c.ExistingVulns))))
			}
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, summaryLine(s, sum, vulnsChecked))
}

func sev(v diffx.Vuln) string {
	if v.Severity != "" {
		return " (" + v.Severity + ")"
	}
	return ""
}

func line(s styler, c diffx.Change, nameW, fromW int) string {
	name := pad(c.Name, nameW)
	from, to := join(c.Old), join(c.New)
	switch c.Kind {
	case diffx.Added:
		return fmt.Sprintf("%s %s %s", s.green("+"), name, s.green(to+"  (added)"))
	case diffx.Removed:
		return fmt.Sprintf("%s %s %s", s.dim("-"), name, s.dim(from+"  (removed)"))
	}
	arrow, lvl := "↑", ""
	if c.Kind == diffx.Downgraded {
		arrow = "↓"
	}
	switch c.Level {
	case vers.Major:
		lvl = s.bred("MAJOR")
	case vers.Minor:
		lvl = s.yellow("minor")
	case vers.Patch:
		lvl = s.dim("patch")
	case vers.Unknown:
		lvl = s.dim("?")
	}
	if c.Kind == diffx.Downgraded {
		lvl += s.bred(" DOWNGRADE")
	}
	return fmt.Sprintf("%s %s %s → %s  %s", s.cyan(arrow), name, pad(from, fromW), to, lvl)
}

func summaryLine(s styler, sum diffx.Summary, vulnsChecked bool) string {
	parts := []string{fmt.Sprintf("%s changed", plural(sum.Total, "package"))}
	if sum.Major > 0 {
		parts = append(parts, s.bred(fmt.Sprintf("%d major", sum.Major)))
	}
	if sum.Minor > 0 {
		parts = append(parts, s.yellow(fmt.Sprintf("%d minor", sum.Minor)))
	}
	if sum.Patch > 0 {
		parts = append(parts, fmt.Sprintf("%d patch", sum.Patch))
	}
	if sum.Added > 0 {
		parts = append(parts, s.green(fmt.Sprintf("%d added", sum.Added)))
	}
	if sum.Removed > 0 {
		parts = append(parts, s.dim(fmt.Sprintf("%d removed", sum.Removed)))
	}
	if sum.Downgraded > 0 {
		parts = append(parts, s.bred(fmt.Sprintf("%d downgraded", sum.Downgraded)))
	}
	out := strings.Join(parts, " · ")
	if vulnsChecked {
		vi := fmt.Sprintf("%d introduced", sum.VulnsIntroduced)
		if sum.VulnsIntroduced > 0 {
			vi = s.bred(vi)
		}
		vf := fmt.Sprintf("%d fixed", sum.VulnsFixed)
		if sum.VulnsFixed > 0 {
			vf = s.green(vf)
		}
		out += " · vulnerabilities: " + vi + ", " + vf
		if sum.VulnsExisting > 0 {
			out += ", " + s.yellow(fmt.Sprintf("%d unresolved", sum.VulnsExisting))
		}
	}
	return out
}

// Markdown writes a report suited for PR comments.
func Markdown(w io.Writer, diffs []diffx.FileDiff, sum diffx.Summary, vulnsChecked bool) {
	fmt.Fprintf(w, "### 🔍 lockvet report\n\n")
	fmt.Fprintf(w, "**%s changed**", plural(sum.Total, "package"))
	var bits []string
	if sum.Major > 0 {
		bits = append(bits, fmt.Sprintf("**%d major** ⚠️", sum.Major))
	}
	if sum.Minor > 0 {
		bits = append(bits, fmt.Sprintf("%d minor", sum.Minor))
	}
	if sum.Patch > 0 {
		bits = append(bits, fmt.Sprintf("%d patch", sum.Patch))
	}
	if sum.Added > 0 {
		bits = append(bits, fmt.Sprintf("%d added", sum.Added))
	}
	if sum.Removed > 0 {
		bits = append(bits, fmt.Sprintf("%d removed", sum.Removed))
	}
	if len(bits) > 0 {
		fmt.Fprintf(w, ": %s", strings.Join(bits, ", "))
	}
	fmt.Fprintln(w)
	if vulnsChecked {
		fmt.Fprintf(w, "\nVulnerabilities: **%d introduced**, %d fixed, %d unresolved (via [OSV.dev](https://osv.dev))\n", sum.VulnsIntroduced, sum.VulnsFixed, sum.VulnsExisting)
	}
	for _, fd := range diffs {
		fmt.Fprintf(w, "\n<details%s>\n<summary><code>%s</code> — %s</summary>\n\n", openAttr(fd), fd.Path, plural(len(fd.Changes), "change"))
		fmt.Fprintln(w, "| | Package | From | To | Level |")
		fmt.Fprintln(w, "|---|---|---|---|---|")
		for _, c := range fd.Changes {
			icon, lvl := "🔼", string(c.LevelString)
			switch {
			case c.Kind == diffx.Added:
				icon, lvl = "➕", "added"
			case c.Kind == diffx.Removed:
				icon, lvl = "➖", "removed"
			case c.Kind == diffx.Downgraded:
				icon, lvl = "🔽", lvl+" **downgrade**"
			case c.Level == vers.Major:
				lvl = "**MAJOR**"
			}
			fmt.Fprintf(w, "| %s | `%s` | %s | %s | %s |\n", icon, c.Name, join(c.Old), join(c.New), lvl)
			for _, v := range c.IntroducedVulns {
				fmt.Fprintf(w, "| ⚠️ | ↳ introduces [%s](%s)%s | | | %s |\n", v.ID, v.URL, sev(v), esc(v.Summary))
			}
			for k, v := range c.FixedVulns {
				if k == maxFixedShown {
					fmt.Fprintf(w, "| ✅ | ↳ …and %d more fixed | | | |\n", len(c.FixedVulns)-maxFixedShown)
					break
				}
				fmt.Fprintf(w, "| ✅ | ↳ fixes [%s](%s)%s | | | %s |\n", v.ID, v.URL, sev(v), esc(v.Summary))
			}
			if n := len(c.ExistingVulns); n > 0 {
				fmt.Fprintf(w, "| 🟡 | ↳ %s both versions | | | worst: %s |\n", pluralVerb(n, "known advisory affects", "known advisories affect"), worst(c.ExistingVulns))
			}
		}
		fmt.Fprintln(w, "\n</details>")
	}
	fmt.Fprintf(w, "\n<sub>generated by <a href=\"https://github.com/matteo-sung/lockvet\">lockvet</a></sub>\n")
}

func openAttr(fd diffx.FileDiff) string {
	for _, c := range fd.Changes {
		if len(c.IntroducedVulns) > 0 || c.Level == vers.Major {
			return " open"
		}
	}
	return ""
}

func esc(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func join(vs []string) string { return strings.Join(vs, ", ") }

func pad(s string, w int) string {
	if len(s) >= w {
		return s
	}
	return s + strings.Repeat(" ", w-len(s))
}

func plural(n int, word string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
