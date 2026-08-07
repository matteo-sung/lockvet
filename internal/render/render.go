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

// maxNotesBlocks caps release-notes blocks in one markdown report so PR
// comments stay under forge size limits.
const maxNotesBlocks = 20

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

// href wraps text in an OSC 8 terminal hyperlink (modern terminals make it
// clickable; others ignore the escapes). Only emitted when color is on,
// which implies a real TTY.
func (s styler) href(url, text string) string {
	if !s.on || url == "" || text == "" {
		return text
	}
	return "\x1b]8;;" + url + "\x1b\\" + text + "\x1b]8;;\x1b\\"
}

// age renders AgeDays compactly: "today", "3d", "4mo", "2y".
func age(days int) string {
	switch {
	case days < 1:
		return "today"
	case days < 60:
		return fmt.Sprintf("%dd", days)
	case days < 730:
		return fmt.Sprintf("%dmo", days/30)
	default:
		return fmt.Sprintf("%dy", days/365)
	}
}

// ageSuffix is what gets appended to a change line when release metadata
// is available: loud for fresh versions, quiet otherwise.
func ageSuffix(s styler, c diffx.Change) string {
	if c.PublishedAt == "" {
		return ""
	}
	if c.Fresh {
		when := "today"
		if c.AgeDays > 0 {
			when = pluralVerb(c.AgeDays, "day", "days") + " ago"
		}
		return "  " + s.yellow("⏱ published "+when)
	}
	return "  " + s.dim("("+age(c.AgeDays)+" old)")
}

// originSuffix explains why a package moved: it's a dependency you declared
// ("direct"), or it was dragged along by one ("via <direct dep>").
func originSuffix(s styler, c diffx.Change) string {
	switch c.Origin {
	case "direct":
		return "  " + s.cyan("(direct)")
	case "transitive":
		if len(c.Via) > 0 {
			return "  " + s.dim("via "+viaChain(c.Via))
		}
		return "  " + s.dim("(transitive)")
	}
	return ""
}

// viaChain renders the pull-in chain compactly: "a", "a › b",
// and "a › … › z" when it is deeper than two hops.
func viaChain(via []string) string {
	switch len(via) {
	case 1:
		return via[0]
	case 2:
		return via[0] + " › " + via[1]
	default:
		return via[0] + " › … › " + via[len(via)-1]
	}
}

// Terminal writes a colored human report.
func Terminal(w io.Writer, diffs []diffx.FileDiff, sum diffx.Summary, color bool, vulnsChecked, metaChecked bool, freshDays int) {
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
			fromW = max(fromW, len(dispVers(c, c.Old)))
		}
		for _, c := range fd.Changes {
			fmt.Fprintln(w, "  "+line(s, c, nameW, fromW)+originSuffix(s, c)+ageSuffix(s, c))
			if c.Deprecated {
				reason := c.DeprecatedReason
				if reason == "" {
					reason = "no reason given"
				}
				fmt.Fprintf(w, "      %s %s\n", s.yellow("● deprecated upstream:"), s.dim(reason))
			}
			if c.Unlisted {
				if c.Ecosystem == "GitHub Actions" {
					fmt.Fprintf(w, "      %s %s\n", s.bred("▲ not a release: "+dispVers(c, c.UnlistedVersions)), s.dim("pinned ref matches no tag in the action's repository — release tags are how actions ship, and the tj-actions attack pinned exactly like this; verify the commit"))
				} else if c.Ecosystem == "SwiftURL" {
					fmt.Fprintf(w, "      %s %s\n", s.bred("▲ not a release: "+join(c.UnlistedVersions)), s.dim("no matching tag in the package's repository — version pins only ever resolve from tags, so this one was deleted or renamed after resolution; verify what the pin fetches"))
				} else {
					fmt.Fprintf(w, "      %s %s\n", s.bred("▲ not in registry index: "+join(c.UnlistedVersions)), s.dim("missing from the registry index though other versions are listed — unpublished/deleted release, or published minutes ago; verify before trusting"))
				}
			}
			if c.IntegrityChanged {
				fmt.Fprintf(w, "      %s %s\n", s.bred("‼ integrity changed: "+join(c.IntegrityVersions)), s.dim("same version, different content hash — registries never change a published artifact, so the tarball this pin expects was replaced; do not trust this without finding out why"))
			}
			if c.TagMismatch {
				fmt.Fprintf(w, "      %s %s\n", s.bred("‼ tag mismatch: "+join(c.TagMismatches)), s.dim("the pinned commit is not what the upstream tag points at today — released tags are immutable; either the tag has been moved since this was resolved, or the lockfile was edited; verify the commit before trusting it"))
			}
			if c.RegistryMoved {
				fmt.Fprintf(w, "      %s %s\n", s.bred("⇄ resolution moved: "+c.OldHost+" → "+c.NewHost), s.dim("this package now resolves from the public registry instead of a private host — the shape of a dependency-confusion attack; make sure the public package is really yours"))
			}
			if c.ScriptsAdded {
				fmt.Fprintf(w, "      %s %s\n", s.bred("⚙ install scripts added: "+join(c.ScriptedVersions)), s.dim("the old version ran no install scripts, this one does — a favourite payload vehicle for hijacked npm packages; review before trusting"))
			}
			if c.TyposquatOf != "" {
				fmt.Fprintf(w, "      %s %s\n", s.bred("≈ name resembles "+c.TyposquatOf+":"), s.dim("a new dependency one edit away from a popular package, and the release is young — the shape of a typosquat; make sure this is the package you meant"))
			}
			if c.ProvenanceDropped {
				fmt.Fprintf(w, "      %s %s\n", s.bred("⛨ provenance dropped: "+join(c.UnattestedVersions)), s.dim("every previous version was published with sigstore provenance, this one wasn't — legitimate CI keeps attesting, a stolen publish token can't; verify the release"))
			}
			if c.LicenseChanged {
				fmt.Fprintf(w, "      %s %s\n", s.yellow("● license change:"), s.dim(c.OldLicense+" → "+c.NewLicense))
			}
			for _, v := range c.IntroducedVulns {
				fmt.Fprintf(w, "      %s %s\n", s.bred("▲ introduces "+v.ID+sev(v)), s.dim(v.Summary))
			}
			if bits := ignoredBits(c); bits != "" {
				fmt.Fprintf(w, "      %s\n", s.dim("○ ignored (.lockvetignore): "+bits))
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
			for _, nt := range c.ReleaseNotes {
				head := nt.Tag
				if nt.Title != "" {
					head += " — " + nt.Title
				}
				fmt.Fprintf(w, "      %s\n", s.cyan("▤ "+s.href(nt.URL, head)))
				if nt.Excerpt == "" {
					continue
				}
				for _, ln := range strings.Split(nt.Excerpt, "\n") {
					fmt.Fprintf(w, "        %s\n", s.dim(ln))
				}
			}
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, summaryLine(s, sum, vulnsChecked, metaChecked, freshDays))
}

func sev(v diffx.Vuln) string {
	if v.Severity != "" {
		return " (" + v.Severity + ")"
	}
	return ""
}

func line(s styler, c diffx.Change, nameW, fromW int) string {
	name := pad(c.Name, nameW)
	from, to := dispVers(c, c.Old), dispVers(c, c.New)
	to = s.href(changesLink(c), to) // clickable upstream diff on TTYs
	switch c.Kind {
	case diffx.Added:
		return fmt.Sprintf("%s %s %s", s.green("+"), name, s.green(to)+s.green("  (added)"))
	case diffx.Removed:
		return fmt.Sprintf("%s %s %s", s.dim("-"), name, s.dim(from+"  (removed)"))
	case diffx.Repinned:
		return fmt.Sprintf("%s %s %s  %s", s.bred("‼"), name, from, s.bred("REPINNED")+s.dim(" (version unchanged)"))
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

func summaryLine(s styler, sum diffx.Summary, vulnsChecked, metaChecked bool, freshDays int) string {
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
	if sum.Direct+sum.Transitive > 0 {
		parts = append(parts, fmt.Sprintf("%d direct", sum.Direct), s.dim(fmt.Sprintf("%d transitive", sum.Transitive)))
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
	if metaChecked {
		if sum.Fresh > 0 {
			out += " · " + s.yellow(fmt.Sprintf("%d fresh (<%dd old)", sum.Fresh, freshDays))
		}
		if sum.Deprecated > 0 {
			out += " · " + s.yellow(fmt.Sprintf("%d deprecated", sum.Deprecated))
		}
		if sum.Unlisted > 0 {
			out += " · " + s.bred(pluralVerb(sum.Unlisted, "version", "versions")+" not in registry index")
		}
		if sum.LicenseChanged > 0 {
			out += " · " + s.yellow(fmt.Sprintf("%s changed", plural(sum.LicenseChanged, "license")))
		}
	}
	if sum.IntegrityChanged > 0 {
		out += " · " + s.bred(pluralVerb(sum.IntegrityChanged, "pin changes", "pins change")+" integrity without a version change")
	}
	if sum.TagMismatch > 0 {
		out += " · " + s.bred(pluralVerb(sum.TagMismatch, "pin doesn't", "pins don't")+" match the upstream tag")
	}
	if sum.RegistryMoved > 0 {
		out += " · " + s.bred(pluralVerb(sum.RegistryMoved, "resolution moves", "resolutions move")+" to the public registry")
	}
	if sum.Typosquats > 0 {
		out += " · " + s.bred(pluralVerb(sum.Typosquats, "name resembles", "names resemble")+" a popular package")
	}
	if sum.ScriptsAdded > 0 {
		out += " · " + s.bred(pluralVerb(sum.ScriptsAdded, "bump adds", "bumps add")+" install scripts")
	}
	if sum.ProvenanceDropped > 0 {
		out += " · " + s.bred(pluralVerb(sum.ProvenanceDropped, "bump drops", "bumps drop")+" provenance")
	}
	if sum.Ignored > 0 {
		out += " · " + s.dim(plural(sum.Ignored, "finding")+" ignored (.lockvetignore)")
	}
	return out
}

// ignoredBits lists a change's acknowledged findings ("fresh, GHSA-…").
func ignoredBits(c diffx.Change) string {
	bits := append([]string{}, c.Ignored...)
	for _, v := range c.IgnoredVulns {
		bits = append(bits, v.ID)
	}
	return strings.Join(bits, ", ")
}

// Markdown writes a report suited for PR comments.
func Markdown(w io.Writer, diffs []diffx.FileDiff, sum diffx.Summary, vulnsChecked, metaChecked bool, freshDays int) {
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
	if sum.Direct+sum.Transitive > 0 {
		bits = append(bits, fmt.Sprintf("%d direct", sum.Direct), fmt.Sprintf("%d transitive", sum.Transitive))
	}
	if len(bits) > 0 {
		fmt.Fprintf(w, ": %s", strings.Join(bits, ", "))
	}
	fmt.Fprintln(w)
	if vulnsChecked {
		fmt.Fprintf(w, "\nVulnerabilities: **%d introduced**, %d fixed, %d unresolved (via [OSV.dev](https://osv.dev))\n", sum.VulnsIntroduced, sum.VulnsFixed, sum.VulnsExisting)
	}
	if metaChecked && (sum.Fresh > 0 || sum.Deprecated > 0 || sum.LicenseChanged > 0 || sum.Unlisted > 0) {
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
		if sum.LicenseChanged > 0 {
			bits = append(bits, fmt.Sprintf("**%s changed** ⚖️", plural(sum.LicenseChanged, "license")))
		}
		fmt.Fprintf(w, "\nRelease metadata: %s (via [deps.dev](https://deps.dev) and the package registries)\n", strings.Join(bits, ", "))
	}
	if sum.IntegrityChanged > 0 {
		fmt.Fprintf(w, "\nIntegrity: **%s content hash without a version change** ‼ — registries never change a published artifact; find out why before merging\n", pluralVerb(sum.IntegrityChanged, "pin changes its", "pins change their"))
	}
	if sum.TagMismatch > 0 {
		fmt.Fprintf(w, "\nIntegrity: **%s not what the upstream tag points at** ‼ — released tags are immutable; the tag was moved since resolution or the lockfile was edited\n", pluralVerb(sum.TagMismatch, "pinned commit is", "pinned commits are"))
	}
	if sum.RegistryMoved > 0 {
		fmt.Fprintf(w, "\nResolution: **%s from a private host to the public registry** ⇄ — the shape of a dependency-confusion attack; make sure the public package is really yours\n", pluralVerb(sum.RegistryMoved, "package moves", "packages move"))
	}
	if sum.Typosquats > 0 {
		fmt.Fprintf(w, "\nTyposquat check: **%s a popular package** ≈ — new young dependencies one edit away from a well-known name; make sure they are the packages you meant\n", pluralVerb(sum.Typosquats, "added name resembles", "added names resemble"))
	}
	if sum.ScriptsAdded > 0 {
		fmt.Fprintf(w, "\nInstall scripts: **%s install scripts** ⚙ where the outgoing version ran none (via the npm registry)\n", pluralVerb(sum.ScriptsAdded, "bump adds", "bumps add"))
	}
	if sum.ProvenanceDropped > 0 {
		fmt.Fprintf(w, "\nProvenance: **%s sigstore provenance** ⛨ where every previous version attested (checked against the package registries)\n", pluralVerb(sum.ProvenanceDropped, "bump drops", "bumps drop"))
	}
	if sum.Ignored > 0 {
		fmt.Fprintf(w, "\nIgnored: %s acknowledged via `.lockvetignore`\n", plural(sum.Ignored, "finding"))
	}
	ageCol := ""
	if metaChecked {
		ageCol = " Age |"
	}
	notesShown, notesOmitted := 0, 0
	for _, fd := range diffs {
		fmt.Fprintf(w, "\n<details%s>\n<summary><code>%s</code> — %s</summary>\n\n", openAttr(fd), fd.Path, plural(len(fd.Changes), "change"))
		fmt.Fprintln(w, "| | Package | From | To | Level |"+ageCol)
		fmt.Fprintln(w, "|---|---|---|---|---|"+strings.Repeat("---|", strings.Count(ageCol, "|")))
		for _, c := range fd.Changes {
			icon, lvl := "🔼", string(c.LevelString)
			switch {
			case c.Kind == diffx.Added:
				icon, lvl = "➕", "added"
			case c.Kind == diffx.Removed:
				icon, lvl = "➖", "removed"
			case c.Kind == diffx.Repinned:
				icon, lvl = "‼", "**REPINNED** (version unchanged)"
			case c.Kind == diffx.Downgraded:
				icon, lvl = "🔽", lvl+" **downgrade**"
			case c.Level == vers.Major:
				lvl = "**MAJOR**"
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
			padCell := ""
			if metaChecked {
				padCell = " |"
			}
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
			toCell := dispVers(c, c.New)
			// Link the new version to the verified upstream diff (or
			// its release page): "what actually changed", one click.
			if u := changesLink(c); u != "" && toCell != "" {
				toCell = "[" + toCell + "](" + u + ")"
			}
			fmt.Fprintf(w, "| %s | %s | %s | %s | %s |%s\n", icon, pkgCell, dispVers(c, c.Old), toCell, lvl, extra)
			if c.Deprecated {
				reason := esc(c.DeprecatedReason)
				if reason == "" {
					reason = "no reason given"
				}
				fmt.Fprintf(w, "| 🟠 | ↳ deprecated upstream | | | %s |%s\n", reason, padCell)
			}
			if c.Unlisted {
				if c.Ecosystem == "GitHub Actions" {
					fmt.Fprintf(w, "| ❗ | ↳ not a release | | %s | pinned ref matches no tag in the action's repository — verify where the commit comes from |%s\n", esc(dispVers(c, c.UnlistedVersions)), padCell)
				} else if c.Ecosystem == "SwiftURL" {
					fmt.Fprintf(w, "| ❗ | ↳ not a release | | %s | no matching tag in the package's repository — version pins only resolve from tags; verify what this pin fetches |%s\n", esc(join(c.UnlistedVersions)), padCell)
				} else {
					fmt.Fprintf(w, "| ❗ | ↳ not in registry index | | %s | missing from the registry index though other versions are listed — unpublished/deleted release, or published minutes ago |%s\n", esc(join(c.UnlistedVersions)), padCell)
				}
			}
			if c.IntegrityChanged {
				fmt.Fprintf(w, "| ‼ | ↳ integrity changed | | %s | same version, different content hash — the artifact this pin expects was replaced; find out why before merging |%s\n", esc(join(c.IntegrityVersions)), padCell)
			}
			if c.TagMismatch {
				fmt.Fprintf(w, "| ‼ | ↳ tag mismatch | | %s | the pinned commit is not what the upstream tag points at today — the tag was moved since resolution or the lockfile was edited |%s\n", esc(join(c.TagMismatches)), padCell)
			}
			if c.RegistryMoved {
				fmt.Fprintf(w, "| ⇄ | ↳ resolution moved | %s | %s | now resolves from the public registry instead of a private host — the shape of a dependency-confusion attack |%s\n", esc(c.OldHost), esc(c.NewHost), padCell)
			}
			if c.ScriptsAdded {
				fmt.Fprintf(w, "| ⚙ | ↳ install scripts added | | %s | the old version ran no install scripts — a favourite payload vehicle for hijacked npm packages |%s\n", esc(join(c.ScriptedVersions)), padCell)
			}
			if c.TyposquatOf != "" {
				fmt.Fprintf(w, "| ≈ | ↳ name resembles `%s` | | | a new young dependency one edit away from a popular package — the shape of a typosquat; make sure this is the package you meant |%s\n", esc(c.TyposquatOf), padCell)
			}
			if c.ProvenanceDropped {
				fmt.Fprintf(w, "| ⛨ | ↳ provenance dropped | | %s | every previous version was published with sigstore provenance, this one wasn't — verify the release |%s\n", esc(join(c.UnattestedVersions)), padCell)
			}
			if c.LicenseChanged {
				fmt.Fprintf(w, "| ⚖️ | ↳ license change | | | %s |%s\n", esc(c.OldLicense+" → "+c.NewLicense), padCell)
			}
			for _, v := range c.IntroducedVulns {
				fmt.Fprintf(w, "| ⚠️ | ↳ introduces [%s](%s)%s | | | %s |%s\n", v.ID, v.URL, sev(v), esc(v.Summary), padCell)
			}
			if bits := ignoredBits(c); bits != "" {
				fmt.Fprintf(w, "| ○ | ↳ ignored via .lockvetignore | | | %s |%s\n", esc(bits), padCell)
			}
			for k, v := range c.FixedVulns {
				if k == maxFixedShown {
					fmt.Fprintf(w, "| ✅ | ↳ …and %d more fixed | | | |%s\n", len(c.FixedVulns)-maxFixedShown, padCell)
					break
				}
				fmt.Fprintf(w, "| ✅ | ↳ fixes [%s](%s)%s | | | %s |%s\n", v.ID, v.URL, sev(v), esc(v.Summary), padCell)
			}
			if n := len(c.ExistingVulns); n > 0 {
				fmt.Fprintf(w, "| 🟡 | ↳ %s both versions | | | worst: %s |%s\n", pluralVerb(n, "known advisory affects", "known advisories affect"), worst(c.ExistingVulns), padCell)
			}
		}
		for _, c := range fd.Changes {
			if len(c.ReleaseNotes) == 0 {
				continue
			}
			if notesShown >= maxNotesBlocks {
				notesOmitted++
				continue
			}
			notesShown++
			fmt.Fprintf(w, "\n<details>\n<summary>📝 <code>%s</code> release notes (%s)</summary>\n\n", c.Name, plural(len(c.ReleaseNotes), "release"))
			for _, nt := range c.ReleaseNotes {
				head := nt.Tag
				if nt.Title != "" {
					head += " — " + nt.Title
				}
				fmt.Fprintf(w, "**[%s](%s)**\n\n", esc(head), nt.URL)
				if nt.Excerpt != "" {
					for _, ln := range strings.Split(nt.Excerpt, "\n") {
						fmt.Fprintln(w, "> "+ln)
					}
					fmt.Fprintln(w)
				}
			}
			fmt.Fprintln(w, "</details>")
		}
		fmt.Fprintln(w, "\n</details>")
	}
	if notesOmitted > 0 {
		fmt.Fprintf(w, "\n<sub>release notes for %s omitted to keep this comment small — run lockvet locally for the rest</sub>\n", plural(notesOmitted, "more package"))
	}
	fmt.Fprintf(w, "\n<sub>generated by <a href=\"https://github.com/matteo-sung/lockvet\">lockvet</a></sub>\n")
}

func openAttr(fd diffx.FileDiff) string {
	for _, c := range fd.Changes {
		if len(c.IntroducedVulns) > 0 || c.Level == vers.Major || c.Fresh || c.Deprecated || c.LicenseChanged || c.IntegrityChanged || c.TagMismatch || c.RegistryMoved {
			return " open"
		}
	}
	return ""
}

func esc(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

// changesLink is the best "what changed upstream" URL for a change: the
// verified tag-to-tag diff when both versions matched real tags, else the
// release/tag page for the incoming version.
func changesLink(c diffx.Change) string {
	if c.CompareURL != "" {
		return c.CompareURL
	}
	return c.ReleaseURL
}

func join(vs []string) string { return strings.Join(vs, ", ") }

// dispVers renders pinned refs for display. Workflow pins get special
// care: full commit SHAs shorten to 7 hex characters, and a ref actreg
// resolved carries the release it stands for — "8f4b7f8 (=v4.2.2)".
func dispVers(c diffx.Change, vs []string) string {
	if c.Ecosystem != "GitHub Actions" {
		return join(vs)
	}
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = dispVer(c, v)
	}
	return strings.Join(out, ", ")
}

func dispVer(c diffx.Change, v string) string {
	d := v
	if len(v) == 40 && isHex(v) {
		d = v[:7]
	}
	if t := c.ResolvedRefs[v]; t != "" && t != v {
		d += " (=" + t + ")"
	}
	return d
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') && (b < 'A' || b > 'F') {
			return false
		}
	}
	return true
}

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
