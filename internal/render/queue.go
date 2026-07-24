package render

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// QueueRow is one pull request in a dependency-update queue overview.
type QueueRow struct {
	Label  string // e.g. "cli#9793" or "#123"
	URL    string
	Title  string
	Author string
	Sum    diffx.Summary
	// NoChanges: the PR touches no lockfiles (or no semantic changes).
	NoChanges bool
	// NoChangesMsg overrides the "no lockfile changes" label (e.g. when
	// an -only filter removed everything).
	NoChangesMsg string
	Err          string // fetch/parse failure; row shows the error instead
}

func (r QueueRow) noChangesMsg() string {
	if r.NoChangesMsg != "" {
		return r.NoChangesMsg
	}
	return "no lockfile changes"
}

// verdict classifies a row for sorting and for the leading marker.
//
//	0 = introduces vulnerabilities
//	1 = needs a look (major, downgrade, fresh, or deprecated)
//	2 = routine (only minor/patch/added/removed, nothing flagged)
//	3 = no lockfile changes
//	4 = error
func (r QueueRow) verdict() int {
	switch {
	case r.Err != "":
		return 4
	case r.NoChanges:
		return 3
	case r.Sum.VulnsIntroduced > 0:
		return 0
	case r.Sum.Major > 0 || r.Sum.Downgraded > 0 || r.Sum.Fresh > 0 || r.Sum.Deprecated > 0:
		return 1
	default:
		return 2
	}
}

// SortQueue orders rows most-alarming first (stable within a class, so the
// incoming most-recently-updated order is kept).
func SortQueue(rows []QueueRow) {
	// insertion sort by verdict, then vulns desc, majors desc — n is tiny.
	less := func(a, b QueueRow) bool {
		if a.verdict() != b.verdict() {
			return a.verdict() < b.verdict()
		}
		if a.Sum.VulnsIntroduced != b.Sum.VulnsIntroduced {
			return a.Sum.VulnsIntroduced > b.Sum.VulnsIntroduced
		}
		if a.Sum.Major != b.Sum.Major {
			return a.Sum.Major > b.Sum.Major
		}
		return false
	}
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && less(rows[j], rows[j-1]); j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return strings.TrimRight(string(r[:n-1]), " ") + "…"
}

// dot renders a zero as a dim dot so non-zero cells stand out.
func dot(s styler, n int, paint func(string) string) string {
	if n == 0 {
		return s.dim("·")
	}
	str := fmt.Sprintf("%d", n)
	if paint != nil {
		return paint(str)
	}
	return str
}

// QueueTerminal renders the queue overview table. noun is "PR" or "MR",
// matching the forge the queue came from.
func QueueTerminal(w io.Writer, heading, noun string, rows []QueueRow, color, vulnsChecked, metaChecked bool, freshDays int) {
	s := styler{on: color}
	fmt.Fprintf(w, "\n%s\n\n", s.bold(heading))
	if len(rows) == 0 {
		fmt.Fprintf(w, "  %s\n\n", s.dim("no open dependency "+noun+"s found"))
		return
	}

	labelW := len(noun)
	for _, r := range rows {
		labelW = max(labelW, len(r.Label))
	}

	head := fmt.Sprintf("    %s  %7s  %5s  %7s  %5s  %4s  %s",
		pad(noun, labelW), "CHANGES", "MAJOR", "VULNS", "FRESH", "DEPR", "TITLE")
	fmt.Fprintln(w, s.dim(head))

	for _, r := range rows {
		mark := s.green("✓")
		switch r.verdict() {
		case 0:
			mark = s.bred("✗")
		case 1:
			mark = s.yellow("!")
		case 3, 4:
			mark = s.dim("–")
		}
		label := pad(r.Label, labelW)
		if s.on && r.URL != "" {
			label = s.href(r.URL, r.Label) + strings.Repeat(" ", labelW-len(r.Label))
		}
		if r.Err != "" {
			fmt.Fprintf(w, "  %s %s  %s\n", mark, label, s.dim("error: "+truncate(r.Err, 80)))
			continue
		}
		if r.NoChanges {
			fmt.Fprintf(w, "  %s %s  %s\n", mark, label, s.dim(r.noChangesMsg()+" — "+truncate(r.Title, 60)))
			continue
		}
		vulns := s.dim("·")
		if r.Sum.VulnsIntroduced > 0 || r.Sum.VulnsFixed > 0 {
			in := fmt.Sprintf("+%d", r.Sum.VulnsIntroduced)
			if r.Sum.VulnsIntroduced > 0 {
				in = s.bred(in)
			} else {
				in = s.dim(in)
			}
			fx := fmt.Sprintf("−%d", r.Sum.VulnsFixed)
			if r.Sum.VulnsFixed > 0 {
				fx = s.green(fx)
			} else {
				fx = s.dim(fx)
			}
			vulns = in + "/" + fx
		}
		fmt.Fprintf(w, "  %s %s  %s  %s  %s  %s  %s  %s\n",
			mark, label,
			padANSI(s, dot(s, r.Sum.Total, nil), 7),
			padANSI(s, dot(s, r.Sum.Major, s.bred), 5),
			padANSI(s, vulns, 7),
			padANSI(s, dot(s, r.Sum.Fresh, s.yellow), 5),
			padANSI(s, dot(s, r.Sum.Deprecated, s.yellow), 4),
			truncate(r.Title, 60))
	}

	fmt.Fprintf(w, "\n%s\n", queueSummary(s, noun, rows, vulnsChecked, metaChecked, freshDays))
	hint := "full report for any of them:  lockvet pr <owner/repo#N>"
	if noun == "MR" {
		hint = "full report for any of them:  lockvet mr <group/project!N>"
	}
	fmt.Fprintf(w, "%s\n", s.dim(hint))
}

// padANSI right-pads to width w counting visible runes only (the cell may
// contain ANSI codes and multi-byte glyphs).
func padANSI(s styler, cell string, w int) string {
	vis := visibleWidth(cell)
	if vis >= w {
		return cell
	}
	return cell + strings.Repeat(" ", w-vis)
}

func visibleWidth(str string) int {
	n, inEsc := 0, false
	for _, r := range str {
		switch {
		case inEsc:
			if r == 'm' {
				inEsc = false
			}
		case r == '\x1b':
			inEsc = true
		default:
			n++
		}
	}
	return n
}

func queueSummary(s styler, noun string, rows []QueueRow, vulnsChecked, metaChecked bool, freshDays int) string {
	var vuln, look, routine, none, errs int
	for _, r := range rows {
		switch r.verdict() {
		case 0:
			vuln++
		case 1:
			look++
		case 2:
			routine++
		case 3:
			none++
		case 4:
			errs++
		}
	}
	parts := []string{fmt.Sprintf("%s", plural(len(rows), "open "+noun))}
	if vuln > 0 {
		parts = append(parts, s.bred(fmt.Sprintf("%d introduce vulnerabilities", vuln)))
	}
	if look > 0 {
		what := "%d need a look (major/downgrade"
		if metaChecked {
			what += fmt.Sprintf("/fresh <%dd/deprecated", freshDays)
		}
		parts = append(parts, s.yellow(fmt.Sprintf(what+")", look)))
	}
	if routine > 0 {
		routineStr := fmt.Sprintf("%d look routine", routine)
		if !vulnsChecked {
			routineStr += " (vulns unchecked)"
		}
		parts = append(parts, s.green(routineStr))
	}
	if none > 0 {
		parts = append(parts, s.dim(fmt.Sprintf("%d without lockfile changes", none)))
	}
	if errs > 0 {
		parts = append(parts, s.bred(fmt.Sprintf("%d failed", errs)))
	}
	return strings.Join(parts, " · ")
}

// QueueMarkdown renders the queue overview as a markdown table (for pasting
// into a triage issue or posting from CI).
func QueueMarkdown(w io.Writer, heading, noun string, rows []QueueRow, vulnsChecked, metaChecked bool, freshDays int) {
	fmt.Fprintf(w, "### 🔍 lockvet queue — %s\n\n", heading)
	if len(rows) == 0 {
		fmt.Fprintf(w, "_no open dependency %ss found_\n", noun)
		return
	}
	fmt.Fprintf(w, "|  | %s | title | changes | major | vulns +/− | fresh | deprecated |\n", noun)
	fmt.Fprintln(w, "|---|---|---|---:|---:|---:|---:|---:|")
	for _, r := range rows {
		mark := "✅"
		switch r.verdict() {
		case 0:
			mark = "❌"
		case 1:
			mark = "⚠️"
		case 3, 4:
			mark = "➖"
		}
		link := esc(r.Label)
		if r.URL != "" {
			link = fmt.Sprintf("[%s](%s)", esc(r.Label), r.URL)
		}
		if r.Err != "" {
			fmt.Fprintf(w, "| %s | %s | _error: %s_ | | | | | |\n", mark, link, esc(truncate(r.Err, 80)))
			continue
		}
		if r.NoChanges {
			fmt.Fprintf(w, "| %s | %s | _%s_ — %s | | | | | |\n", mark, link, r.noChangesMsg(), esc(truncate(r.Title, 60)))
			continue
		}
		vulns := ""
		if r.Sum.VulnsIntroduced > 0 || r.Sum.VulnsFixed > 0 {
			vulns = fmt.Sprintf("+%d/−%d", r.Sum.VulnsIntroduced, r.Sum.VulnsFixed)
		}
		mdCell := func(n int) string {
			if n == 0 {
				return ""
			}
			return fmt.Sprintf("%d", n)
		}
		fmt.Fprintf(w, "| %s | %s | %s | %d | %s | %s | %s | %s |\n",
			mark, link, esc(truncate(r.Title, 60)), r.Sum.Total,
			mdCell(r.Sum.Major), vulns, mdCell(r.Sum.Fresh), mdCell(r.Sum.Deprecated))
	}
	fmt.Fprintf(w, "\n%s\n", mdQueueFooter(noun, rows, vulnsChecked, metaChecked, freshDays))
}

func mdQueueFooter(noun string, rows []QueueRow, vulnsChecked, metaChecked bool, freshDays int) string {
	s := styler{on: false}
	return "**" + queueSummary(s, noun, rows, vulnsChecked, metaChecked, freshDays) + "**"
}
