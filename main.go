// lockvet — explain any lockfile change: what bumped, what's breaking,
// what's newly vulnerable. https://github.com/matteo-sung/lockvet
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/gitx"
	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/osv"
	"github.com/matteo-sung/lockvet/internal/render"
	"github.com/matteo-sung/lockvet/internal/vers"
)

var version = "dev" // set via -ldflags at release time

var usage = `lockvet — explain any lockfile change before you merge it.

USAGE
  lockvet [flags] [<base> [<target>]]

  lockvet                 working tree vs HEAD
  lockvet HEAD~5          working tree vs HEAD~5
  lockvet main my-branch  branch vs branch (or any two revisions)

FLAGS
  -md            markdown output (for PR comments)
  -json          JSON output
  -no-vulns      skip the OSV.dev vulnerability check (also: offline mode)
  -fail-on X     exit 1 if the diff contains X: "major", "vuln", or "downgrade"
                 (repeatable as comma list: -fail-on major,vuln)
  -C dir         run as if started in dir
  -no-color      disable colors (also respects NO_COLOR)
  -version       print version

SUPPORTED LOCKFILES
  ` + strings.Join(lock.KnownBasenames(), ", ") + `

Every ecosystem in one binary. Vulnerability data: https://osv.dev
`

func main() {
	var (
		md      = flag.Bool("md", false, "")
		jsonOut = flag.Bool("json", false, "")
		noVulns = flag.Bool("no-vulns", false, "")
		failOn  = flag.String("fail-on", "", "")
		dir     = flag.String("C", ".", "")
		noColor = flag.Bool("no-color", false, "")
		showVer = flag.Bool("version", false, "")
	)
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()

	if *showVer {
		fmt.Println("lockvet", version)
		return
	}

	base, target := "HEAD", ""
	switch args := flag.Args(); len(args) {
	case 0:
	case 1:
		base = args[0]
	case 2:
		base, target = args[0], args[1]
	default:
		fatal("too many arguments (want at most: <base> <target>)")
	}
	if i := strings.Index(base, ".."); i >= 0 && target == "" {
		base, target = base[:i], strings.TrimPrefix(base[i+2:], ".")
	}

	repo, err := gitx.Open(*dir)
	check(err)
	check(repo.ResolveRev(base))
	if target != "" {
		check(repo.ResolveRev(target))
	}

	changed, err := repo.ChangedFiles(base, target)
	check(err)

	var diffs []diffx.FileDiff
	for _, p := range changed {
		parser := lock.ByBasename(p)
		if parser == nil {
			continue
		}
		oldData, err := repo.Show(base, p)
		check(err)
		newData, err := repo.Show(target, p)
		check(err)
		oldF := parseOrNil(parser, p, oldData)
		newF := parseOrNil(parser, p, newData)
		if oldF == nil && newF == nil {
			continue
		}
		fd := diffx.Diff(oldF, newF)
		if len(fd.Changes) > 0 {
			diffs = append(diffs, fd)
		}
	}

	if len(diffs) == 0 {
		where := "between " + base + " and " + displayTarget(target)
		fmt.Fprintf(os.Stderr, "lockvet: no lockfile changes %s\n", where)
		fmt.Fprintf(os.Stderr, "hint: try a range, e.g.  lockvet HEAD~10  or  lockvet main my-branch\n")
		return
	}

	vulnsChecked := false
	if !*noVulns {
		if err := osv.Annotate(diffs); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: vulnerability check skipped: %v\n", err)
		} else {
			vulnsChecked = true
		}
	}

	sum := diffx.Summarize(diffs)

	switch {
	case *jsonOut:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		check(enc.Encode(map[string]any{
			"base": base, "target": displayTarget(target),
			"files": diffs, "summary": sum, "vulns_checked": vulnsChecked,
		}))
	case *md:
		render.Markdown(os.Stdout, diffs, sum, vulnsChecked)
	default:
		color := !*noColor && os.Getenv("NO_COLOR") == "" && isTTY()
		render.Terminal(os.Stdout, diffs, sum, color, vulnsChecked)
	}

	if code := failCode(*failOn, diffs, sum); code != 0 {
		os.Exit(code)
	}
}

func failCode(failOn string, diffs []diffx.FileDiff, sum diffx.Summary) int {
	for _, cond := range strings.Split(failOn, ",") {
		switch strings.TrimSpace(cond) {
		case "":
		case "major":
			if sum.Major > 0 {
				return 1
			}
		case "vuln", "vulns":
			if sum.VulnsIntroduced > 0 {
				return 1
			}
		case "downgrade", "downgrades":
			if sum.Downgraded > 0 {
				return 1
			}
		default:
			fatal(fmt.Sprintf("unknown -fail-on condition %q (want major, vuln, or downgrade)", cond))
		}
	}
	return 0
}

func parseOrNil(parser *lock.Parser, p string, data []byte) *lock.File {
	if data == nil {
		return nil
	}
	f, err := parser.Parse(p, data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lockvet: warning: could not parse %s: %v\n", path.Base(p), err)
		return nil
	}
	return f
}

func displayTarget(target string) string {
	if target == "" {
		return "working tree"
	}
	return target
}

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func check(err error) {
	if err != nil {
		fatal(err.Error())
	}
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "lockvet:", msg)
	os.Exit(2)
}

var _ = vers.Major // keep import for future flags
