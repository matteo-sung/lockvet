package main

// pkg.go — `lockvet pkg <ecosystem>:<name>[@version] ...`: vet a package
// BEFORE it is in any lockfile — the moment you are deciding whether to
// `npm install` / `pip install` / `cargo add` it. Each spec becomes a
// synthetic one-package "diff against nothing", so the entire pipeline
// runs unmodified: advisories (OSV.dev), release age, deprecation /
// retraction / yank, the unlisted-version flag, typosquat suspects,
// install-script and provenance data where the registry exposes them.
// With no version given, the package's registry says what "latest" is.

import (
	"fmt"
	"os"
	"strings"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/latest"
	"github.com/matteo-sung/lockvet/internal/pkgspec"
	"github.com/matteo-sung/lockvet/internal/render"
)

// vetPkg resolves each spec (asking the registry for the latest version
// where none was given) and runs the standard pipeline over synthetic
// one-package diffs. Shared by the CLI and the MCP `vet_package` tool.
func vetPkg(args []string, o vetOptions) (*vetOutcome, error) {
	var diffs []diffx.FileDiff
	for _, arg := range args {
		spec, err := pkgspec.Parse(arg)
		if err != nil {
			return nil, err
		}
		if spec.Version == "" {
			if o.noMeta {
				return nil, fmt.Errorf("%s: -offline/-no-meta can't ask the registry what \"latest\" is — say which version to vet", spec.Label)
			}
			v, err := latest.Resolve(spec.Eco, spec.LookupName())
			if err != nil {
				return nil, err
			}
			spec.Version = v
			spec.Label += "@" + v + " (latest)"
		}
		fd := diffx.Diff(nil, spec.File())
		diffs = append(diffs, fd)
	}
	// Ignore rules are for accepted findings in a repo; a pkg lookup is a
	// fresh question. Keep discovery off unless the user pointed at a file.
	if o.ignoreFile == "" {
		o.noIgnore = true
	}
	v, err := finishVet(diffs, o, "", "", strings.Join(args, ", "))
	if err != nil {
		return nil, err
	}
	v.pkg = true
	return v, nil
}

// runPkg is the CLI entry point for `lockvet pkg`.
func runPkg(args []string, o vetOptions, md, jsonOut, noColor bool, failOn string) {
	v, err := vetPkg(args, o)
	check(err)
	for _, w := range v.warnings {
		fmt.Fprintf(os.Stderr, "lockvet: warning: %s\n", w)
	}
	if v.message != "" {
		fmt.Fprintf(os.Stderr, "lockvet: %s\n", v.message)
		return
	}
	switch {
	case jsonOut:
		txt, err := v.jsonText()
		check(err)
		fmt.Println(txt)
	case md:
		render.Markdown(os.Stdout, v.diffs, v.sum, v.vulnsChecked, v.metaChecked, v.freshDays)
	default:
		color := !noColor && os.Getenv("NO_COLOR") == "" && isTTY()
		render.Terminal(os.Stdout, v.diffs, v.sum, color, v.vulnsChecked, v.metaChecked, v.freshDays)
	}
	if code := failCode(failOn, v.diffs, v.sum); code != 0 {
		os.Exit(code)
	}
}
