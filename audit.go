package main

// audit.go — `lockvet audit [path ...]`: vet what the lockfiles pin TODAY,
// not a change. The same pipeline that explains a diff runs over the full
// dependency set, so an audit reports every pinned version that is affected
// by a known advisory (OSV.dev), missing from its registry's index (what an
// unpublished or pulled — often malicious — release looks like), deprecated /
// retracted / yanked / abandoned upstream, or published only days ago.
//
// Implementation: every lockfile is diffed against nothing, so each package
// arrives as an Added change and every annotation layer (OSV, deps.dev, the
// per-registry checks) works unmodified. Only the presentation differs: the
// audit renderers show findings, not the package inventory.

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/render"
)

// runAudit is the CLI entry point for `lockvet audit [path ...]`.
func runAudit(paths []string, dir string, o vetOptions, md, jsonOut, sarifOut, noColor bool, failOn string) {
	v, err := vetAudit(paths, dir, o)
	check(err)
	for _, w := range v.warnings {
		fmt.Fprintf(os.Stderr, "lockvet: warning: %s\n", w)
	}
	if v.message != "" {
		fmt.Fprintf(os.Stderr, "lockvet: %s\n", v.message)
		return
	}
	switch {
	case sarifOut:
		check(render.SARIFAudit(os.Stdout, v.diffs, effectiveVersion(),
			func(p string) []byte { return v.contents[p] }))
	case jsonOut:
		txt, err := v.jsonText()
		check(err)
		fmt.Println(txt)
	case md:
		render.AuditMarkdown(os.Stdout, v.diffs, v.sum, v.vulnsChecked, v.metaChecked, v.freshDays)
	default:
		color := !noColor && os.Getenv("NO_COLOR") == "" && isTTY()
		render.AuditTerminal(os.Stdout, v.diffs, v.sum, color, v.vulnsChecked, v.metaChecked, v.freshDays)
	}
	if code := failCode(failOn, v.diffs, v.sum); code != 0 {
		os.Exit(code)
	}
}

// auditSkipDirs are directory names never worth descending into: they hold
// third-party or generated trees whose lockfiles the user doesn't own.
var auditSkipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "bower_components": true,
	".terraform": true, ".venv": true, "venv": true, ".tox": true,
	"__pycache__": true, ".bundle": true,
}

// discoverLockfiles walks roots (files or directories) and returns every
// recognizable lockfile path, sorted. Explicit file arguments are returned
// as-is (their format is settled at parse time, so SBOMs under any name
// work); directory walks only pick up known basenames.
func discoverLockfiles(roots []string) ([]string, error) {
	var files []string
	seen := map[string]bool{}
	add := func(p string) {
		p = filepath.Clean(p)
		if !seen[p] {
			seen[p] = true
			files = append(files, p)
		}
	}
	for _, root := range roots {
		st, err := os.Stat(root)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			add(root)
			continue
		}
		err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if p != root && auditSkipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if lock.ByBasename(p) != nil {
				add(p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(files)
	return files, nil
}

// vetAudit audits the lockfiles under paths (or dir when paths is empty).
// Shared by the CLI (`lockvet audit`) and the MCP `audit` tool.
func vetAudit(paths []string, dir string, o vetOptions) (*vetOutcome, error) {
	roots := paths
	if len(roots) == 0 {
		roots = []string{dir}
	}
	files, err := discoverLockfiles(roots)
	if err != nil {
		return nil, err
	}
	label := strings.Join(roots, ", ")
	if len(files) == 0 {
		return &vetOutcome{audit: true, freshDays: o.freshDays,
			message: "no lockfiles found under " + label}, nil
	}

	var (
		diffs    []diffx.FileDiff
		contents = map[string][]byte{}
		warnings []string
		explicit = map[string]bool{}
	)
	for _, root := range roots {
		if st, err := os.Stat(root); err == nil && !st.IsDir() {
			explicit[filepath.Clean(root)] = true
		}
	}
	for _, p := range files {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		parser := lock.ByBasename(p)
		if parser == nil {
			parser = lock.SBOMParser() // explicit file argument under a free-form name
		}
		f, perr := parser.Parse(p, data)
		if perr != nil {
			if explicit[p] {
				return nil, fmt.Errorf("%s: %v", p, perr)
			}
			warnings = append(warnings, fmt.Sprintf("%s: %v (skipped)", p, perr))
			continue
		}
		fd := diffx.Diff(nil, f)
		if len(fd.Changes) == 0 {
			continue
		}
		sort.Slice(fd.Changes, func(i, j int) bool { return fd.Changes[i].Name < fd.Changes[j].Name })
		diffs = append(diffs, fd)
		contents[p] = data
	}

	if len(diffs) == 0 {
		v := &vetOutcome{audit: true, freshDays: o.freshDays,
			message: fmt.Sprintf("no packages pinned in %s under %s", plural(len(files), "lockfile"), label)}
		v.warnings = warnings
		return v, nil
	}

	// Apply -only here (not in finishVet) so the empty-result message talks
	// about pinned packages, not changes.
	if o.only != "" {
		total := 0
		for _, fd := range diffs {
			total += len(fd.Changes)
		}
		diffs = diffx.Filter(diffs, o.only)
		if len(diffs) == 0 {
			v := &vetOutcome{audit: true, freshDays: o.freshDays,
				message: fmt.Sprintf("no packages matching only=%q under %s (%s pinned in total)",
					o.only, label, plural(total, "package"))}
			v.warnings = warnings
			return v, nil
		}
	}

	inner := o
	inner.only = ""
	inner.changelogs = false
	inner.noLinks = true // one link probe per source repo × every pinned package = too many
	v, err := finishVet(diffs, inner, "audit", "", label)
	if err != nil {
		return nil, err
	}
	v.audit = true
	v.contents = contents
	v.warnings = append(warnings, v.warnings...)
	return v, nil
}
