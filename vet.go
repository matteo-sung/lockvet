package main

// vet.go — a reusable, error-returning version of the analysis pipeline,
// used by the MCP server (mcp.go). The CLI entry points in main.go keep
// their own inline pipeline (they print warnings as they go and exit on
// error); this one collects warnings and returns them.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/matteo-sung/lockvet/internal/actreg"
	"github.com/matteo-sung/lockvet/internal/adopr"
	"github.com/matteo-sung/lockvet/internal/bbpr"
	"github.com/matteo-sung/lockvet/internal/cargoreg"
	"github.com/matteo-sung/lockvet/internal/conanreg"
	"github.com/matteo-sung/lockvet/internal/condareg"
	"github.com/matteo-sung/lockvet/internal/cranreg"
	"github.com/matteo-sung/lockvet/internal/depsdev"
	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/gemreg"
	"github.com/matteo-sung/lockvet/internal/ghpr"
	"github.com/matteo-sung/lockvet/internal/gitx"
	"github.com/matteo-sung/lockvet/internal/glmr"
	"github.com/matteo-sung/lockvet/internal/goreg"
	"github.com/matteo-sung/lockvet/internal/gtpr"
	"github.com/matteo-sung/lockvet/internal/hexreg"
	"github.com/matteo-sung/lockvet/internal/hkgreg"
	"github.com/matteo-sung/lockvet/internal/ignore"
	"github.com/matteo-sung/lockvet/internal/jsrreg"
	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/mvnreg"
	"github.com/matteo-sung/lockvet/internal/npmreg"
	"github.com/matteo-sung/lockvet/internal/nugetreg"
	"github.com/matteo-sung/lockvet/internal/osv"
	"github.com/matteo-sung/lockvet/internal/phpreg"
	"github.com/matteo-sung/lockvet/internal/podreg"
	"github.com/matteo-sung/lockvet/internal/pubreg"
	"github.com/matteo-sung/lockvet/internal/pypireg"
	"github.com/matteo-sung/lockvet/internal/relnotes"
	"github.com/matteo-sung/lockvet/internal/render"
	"github.com/matteo-sung/lockvet/internal/squat"
	"github.com/matteo-sung/lockvet/internal/swiftreg"
	"github.com/matteo-sung/lockvet/internal/taglink"
	"github.com/matteo-sung/lockvet/internal/tfreg"
)

type vetOptions struct {
	only       string
	freshDays  int
	noVulns    bool
	noMeta     bool
	changelogs bool
	noLinks    bool // skip taglink/relnotes (audit mode: links aren't findings)

	// .lockvetignore handling: an explicit -ignore-file path, -no-ignore,
	// and the directory searched for the default file.
	ignoreFile string
	noIgnore   bool
	ignoreDir  string
}

// vetOutcome is the result of one analysis. When message is non-empty there
// was nothing to report (no lockfile changes / nothing matching -only) and
// diffs is empty.
type vetOutcome struct {
	diffs        []diffx.FileDiff
	sum          diffx.Summary
	base, target string
	vulnsChecked bool
	metaChecked  bool
	freshDays    int
	message      string
	warnings     []string

	// Audit mode (`lockvet audit`): every package arrived as an Added
	// change; render findings, not the inventory. contents keeps each
	// lockfile's raw bytes so SARIF can anchor alerts to exact lines.
	audit    bool
	contents map[string][]byte

	// Pkg mode (`lockvet pkg`): synthetic one-package diffs, one per
	// requested spec — there is no base or target revision.
	pkg bool
}

// markdown renders the outcome the same way `lockvet -md` does.
func (v *vetOutcome) markdown() string {
	if v.message != "" {
		return v.message
	}
	var buf bytes.Buffer
	if v.audit {
		render.AuditMarkdown(&buf, v.diffs, v.sum, v.vulnsChecked, v.metaChecked, v.freshDays)
	} else {
		render.Markdown(&buf, v.diffs, v.sum, v.vulnsChecked, v.metaChecked, v.freshDays)
	}
	return buf.String()
}

// jsonText renders the outcome the same way `lockvet -json` does.
func (v *vetOutcome) jsonText() (string, error) {
	if v.message != "" {
		out, err := json.MarshalIndent(map[string]any{"message": v.message}, "", "  ")
		return string(out), err
	}
	doc := map[string]any{
		"base": v.base, "target": v.target,
		"files": v.diffs, "summary": v.sum,
		"vulns_checked": v.vulnsChecked,
		"meta_checked":  v.metaChecked, "fresh_days": v.freshDays,
	}
	if v.audit {
		// In an audit every package is reported as an Added change against
		// nothing: "introduced_vulns" = advisories affecting the pinned
		// version, "added" = packages pinned.
		doc["mode"] = "audit"
		delete(doc, "base")
		delete(doc, "target")
	}
	if v.pkg {
		// `lockvet pkg`: each file entry is one requested package spec;
		// "introduced_vulns" = advisories affecting the looked-up version.
		doc["mode"] = "pkg"
		delete(doc, "base")
		delete(doc, "target")
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	return string(out), err
}

func (v *vetOutcome) render(format string) (string, error) {
	if format == "json" {
		return v.jsonText()
	}
	return v.markdown(), nil
}

// finishVet applies -only, annotates (OSV, deps.dev, taglink), and
// summarizes. noChangesMsg describes the source for the "nothing changed"
// message.
func finishVet(diffs []diffx.FileDiff, o vetOptions, base, target, noChangesIn string) (*vetOutcome, error) {
	v := &vetOutcome{base: base, target: target, freshDays: o.freshDays}
	if len(diffs) == 0 {
		v.message = "no lockfile changes in " + noChangesIn
		return v, nil
	}
	if o.only != "" {
		total := 0
		for _, fd := range diffs {
			total += len(fd.Changes)
		}
		diffs = diffx.Filter(diffs, o.only)
		if len(diffs) == 0 {
			v.message = fmt.Sprintf("no changes matching only=%q in %s (%s changed in total)",
				o.only, noChangesIn, plural(total, "package"))
			return v, nil
		}
	}

	anyOSV, anyMeta := false, false
	for _, fd := range diffs {
		for _, c := range fd.Changes {
			if lock.Ecosystem(c.Ecosystem).HasOSV() {
				anyOSV = true
			}
			if depsdev.Covers(c.Ecosystem) {
				anyMeta = true
			}
		}
	}
	if !o.noMeta {
		// Resolve workflow pins (SHA → release tag, floating major →
		// concrete release) BEFORE the vulnerability check: OSV ranges
		// for GitHub Actions are evaluated client-side against the
		// resolved releases.
		if ok, err := actreg.Annotate(diffs); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("action tag check skipped: %v", err))
		} else if ok {
			v.metaChecked = true
		}
		// Verify SwiftPM pins against the upstream repositories' tags:
		// the version's tag must exist, and the pinned commit must be
		// what the tag points at.
		if ok, err := swiftreg.Annotate(diffs); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("swift tag check skipped: %v", err))
		} else if ok {
			v.metaChecked = true
		}
	}
	if !o.noVulns && anyOSV {
		if err := osv.Annotate(diffs); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("vulnerability check skipped: %v", err))
		} else {
			v.vulnsChecked = true
		}
	}
	if !o.noMeta && anyMeta {
		if err := depsdev.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("release-metadata check skipped: %v", err))
		} else {
			v.metaChecked = true
		}
	}
	if !o.noMeta {
		// deps.dev has no Composer system: for PHP, Packagist itself is
		// the metadata layer (ages, abandoned, licenses, unlisted).
		if ok, err := phpreg.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("Packagist registry check skipped: %v", err))
		} else if ok {
			v.metaChecked = true
		}
		if ok, err := hexreg.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("hex.pm registry check skipped: %v", err))
		} else if ok {
			v.metaChecked = true
		}
		if ok, err := pubreg.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("pub.dev registry check skipped: %v", err))
		} else if ok {
			v.metaChecked = true
		}
		if ok, err := jsrreg.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("jsr.io registry check skipped: %v", err))
		} else if ok {
			v.metaChecked = true
		}
		if ok, err := podreg.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("CocoaPods registry check skipped: %v", err))
		} else if ok {
			v.metaChecked = true
		}
		if ok, err := tfreg.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("Terraform registry check skipped: %v", err))
		} else if ok {
			v.metaChecked = true
		}
		if ok, err := conanreg.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("ConanCenter registry check skipped: %v", err))
		} else if ok {
			v.metaChecked = true
		}
		if ok, err := cranreg.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("CRAN registry check skipped: %v", err))
		} else if ok {
			v.metaChecked = true
		}
		if ok, err := hkgreg.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("Hackage registry check skipped: %v", err))
		} else if ok {
			v.metaChecked = true
		}
		if ok, err := condareg.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("anaconda.org registry check skipped: %v", err))
		} else if ok {
			v.metaChecked = true
		}
		if v.metaChecked && !o.noLinks {
			taglink.Annotate(diffs)
			if o.changelogs {
				v.warnings = append(v.warnings, relnotes.Annotate(diffs, ghpr.Token())...)
			}
		}
		if err := npmreg.Annotate(diffs); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("install-script check skipped: %v", err))
		}
		if err := pypireg.Annotate(diffs); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("PyPI registry check skipped: %v", err))
		}
		if err := cargoreg.Annotate(diffs); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("crates.io registry check skipped: %v", err))
		}
		if err := gemreg.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("RubyGems registry check skipped: %v", err))
		}
		if err := nugetreg.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("NuGet registry check skipped: %v", err))
		}
		if err := goreg.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("Go module proxy check skipped: %v", err))
		}
		if err := mvnreg.Annotate(diffs, o.freshDays); err != nil {
			v.warnings = append(v.warnings, fmt.Sprintf("Maven repository check skipped: %v", err))
		}
	}
	// The typosquat check is fully local (embedded popularity lists) — it
	// runs even with -no-meta/-offline; with ages unknown the young-release
	// gate honestly passes everything through. Last so it can use ages when
	// the metadata layers did run.
	squat.Annotate(diffs)
	ign, err := ignore.Resolve(o.ignoreFile, o.noIgnore, o.ignoreDir)
	if err != nil {
		return nil, err
	}
	_, ignWarns := ign.Apply(diffs, time.Now())
	v.warnings = append(v.warnings, ignWarns...)

	v.diffs = diffs
	v.sum = diffx.Summarize(diffs)
	return v, nil
}

// remoteSource is a resolved PR/MR/compare/commit reference on any forge.
type remoteSource struct {
	fetch func(func(string) bool) (*ghpr.Result, error)
	what  string
}

// resolveAnyRemote recognises everything `lockvet pr|mr|compare <arg>`
// accepts as a single argument: PR/MR references and URLs first, then
// compare and commit URLs, across GitHub, GitLab, Bitbucket, Gitea/Forgejo,
// and Azure DevOps.
func resolveAnyRemote(arg string) (*remoteSource, error) {
	// Pull/merge request shapes (owner/repo#N, group/project!N, PR URLs).
	if ref, ok := bbpr.Parse(arg); ok {
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return bbpr.Fetch(ref, f) }, ref.String()}, nil
	}
	if ref, ok := adopr.Parse(arg); ok {
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return adopr.Fetch(ref, f) }, ref.String()}, nil
	}
	if ref, ok := ghpr.Parse(arg); ok {
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return ghpr.Fetch(ref, f) }, ref.String()}, nil
	}
	if ref, ok := glmr.ParseMR(arg); ok {
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return glmr.Fetch(ref, f) }, ref.String()}, nil
	}
	if ref, ok := gtpr.Parse(arg); ok {
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return gtpr.Fetch(ref, f) }, ref.String()}, nil
	}

	// Compare and commit URLs.
	if ref, ok := ghpr.ParseCompare(arg); ok {
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return ghpr.FetchCompare(ref, f) }, ref.String()}, nil
	}
	if o, r, sha, ok := ghpr.ParseCommit(arg); ok {
		ref, err := ghpr.ResolveCommit(o, r, sha)
		if err != nil {
			return nil, err
		}
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return ghpr.FetchCompare(ref, f) }, ref.String()}, nil
	}
	if ref, ok := glmr.ParseCompare(arg); ok {
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return glmr.FetchCompare(ref, f) }, ref.String()}, nil
	}
	if h, p, sha, ok := glmr.ParseCommit(arg); ok {
		ref, err := glmr.ResolveCommit(h, p, sha)
		if err != nil {
			return nil, err
		}
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return glmr.FetchCompare(ref, f) }, ref.String()}, nil
	}
	if ref, ok := bbpr.ParseCompare(arg); ok {
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return bbpr.FetchCompare(ref, f) }, ref.String()}, nil
	}
	if w, r, sha, ok := bbpr.ParseCommit(arg); ok {
		ref, err := bbpr.ResolveCommit(w, r, sha)
		if err != nil {
			return nil, err
		}
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return bbpr.FetchCompare(ref, f) }, ref.String()}, nil
	}
	if ref, ok := adopr.ParseCompare(arg); ok {
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return adopr.FetchCompare(ref, f) }, ref.String()}, nil
	}
	if inst, proj, repo, sha, ok := adopr.ParseCommit(arg); ok {
		ref, err := adopr.ResolveCommit(inst, proj, repo, sha)
		if err != nil {
			return nil, err
		}
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return adopr.FetchCompare(ref, f) }, ref.String()}, nil
	}
	if ref, ok := gtpr.ParseCommit(arg); ok {
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return gtpr.FetchCommit(ref, f) }, ref.String()}, nil
	}
	if ref, ok := gtpr.ParseCompare(arg); ok {
		return &remoteSource{func(f func(string) bool) (*ghpr.Result, error) { return gtpr.FetchCompare(ref, f) }, ref.String()}, nil
	}
	return nil, fmt.Errorf("cannot parse %q — want a pull/merge request, compare, or commit URL on GitHub, GitLab, Bitbucket, Gitea/Forgejo, or Azure DevOps, or a shorthand like owner/repo#123 or group/project!123", arg)
}

// vetRemote vets a PR/MR/compare/commit given as a single URL or shorthand.
func vetRemote(arg string, o vetOptions) (*vetOutcome, error) {
	src, err := resolveAnyRemote(arg)
	if err != nil {
		return nil, err
	}
	res, err := src.fetch(func(p string) bool { return lock.ByBasename(p) != nil })
	if err != nil {
		return nil, err
	}
	var diffs []diffx.FileDiff
	var warnings []string
	warnings = append(warnings, res.Warnings...)
	for _, cf := range res.Files {
		parser := lock.ByBasename(cf.Path)
		oldF, w1 := parseOrWarn(parser, cf.Path, cf.Old)
		newF, w2 := parseOrWarn(parser, cf.Path, cf.New)
		warnings = append(warnings, w1...)
		warnings = append(warnings, w2...)
		if oldF == nil && newF == nil {
			continue
		}
		if fd := diffx.Diff(oldF, newF); len(fd.Changes) > 0 {
			diffs = append(diffs, fd)
		}
	}
	what := src.what
	if res.Title != "" {
		what = fmt.Sprintf("%s (%q)", src.what, res.Title)
	}
	v, err := finishVet(diffs, o, res.BaseLabel, res.HeadLabel, what)
	if v != nil {
		v.warnings = append(warnings, v.warnings...)
	}
	return v, err
}

// vetGit vets lockfile changes in a local git repository, like plain
// `lockvet [base [target]]`.
func vetGit(dir, base, target string, o vetOptions) (*vetOutcome, error) {
	if base == "" {
		base = "HEAD"
	}
	if i := strings.Index(base, ".."); i >= 0 && target == "" {
		base, target = base[:i], strings.TrimPrefix(base[i+2:], ".")
	}
	if o.ignoreDir == "" {
		o.ignoreDir = dir
	}
	repo, err := gitx.Open(dir)
	if err != nil {
		return nil, err
	}
	if err := repo.ResolveRev(base); err != nil {
		return nil, err
	}
	if target != "" {
		if err := repo.ResolveRev(target); err != nil {
			return nil, err
		}
	}
	changed, err := repo.ChangedFiles(base, target)
	if err != nil {
		return nil, err
	}
	var diffs []diffx.FileDiff
	var warnings []string
	for _, p := range changed {
		parser := lock.ByBasename(p)
		if parser == nil {
			continue
		}
		oldData, err := repo.Show(base, p)
		if err != nil {
			return nil, err
		}
		newData, err := repo.Show(target, p)
		if err != nil {
			return nil, err
		}
		oldF, w1 := parseOrWarn(parser, p, oldData)
		newF, w2 := parseOrWarn(parser, p, newData)
		warnings = append(warnings, w1...)
		warnings = append(warnings, w2...)
		if oldF == nil && newF == nil {
			continue
		}
		if fd := diffx.Diff(oldF, newF); len(fd.Changes) > 0 {
			diffs = append(diffs, fd)
		}
	}
	where := fmt.Sprintf("%s between %s and %s", dir, base, displayTarget(target))
	v, err := finishVet(diffs, o, base, displayTarget(target), where)
	if v != nil {
		v.warnings = append(warnings, v.warnings...)
	}
	return v, err
}

// vetFiles vets two lockfiles or SBOMs on disk, like `lockvet diff`.
func vetFiles(oldPath, newPath string, o vetOptions) (*vetOutcome, error) {
	if o.ignoreDir == "" {
		o.ignoreDir = filepath.Dir(newPath)
	}
	pOld, pNew := lock.ByBasename(oldPath), lock.ByBasename(newPath)
	if pOld == nil {
		pOld = pNew
	}
	if pNew == nil {
		pNew = pOld
	}
	parseFile := func(p string, parser *lock.Parser) (*lock.File, error) {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		if parser == nil {
			parser = lock.FallbackParser(p)
		}
		f, err := parser.Parse(p, data)
		if err != nil {
			return nil, fmt.Errorf("%s: %v (want two lockfiles with their usual names — one side may carry a suffix, e.g. Cargo.lock.orig vs Cargo.lock — or CycloneDX/SPDX JSON SBOMs under any filename)", p, err)
		}
		return f, nil
	}
	oldF, err := parseFile(oldPath, pOld)
	if err != nil {
		return nil, err
	}
	newF, err := parseFile(newPath, pNew)
	if err != nil {
		return nil, err
	}
	var diffs []diffx.FileDiff
	if fd := diffx.Diff(oldF, newF); len(fd.Changes) > 0 {
		diffs = append(diffs, fd)
	}
	return finishVet(diffs, o, oldPath, newPath, fmt.Sprintf("%s vs %s", oldPath, newPath))
}

// parseOrWarn is parseOrNil without the stderr side effect.
func parseOrWarn(parser *lock.Parser, p string, data []byte) (*lock.File, []string) {
	if data == nil {
		return nil, nil
	}
	f, err := parser.Parse(p, data)
	if err != nil {
		return nil, []string{fmt.Sprintf("could not parse %s: %v", p, err)}
	}
	return f, nil
}
