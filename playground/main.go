//go:build js && wasm

// Command playground is the browser build of lockvet. It compiles to
// WebAssembly and powers https://matteo-sung.github.io/lockvet/ — paste a
// pull-request / compare / commit URL from any supported forge, or drop two
// lockfiles, and get the full lockvet report without installing anything.
//
// It exposes two globals to JavaScript:
//
//	lockvetRun(opts) -> Promise<result>
//	lockvetVersion   -> string
//
// opts (a plain object):
//
//	mode:      "url" | "files" | "audit" | "pkg"
//	url:       PR / MR / compare / commit URL (mode "url")
//	token:     optional API token for the matched forge (mode "url")
//	oldName, oldData, newName, newData:  file names + Uint8Array (mode "files")
//	auditFiles: [{name, data: Uint8Array}, …] (mode "audit" — the pinned
//	           set is vetted as-is, like `lockvet audit`)
//	pkgs:      package specs, whitespace- or comma-separated (mode "pkg" —
//	           each eco:name[@version] is vetted like `lockvet pkg`)
//	only:      -only filter pattern ("" = all)
//	freshDays: like -fresh-days (default 7)
//	noVulns, noMeta: like the CLI flags
//	changelogs: like -changelogs (upstream release notes; GitHub-hosted
//	           upstreams; a GitHub token raises the API rate limit)
//
// result (a plain object):
//
//	terminal, markdown, json: the three report renderings (terminal = ANSI)
//	base, target, title:      labels
//	noChanges:  true when nothing relevant changed (message says why)
//	message:    human text when noChanges
//	warnings:   []string (non-fatal, e.g. OSV skipped)
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall/js"

	"github.com/matteo-sung/lockvet/internal/adopr"
	"github.com/matteo-sung/lockvet/internal/bbpr"
	"github.com/matteo-sung/lockvet/internal/bzlreg"
	"github.com/matteo-sung/lockvet/internal/cargoreg"
	"github.com/matteo-sung/lockvet/internal/conanreg"
	"github.com/matteo-sung/lockvet/internal/condareg"
	"github.com/matteo-sung/lockvet/internal/cranreg"
	"github.com/matteo-sung/lockvet/internal/depsdev"
	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/flakereg"
	"github.com/matteo-sung/lockvet/internal/ghpr"
	"github.com/matteo-sung/lockvet/internal/glmr"
	"github.com/matteo-sung/lockvet/internal/goreg"
	"github.com/matteo-sung/lockvet/internal/gtpr"
	"github.com/matteo-sung/lockvet/internal/hexreg"
	"github.com/matteo-sung/lockvet/internal/hkgreg"
	"github.com/matteo-sung/lockvet/internal/jsrreg"
	"github.com/matteo-sung/lockvet/internal/latest"
	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/npmreg"
	"github.com/matteo-sung/lockvet/internal/nugetreg"
	"github.com/matteo-sung/lockvet/internal/osv"
	"github.com/matteo-sung/lockvet/internal/phpreg"
	"github.com/matteo-sung/lockvet/internal/pkgspec"
	"github.com/matteo-sung/lockvet/internal/podreg"
	"github.com/matteo-sung/lockvet/internal/pubreg"
	"github.com/matteo-sung/lockvet/internal/pypireg"
	"github.com/matteo-sung/lockvet/internal/relnotes"
	"github.com/matteo-sung/lockvet/internal/render"
	"github.com/matteo-sung/lockvet/internal/squat"
	"github.com/matteo-sung/lockvet/internal/tfreg"
)

var version = "dev" // set via -ldflags at build time

func main() {
	// versionbatch does not answer CORS preflights; per-version GETs do.
	depsdev.SingleRequests = true
	cargoreg.UseAPI = true
	// repo.packagist.org (p2) sends no CORS headers; packagist.org does.
	phpreg.UseAPI = true
	// The CocoaPods CDN index is CORS-open, but its /Specs/ podspec
	// paths 301-redirect to jsDelivr without CORS headers — read those
	// from the mirror directly. trunk (publish dates) has no CORS at all.
	podreg.SpecsURL = "https://cdn.jsdelivr.net/cocoa"
	podreg.UseTrunk = false
	// center.conan.io sends no CORS headers: the browser cannot query
	// ConanCenter at all, so conan.lock diffs carry no registry claims.
	conanreg.Enabled = false
	cranreg.Enabled = false  // no CORS on crandb / cran.r-project.org
	condareg.Enabled = false // no CORS on api.anaconda.org
	hkgreg.Enabled = false   // no CORS on hackage.haskell.org
	bzlreg.Enabled = false   // no CORS on bcr.bazel.build
	// registry.terraform.io sends no CORS headers; the OpenTofu mirror
	// (api.opentofu.org) is CORS-open and provides ages + source links.
	tfreg.UseTerraformRegistry = false
	js.Global().Set("lockvetRun", js.FuncOf(runPromise))
	js.Global().Set("lockvetVersion", version)
	select {}
}

// runPromise wraps run in a JS Promise so the (single-threaded) JS side
// never blocks: all network and parsing work happens in a goroutine.
func runPromise(_ js.Value, args []js.Value) any {
	if len(args) != 1 {
		return rejected("lockvetRun wants exactly one options object")
	}
	opts := args[0]
	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve, reject := promiseArgs[0], promiseArgs[1]
		go func() {
			defer func() {
				if r := recover(); r != nil {
					reject.Invoke(fmt.Sprintf("lockvet crashed: %v", r))
				}
			}()
			res, err := run(opts)
			if err != nil {
				reject.Invoke(err.Error())
				return
			}
			resolve.Invoke(res)
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

func rejected(msg string) js.Value {
	return js.Global().Get("Promise").Call("reject", msg)
}

type request struct {
	mode             string
	url              string
	token            string
	oldName, newName string
	oldData, newData []byte
	auditFiles       []namedFile
	pkgs             string
	only             string
	freshDays        int
	noVulns, noMeta  bool
	changelogs       bool
}

type namedFile struct {
	name string
	data []byte
}

func decode(opts js.Value) request {
	str := func(k string) string {
		v := opts.Get(k)
		if v.Type() != js.TypeString {
			return ""
		}
		return v.String()
	}
	boolean := func(k string) bool {
		v := opts.Get(k)
		return v.Type() == js.TypeBoolean && v.Bool()
	}
	data := func(k string) []byte {
		v := opts.Get(k)
		if v.Type() != js.TypeObject {
			return nil
		}
		b := make([]byte, v.Get("length").Int())
		js.CopyBytesToGo(b, v)
		return b
	}
	req := request{
		mode:       str("mode"),
		url:        strings.TrimSpace(str("url")),
		token:      strings.TrimSpace(str("token")),
		oldName:    str("oldName"),
		newName:    str("newName"),
		oldData:    data("oldData"),
		newData:    data("newData"),
		pkgs:       strings.TrimSpace(str("pkgs")),
		only:       strings.TrimSpace(str("only")),
		freshDays:  7,
		noVulns:    boolean("noVulns"),
		noMeta:     boolean("noMeta"),
		changelogs: boolean("changelogs"),
	}
	if v := opts.Get("freshDays"); v.Type() == js.TypeNumber {
		req.freshDays = v.Int()
	}
	if v := opts.Get("auditFiles"); v.Type() == js.TypeObject {
		for i := 0; i < v.Get("length").Int(); i++ {
			e := v.Index(i)
			d := e.Get("data")
			b := make([]byte, d.Get("length").Int())
			js.CopyBytesToGo(b, d)
			req.auditFiles = append(req.auditFiles, namedFile{name: e.Get("name").String(), data: b})
		}
	}
	return req
}

func run(opts js.Value) (js.Value, error) {
	req := decode(opts)

	var (
		diffs        []diffx.FileDiff
		base, target string
		title        string
		warnings     []string
		audit        bool
		pkg          bool
	)

	switch req.mode {
	case "url":
		fetch, tokenEnv, what, err := resolveRemote(req.url)
		if err != nil {
			return js.Undefined(), err
		}
		// The forge clients read their tokens from the environment at
		// call time; wasm gets a private empty environment, so an
		// optional user-supplied token just becomes the right env var.
		os.Unsetenv("GITHUB_TOKEN")
		os.Unsetenv("GITLAB_TOKEN")
		os.Unsetenv("BITBUCKET_TOKEN")
		os.Unsetenv("GITEA_TOKEN")
		os.Unsetenv("AZURE_DEVOPS_TOKEN")
		if req.token != "" && tokenEnv != "" {
			os.Setenv(tokenEnv, req.token)
		}
		res, err := fetch(func(p string) bool { return lock.ByBasename(p) != nil })
		if err != nil {
			return js.Undefined(), err
		}
		warnings = append(warnings, res.Warnings...)
		base, target, title = res.BaseLabel, res.HeadLabel, res.Title
		for _, cf := range res.Files {
			parser := lock.ByBasename(cf.Path)
			oldF := parseOrNil(parser, cf.Path, cf.Old)
			newF := parseOrNil(parser, cf.Path, cf.New)
			if oldF == nil && newF == nil {
				continue
			}
			if fd := diffx.Diff(oldF, newF); len(fd.Changes) > 0 {
				diffs = append(diffs, fd)
			}
		}
		if len(diffs) == 0 {
			msg := "no lockfile changes in " + what
			if title != "" {
				msg = fmt.Sprintf("no lockfile changes in %s (%q)", what, title)
			}
			return noChanges(msg), nil
		}

	case "files":
		if len(req.oldData) == 0 || len(req.newData) == 0 {
			return js.Undefined(), errors.New("need two files: the old and the new lockfile (or two CycloneDX/SPDX JSON SBOMs)")
		}
		pOld, pNew := lock.ByBasename(req.oldName), lock.ByBasename(req.newName)
		if pOld == nil {
			pOld = pNew
		}
		if pNew == nil {
			pNew = pOld
		}
		parseFile := func(name string, parser *lock.Parser, data []byte) (*lock.File, error) {
			if parser == nil {
				parser = lock.FallbackParser(name)
			}
			f, err := parser.Parse(name, data)
			if err != nil {
				return nil, fmt.Errorf("%s: %v (want two lockfiles with their usual names, or CycloneDX/SPDX JSON SBOMs under any name)", name, err)
			}
			return f, nil
		}
		oldF, err := parseFile(req.oldName, pOld, req.oldData)
		if err != nil {
			return js.Undefined(), err
		}
		newF, err := parseFile(req.newName, pNew, req.newData)
		if err != nil {
			return js.Undefined(), err
		}
		base, target = req.oldName, req.newName
		fd := diffx.Diff(oldF, newF)
		if len(fd.Changes) == 0 {
			return noChanges(fmt.Sprintf("no changes between %s and %s", req.oldName, req.newName)), nil
		}
		diffs = append(diffs, fd)

	case "audit":
		// `lockvet audit` in the browser: every dropped lockfile is diffed
		// against nothing, so each pinned package arrives as an Added change
		// and the whole annotation pipeline works unmodified; the audit
		// renderers then show findings, not the inventory.
		if len(req.auditFiles) == 0 {
			return js.Undefined(), errors.New("drop at least one lockfile (or a CycloneDX/SPDX JSON SBOM) to audit")
		}
		audit = true
		req.changelogs = false // release notes explain bumps; an audit has none
		var names []string
		for _, af := range req.auditFiles {
			parser := lock.ByBasename(af.name)
			if parser == nil {
				parser = lock.FallbackParser(af.name)
			}
			f, err := parser.Parse(af.name, af.data)
			if err != nil {
				return js.Undefined(), fmt.Errorf("%s: %v (want a lockfile under its usual name, or a CycloneDX/SPDX JSON SBOM under any name)", af.name, err)
			}
			names = append(names, af.name)
			fd := diffx.Diff(nil, f)
			if len(fd.Changes) == 0 {
				continue
			}
			sort.Slice(fd.Changes, func(i, j int) bool { return fd.Changes[i].Name < fd.Changes[j].Name })
			diffs = append(diffs, fd)
		}
		if len(diffs) == 0 {
			return noChanges("no packages pinned in " + strings.Join(names, ", ")), nil
		}
		target = strings.Join(names, ", ")

	case "pkg":
		// `lockvet pkg` in the browser: each spec becomes a synthetic
		// one-package diff against nothing, so the whole pipeline —
		// advisories, ages, deprecation, unlisted, typosquat, install
		// scripts, provenance — answers "should I install this?" before
		// anything is installed.
		specs := strings.FieldsFunc(req.pkgs, func(r rune) bool {
			return r == ' ' || r == '\t' || r == '\n' || r == ','
		})
		if len(specs) == 0 {
			return js.Undefined(), errors.New("give at least one package as <ecosystem>:<name>[@version], e.g. npm:left-pad or pypi:requests@2.32.0")
		}
		pkg = true
		var labels []string
		for _, arg := range specs {
			spec, err := pkgspec.Parse(arg)
			if err != nil {
				return js.Undefined(), err
			}
			if spec.Version == "" {
				if req.noMeta {
					return js.Undefined(), fmt.Errorf("%s: the registry-checks-off option can't ask the registry what \"latest\" is — say which version to vet", spec.Label)
				}
				v, err := latest.Resolve(spec.Eco, spec.LookupName())
				if err != nil {
					return js.Undefined(), fmt.Errorf("%v — not every registry answers browsers; adding @version may help", err)
				}
				spec.Version = v
				spec.Label += "@" + v + " (latest)"
			}
			labels = append(labels, spec.Label)
			diffs = append(diffs, diffx.Diff(nil, spec.File()))
		}
		target = strings.Join(labels, ", ")

	default:
		return js.Undefined(), fmt.Errorf("unknown mode %q (want \"url\", \"files\", \"audit\", or \"pkg\")", req.mode)
	}

	if req.only != "" {
		total := 0
		for _, fd := range diffs {
			total += len(fd.Changes)
		}
		diffs = diffx.Filter(diffs, req.only)
		if len(diffs) == 0 {
			if audit {
				return noChanges(fmt.Sprintf("no packages matching filter %q (%d packages pinned in total)", req.only, total)), nil
			}
			return noChanges(fmt.Sprintf("no changes matching filter %q (%d packages changed in total)", req.only, total)), nil
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

	vulnsChecked := false
	if !req.noVulns && anyOSV {
		if err := osv.Annotate(diffs); err != nil {
			warnings = append(warnings, fmt.Sprintf("vulnerability check skipped: %v", err))
		} else {
			vulnsChecked = true
		}
	}
	metaChecked := false
	if !req.noMeta && anyMeta {
		if err := depsdev.Annotate(diffs, req.freshDays); err != nil {
			warnings = append(warnings, fmt.Sprintf("release-metadata check skipped: %v", err))
		} else {
			metaChecked = true
		}
	}
	if !req.noMeta {
		// deps.dev has no Composer system: Packagist itself is the PHP
		// metadata layer (its packages endpoint is CORS-open).
		if ok, err := phpreg.Annotate(diffs, req.freshDays); err != nil {
			warnings = append(warnings, fmt.Sprintf("Packagist registry check skipped: %v", err))
		} else if ok {
			metaChecked = true
		}
		// hex.pm's API is CORS-open — same route as the CLI.
		if ok, err := hexreg.Annotate(diffs, req.freshDays); err != nil {
			warnings = append(warnings, fmt.Sprintf("hex.pm registry check skipped: %v", err))
		} else if ok {
			metaChecked = true
		}
		// pub.dev's API is CORS-open — same route as the CLI.
		if ok, err := pubreg.Annotate(diffs, req.freshDays); err != nil {
			warnings = append(warnings, fmt.Sprintf("pub.dev registry check skipped: %v", err))
		} else if ok {
			metaChecked = true
		}
		// jsr.io is CORS-open — same route as the CLI.
		if ok, err := jsrreg.Annotate(diffs, req.freshDays); err != nil {
			warnings = append(warnings, fmt.Sprintf("jsr.io registry check skipped: %v", err))
		} else if ok {
			metaChecked = true
		}
		// CocoaPods: CDN index + podspecs via the jsDelivr mirror
		// (no ages in the browser — trunk sends no CORS headers).
		if ok, err := podreg.Annotate(diffs, req.freshDays); err != nil {
			warnings = append(warnings, fmt.Sprintf("CocoaPods registry check skipped: %v", err))
		} else if ok {
			metaChecked = true
		}
		// Terraform providers: ages + source links via the CORS-open
		// OpenTofu mirror (no unlisted/deprecation claims from a mirror).
		if ok, err := tfreg.Annotate(diffs, req.freshDays); err != nil {
			warnings = append(warnings, fmt.Sprintf("Terraform registry check skipped: %v", err))
		} else if ok {
			metaChecked = true
		}
		if metaChecked && req.changelogs {
			// taglink (verified changelog links) is skipped in the
			// browser — git smart-HTTP endpoints don't allow cross-origin
			// requests. The CLI has them. Release notes instead resolve
			// tags against the GitHub release list itself (relnotes.Fallback).
			relnotes.Fallback = true
			relnotes.MaxRepos = 25 // stay inside the browser's anonymous API quota
			for _, w := range relnotes.Annotate(diffs, os.Getenv("GITHUB_TOKEN")) {
				warnings = append(warnings,
					strings.Replace(w, "set GITHUB_TOKEN", "paste a GitHub API token under Options", 1))
			}
		}
		if err := npmreg.Annotate(diffs); err != nil {
			warnings = append(warnings, fmt.Sprintf("install-script check skipped: %v", err))
		}
		if err := pypireg.Annotate(diffs); err != nil {
			warnings = append(warnings, fmt.Sprintf("PyPI registry check skipped: %v", err))
		}
		if err := cargoreg.Annotate(diffs); err != nil {
			warnings = append(warnings, fmt.Sprintf("crates.io registry check skipped: %v", err))
		}
		// api.nuget.org allows cross-origin requests: full NuGet signals
		// in the browser too.
		if err := nugetreg.Annotate(diffs, req.freshDays); err != nil {
			warnings = append(warnings, fmt.Sprintf("NuGet registry check skipped: %v", err))
		}
		// proxy.golang.org sends ACAO:* — full Go signals in the browser.
		if err := goreg.Annotate(diffs, req.freshDays); err != nil {
			warnings = append(warnings, fmt.Sprintf("Go module proxy check skipped: %v", err))
		}
	}
	// The typosquat check is fully local (embedded popularity lists) — it
	// runs even with -no-meta/-offline; with ages unknown the young-release
	// gate honestly passes everything through. Last so it can use ages when
	// the metadata layers did run.
	flakereg.Annotate(diffs, req.freshDays) // fully local, like squat
	squat.Annotate(diffs)

	sum := diffx.Summarize(diffs)

	var term, md bytes.Buffer
	doc := map[string]any{
		"base": base, "target": target,
		"files": diffs, "summary": sum,
		"vulns_checked": vulnsChecked,
		"meta_checked":  metaChecked, "fresh_days": req.freshDays,
	}
	if audit {
		render.AuditTerminal(&term, diffs, sum, true, vulnsChecked, metaChecked, req.freshDays)
		render.AuditMarkdown(&md, diffs, sum, vulnsChecked, metaChecked, req.freshDays)
		// Same JSON shape as `lockvet audit -json`: every package is an
		// Added change, "introduced_vulns" = advisories affecting the pin.
		doc["mode"] = "audit"
		delete(doc, "base")
		delete(doc, "target")
	} else if pkg {
		render.Terminal(&term, diffs, sum, true, vulnsChecked, metaChecked, req.freshDays)
		render.Markdown(&md, diffs, sum, vulnsChecked, metaChecked, req.freshDays)
		// Same JSON shape as `lockvet pkg -json`: each file entry is one
		// requested spec, "introduced_vulns" = advisories on that version.
		doc["mode"] = "pkg"
		delete(doc, "base")
		delete(doc, "target")
	} else {
		render.Terminal(&term, diffs, sum, true, vulnsChecked, metaChecked, req.freshDays)
		render.Markdown(&md, diffs, sum, vulnsChecked, metaChecked, req.freshDays)
	}
	jsonBuf := &bytes.Buffer{}
	enc := json.NewEncoder(jsonBuf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return js.Undefined(), err
	}

	warnJS := make([]any, len(warnings))
	for i, w := range warnings {
		warnJS[i] = w
	}
	return js.ValueOf(map[string]any{
		"terminal": term.String(),
		"markdown": md.String(),
		"json":     jsonBuf.String(),
		"base":     base,
		"target":   target,
		"title":    title,
		"warnings": warnJS,
	}), nil
}

func noChanges(msg string) js.Value {
	return js.ValueOf(map[string]any{"noChanges": true, "message": msg})
}

type fetchFunc func(func(string) bool) (*ghpr.Result, error)

// resolveRemote mirrors the CLI's URL auto-detection: PR / MR, then compare,
// then single-commit URLs, per forge. It also reports which env var an
// optional token should land in for the matched forge.
func resolveRemote(u string) (fetch fetchFunc, tokenEnv, what string, err error) {
	if u == "" {
		return nil, "", "", errors.New("paste a pull-request, merge-request, compare, or commit URL")
	}
	switch {
	case strings.Contains(u, "bitbucket.org/"):
		tokenEnv = "BITBUCKET_TOKEN"
		if ref, ok := bbpr.Parse(u); ok {
			return func(f func(string) bool) (*ghpr.Result, error) { return bbpr.Fetch(ref, f) }, tokenEnv, ref.String(), nil
		}
		if ref, ok := bbpr.ParseCompare(u); ok {
			return func(f func(string) bool) (*ghpr.Result, error) { return bbpr.FetchCompare(ref, f) }, tokenEnv, ref.String(), nil
		}
		if w, r, sha, ok := bbpr.ParseCommit(u); ok {
			ref, err := bbpr.ResolveCommit(w, r, sha)
			if err != nil {
				return nil, "", "", err
			}
			return func(f func(string) bool) (*ghpr.Result, error) { return bbpr.FetchCompare(ref, f) }, tokenEnv, ref.String(), nil
		}
	case strings.Contains(u, "/_git/"):
		tokenEnv = "AZURE_DEVOPS_TOKEN"
		if ref, ok := adopr.Parse(u); ok {
			return func(f func(string) bool) (*ghpr.Result, error) { return adopr.Fetch(ref, f) }, tokenEnv, ref.String(), nil
		}
		if ref, ok := adopr.ParseCompare(u); ok {
			return func(f func(string) bool) (*ghpr.Result, error) { return adopr.FetchCompare(ref, f) }, tokenEnv, ref.String(), nil
		}
		if inst, proj, repo, sha, ok := adopr.ParseCommit(u); ok {
			ref, err := adopr.ResolveCommit(inst, proj, repo, sha)
			if err != nil {
				return nil, "", "", err
			}
			return func(f func(string) bool) (*ghpr.Result, error) { return adopr.FetchCompare(ref, f) }, tokenEnv, ref.String(), nil
		}
	case strings.Contains(u, "github.com/") || regularGitHubRef(u):
		tokenEnv = "GITHUB_TOKEN"
		if ref, ok := ghpr.Parse(u); ok {
			return func(f func(string) bool) (*ghpr.Result, error) { return ghpr.Fetch(ref, f) }, tokenEnv, ref.String(), nil
		}
		if ref, ok := ghpr.ParseCompare(u); ok {
			return func(f func(string) bool) (*ghpr.Result, error) { return ghpr.FetchCompare(ref, f) }, tokenEnv, ref.String(), nil
		}
		if o, r, sha, ok := ghpr.ParseCommit(u); ok {
			ref, err := ghpr.ResolveCommit(o, r, sha)
			if err != nil {
				return nil, "", "", err
			}
			return func(f func(string) bool) (*ghpr.Result, error) { return ghpr.FetchCompare(ref, f) }, tokenEnv, ref.String(), nil
		}
	case strings.Contains(u, "/-/") || strings.Contains(u, "!"):
		tokenEnv = "GITLAB_TOKEN"
		if ref, ok := glmr.ParseMR(u); ok {
			return func(f func(string) bool) (*ghpr.Result, error) { return glmr.Fetch(ref, f) }, tokenEnv, ref.String(), nil
		}
		if ref, ok := glmr.ParseCompare(u); ok {
			return func(f func(string) bool) (*ghpr.Result, error) { return glmr.FetchCompare(ref, f) }, tokenEnv, ref.String(), nil
		}
		if h, p, sha, ok := glmr.ParseCommit(u); ok {
			ref, err := glmr.ResolveCommit(h, p, sha)
			if err != nil {
				return nil, "", "", err
			}
			return func(f func(string) bool) (*ghpr.Result, error) { return glmr.FetchCompare(ref, f) }, tokenEnv, ref.String(), nil
		}
	default:
		// Gitea/Forgejo web URLs (codeberg.org or self-hosted): the
		// /pulls/N path shape is unique to them, so any host works.
		tokenEnv = "GITEA_TOKEN"
		if ref, ok := gtpr.Parse(u); ok {
			return func(f func(string) bool) (*ghpr.Result, error) { return gtpr.Fetch(ref, f) }, tokenEnv, ref.String(), nil
		}
		if ref, ok := gtpr.ParseCommit(u); ok {
			return func(f func(string) bool) (*ghpr.Result, error) { return gtpr.FetchCommit(ref, f) }, tokenEnv, ref.String(), nil
		}
		if ref, ok := gtpr.ParseCompare(u); ok {
			return func(f func(string) bool) (*ghpr.Result, error) { return gtpr.FetchCompare(ref, f) }, tokenEnv, ref.String(), nil
		}
	}
	return nil, "", "", fmt.Errorf("cannot parse %q — paste a GitHub / GitLab / Bitbucket / Gitea / Azure DevOps pull-request, compare, or commit URL (or owner/repo#N for GitHub)", u)
}

// regularGitHubRef reports whether s looks like the owner/repo#N shorthand.
func regularGitHubRef(s string) bool {
	_, ok := ghpr.Parse(s)
	return ok
}

// parseOrNil mirrors the CLI helper: nil data or a parse failure on one
// side must not sink the whole diff.
func parseOrNil(p *lock.Parser, path string, data []byte) *lock.File {
	if p == nil || len(data) == 0 {
		return nil
	}
	f, err := p.Parse(path, data)
	if err != nil {
		return nil
	}
	return f
}
