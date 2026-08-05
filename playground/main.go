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
//	mode:      "url" | "files"
//	url:       PR / MR / compare / commit URL (mode "url")
//	token:     optional API token for the matched forge (mode "url")
//	oldName, oldData, newName, newData:  file names + Uint8Array (mode "files")
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
	"strings"
	"syscall/js"

	"github.com/matteo-sung/lockvet/internal/adopr"
	"github.com/matteo-sung/lockvet/internal/bbpr"
	"github.com/matteo-sung/lockvet/internal/depsdev"
	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/ghpr"
	"github.com/matteo-sung/lockvet/internal/glmr"
	"github.com/matteo-sung/lockvet/internal/gtpr"
	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/npmreg"
	"github.com/matteo-sung/lockvet/internal/osv"
	"github.com/matteo-sung/lockvet/internal/pypireg"
	"github.com/matteo-sung/lockvet/internal/relnotes"
	"github.com/matteo-sung/lockvet/internal/render"
)

var version = "dev" // set via -ldflags at build time

func main() {
	// versionbatch does not answer CORS preflights; per-version GETs do.
	depsdev.SingleRequests = true
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
	only             string
	freshDays        int
	noVulns, noMeta  bool
	changelogs       bool
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
		only:       strings.TrimSpace(str("only")),
		freshDays:  7,
		noVulns:    boolean("noVulns"),
		noMeta:     boolean("noMeta"),
		changelogs: boolean("changelogs"),
	}
	if v := opts.Get("freshDays"); v.Type() == js.TypeNumber {
		req.freshDays = v.Int()
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
				parser = lock.SBOMParser()
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

	default:
		return js.Undefined(), fmt.Errorf("unknown mode %q (want \"url\" or \"files\")", req.mode)
	}

	if req.only != "" {
		total := 0
		for _, fd := range diffs {
			total += len(fd.Changes)
		}
		diffs = diffx.Filter(diffs, req.only)
		if len(diffs) == 0 {
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
			// taglink (verified changelog links) is skipped in the
			// browser — git smart-HTTP endpoints don't allow cross-origin
			// requests. The CLI has them. Release notes instead resolve
			// tags against the GitHub release list itself (relnotes.Fallback).
			if req.changelogs {
				relnotes.Fallback = true
				relnotes.MaxRepos = 25 // stay inside the browser's anonymous API quota
				for _, w := range relnotes.Annotate(diffs, os.Getenv("GITHUB_TOKEN")) {
					warnings = append(warnings,
						strings.Replace(w, "set GITHUB_TOKEN", "paste a GitHub API token under Options", 1))
				}
			}
		}
	}
	if !req.noMeta {
		if err := npmreg.Annotate(diffs); err != nil {
			warnings = append(warnings, fmt.Sprintf("install-script check skipped: %v", err))
		}
		if err := pypireg.Annotate(diffs); err != nil {
			warnings = append(warnings, fmt.Sprintf("PyPI registry check skipped: %v", err))
		}
	}

	sum := diffx.Summarize(diffs)

	var term, md bytes.Buffer
	render.Terminal(&term, diffs, sum, true, vulnsChecked, metaChecked, req.freshDays)
	render.Markdown(&md, diffs, sum, vulnsChecked, metaChecked, req.freshDays)
	jsonBuf := &bytes.Buffer{}
	enc := json.NewEncoder(jsonBuf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(map[string]any{
		"base": base, "target": target,
		"files": diffs, "summary": sum,
		"vulns_checked": vulnsChecked,
		"meta_checked":  metaChecked, "fresh_days": req.freshDays,
	}); err != nil {
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
