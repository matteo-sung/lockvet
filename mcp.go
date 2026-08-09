package main

// mcp.go — `lockvet mcp`: a Model Context Protocol server over stdio, so AI
// assistants and coding agents can vet lockfile changes themselves. Plain
// JSON-RPC 2.0 with newline-delimited messages — no dependencies, like the
// rest of lockvet.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

var mcpProtocolVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
}

const mcpLatestProtocol = "2025-06-18"

const mcpInstructions = `lockvet explains lockfile changes: what was bumped, what's a major/breaking
jump, what became vulnerable (and what a bump fixes), how old each incoming
version is, what's deprecated, what's missing from the registry index, what looks like a typosquat, what suddenly runs install scripts, what silently drops sigstore provenance, what changes its content hash without a version change, what moves from a private registry to the public one
(unpublished/pulled releases), and license changes — across 59 lockfile
formats (npm, pnpm, yarn, bun, Cargo, uv, poetry, go.mod, composer, Gemfile,
conda, Julia, Haskell, Scala/sbt, Terraform, Helm, Ansible Galaxy, renv, SBOMs, and more).

Use vet_url for a pull/merge request, compare, or commit URL on GitHub,
GitLab, Bitbucket, Gitea/Forgejo, or Azure DevOps (no clone needed);
vet_git for a local git repository; vet_files for two lockfiles or SBOMs on
disk; audit to check everything a project currently pins (known advisories,
unlisted/yanked/deprecated versions) rather than a change; vet_package to
vet a dependency BEFORE installing it (specs like npm:left-pad or
pypi:requests@2.32.0 — advisories, age, deprecation, typosquat suspicion);
queue to triage every open Dependabot/Renovate PR of a repo, user, or org
at once. Reports are markdown by default; pass format:"json" for
structured output.`

type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// runMCP serves MCP on stdin/stdout until EOF.
func runMCP() {
	if err := serveMCP(os.Stdin, os.Stdout); err != nil {
		fatal(fmt.Sprintf("mcp: %v", err))
	}
}

func serveMCP(r io.Reader, w io.Writer) error {
	in := bufio.NewScanner(r)
	in.Buffer(make([]byte, 64*1024), 32*1024*1024)
	out := bufio.NewWriter(w)

	reply := func(id json.RawMessage, result any, rpcErr *mcpError) error {
		msg := map[string]any{"jsonrpc": "2.0", "id": id}
		if rpcErr != nil {
			msg["error"] = rpcErr
		} else {
			msg["result"] = result
		}
		b, err := json.Marshal(msg)
		if err != nil {
			return err
		}
		out.Write(b)
		out.WriteByte('\n')
		return out.Flush()
	}

	for in.Scan() {
		line := bytes.TrimSpace(in.Bytes())
		if len(line) == 0 {
			continue
		}
		var req mcpRequest
		if err := json.Unmarshal(line, &req); err != nil {
			if err := reply(nil, nil, &mcpError{-32700, "parse error: " + err.Error()}); err != nil {
				return err
			}
			continue
		}
		isNotification := len(req.ID) == 0 || string(req.ID) == "null"

		var (
			result any
			rpcErr *mcpError
		)
		switch req.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string `json:"protocolVersion"`
			}
			json.Unmarshal(req.Params, &p)
			ver := mcpLatestProtocol
			if mcpProtocolVersions[p.ProtocolVersion] {
				ver = p.ProtocolVersion
			}
			result = map[string]any{
				"protocolVersion": ver,
				"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
				"serverInfo": map[string]any{
					"name":    "lockvet",
					"title":   "lockvet — explain any lockfile change",
					"version": strings.TrimPrefix(effectiveVersion(), "v"),
				},
				"instructions": mcpInstructions,
			}
		case "ping":
			result = map[string]any{}
		case "tools/list":
			result = map[string]any{"tools": mcpTools()}
		case "tools/call":
			result, rpcErr = mcpToolCall(req.Params)
		case "notifications/initialized", "notifications/cancelled", "notifications/roots/list_changed":
			// nothing to do
		default:
			rpcErr = &mcpError{-32601, "method not found: " + req.Method}
		}

		if isNotification {
			continue
		}
		if err := reply(req.ID, result, rpcErr); err != nil {
			return err
		}
	}
	return in.Err()
}

// mcpTools describes the tools. Shared option properties are repeated
// per tool so each schema is self-contained.
func mcpTools() []map[string]any {
	strProp := func(desc string) map[string]any {
		return map[string]any{"type": "string", "description": desc}
	}
	onlyProp := strProp(`only report packages whose name — or any package in their "via" chain — matches this pattern (glob, case-insensitive, comma list ok, e.g. "@babel/*")`)
	freshProp := map[string]any{"type": "integer", "description": "flag versions published fewer than N days ago (default 7; 0 shows ages but never flags)"}
	offlineProp := map[string]any{"type": "boolean", "description": "skip all network lookups (no vulnerability, age, or deprecation data)"}
	changelogsProp := map[string]any{"type": "boolean", "description": "also fetch upstream release notes for every bump, including the releases a multi-version jump skips over (GitHub Releases first, then the repo's CHANGELOG/CHANGES/NEWS/HISTORY file at the verified tag — GitHub, GitLab, Gitea and Bitbucket hosted upstreams; GITHUB_TOKEN raises the releases-API rate limit)"}
	formatProp := map[string]any{"type": "string", "enum": []string{"markdown", "json"}, "description": `output format (default "markdown")`}
	ro := map[string]any{"readOnlyHint": true, "openWorldHint": true}

	return []map[string]any{
		{
			"name":  "vet_url",
			"title": "Vet a pull request, compare range, or commit by URL",
			"description": "Explain the lockfile/dependency changes of a pull/merge request, compare range, or commit on GitHub, GitLab, Bitbucket Cloud, Gitea/Forgejo (incl. Codeberg), or Azure DevOps — no clone needed. " +
				"Reports every added/removed/bumped package with semver severity, vulnerabilities introduced/fixed/unresolved (OSV.dev), release age, deprecations, license changes, unlisted versions, typosquat-suspect additions (new young packages one edit from a popular name), integrity changes on unchanged versions, SwiftPM/workflow/toolchain (.tool-versions, mise.toml) pins verified against upstream tags (moved-tag and not-a-release catches) and private-to-public registry resolution moves (dependency-confusion shape), npm install-script and npm/PyPI/crates.io/RubyGems provenance-dropped transitions (ages/deprecations cover Packagist, hex.pm, pub.dev, jsr.io, CocoaPods, CRAN, Helm chart repositories and Ansible Galaxy too), direct-vs-transitive origin with via-chains, and verified upstream changelog/diff links. " +
				"Accepts PR/MR URLs, compare URLs, commit URLs, or shorthands like owner/repo#123 (GitHub) and group/project!123 (GitLab). Uses GITHUB_TOKEN / GITLAB_TOKEN / BITBUCKET_TOKEN / GITEA_TOKEN / AZURE_DEVOPS_TOKEN from the environment when present; public repos work unauthenticated.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"url":        strProp("PR/MR, compare, or commit URL (or owner/repo#123 / group/project!123 shorthand)"),
					"only":       onlyProp,
					"fresh_days": freshProp,
					"offline":    offlineProp,
					"changelogs": changelogsProp,
					"format":     formatProp,
				},
				"required": []string{"url"},
			},
			"annotations": ro,
		},
		{
			"name":  "vet_git",
			"title": "Vet lockfile changes in a local git repository",
			"description": "Explain the lockfile/dependency changes in a local git repository: working tree vs HEAD by default, or any revision range (base=HEAD~5, or base=main target=my-branch). " +
				"Same report as vet_url: bumps with semver severity, vulnerabilities introduced/fixed, release ages, deprecations, license changes, via-chains. A .lockvetignore file in the repo (acknowledged findings) is honoured. Run it before committing or merging a dependency update.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"dir":        strProp("path to the git repository (default: current directory)"),
					"base":       strProp(`base revision (default "HEAD"); ranges like "main...topic" work too`),
					"target":     strProp("target revision (default: working tree)"),
					"only":       onlyProp,
					"fresh_days": freshProp,
					"offline":    offlineProp,
					"changelogs": changelogsProp,
					"format":     formatProp,
				},
			},
			"annotations": ro,
		},
		{
			"name":  "audit",
			"title": "Audit what the lockfiles pin right now",
			"description": "Audit the CURRENT dependency set of a project — not a change: every lockfile under the directory is checked in full (a .lockvetignore file there is honoured). " +
				"Reports each pinned version that is affected by a known advisory (OSV.dev), missing from its registry's index (what an unpublished or pulled — often malicious — release looks like), deprecated/retracted/yanked/abandoned upstream, or published only days ago. " +
				"Run it to answer \"is anything we currently depend on known-bad?\" — e.g. after news of a supply-chain attack, or as a periodic hygiene check.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"dir":        strProp("directory to audit (walked recursively; node_modules/vendor/.git skipped; default: current directory)"),
					"only":       onlyProp,
					"fresh_days": freshProp,
					"offline":    offlineProp,
					"format":     formatProp,
				},
			},
			"annotations": ro,
		},
		{
			"name":        "vet_files",
			"title":       "Vet two lockfiles or SBOMs on disk",
			"description": "Explain the dependency changes between two files on disk, no git needed: two lockfiles (any of the 40 supported formats; one side may carry a suffix, e.g. Cargo.lock.orig vs Cargo.lock) or two CycloneDX/SPDX JSON SBOMs under any filename — e.g. syft scans of two container images.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"old_path":   strProp("path to the old lockfile or SBOM"),
					"new_path":   strProp("path to the new lockfile or SBOM"),
					"only":       onlyProp,
					"fresh_days": freshProp,
					"offline":    offlineProp,
					"changelogs": changelogsProp,
					"format":     formatProp,
				},
				"required": []string{"old_path", "new_path"},
			},
			"annotations": ro,
		},
		{
			"name":  "vet_package",
			"title": "Vet a package before installing it",
			"description": "Vet one or more packages BEFORE they are in any lockfile — the moment you are deciding whether to npm install / pip install / cargo add them. " +
				"Reports known advisories affecting the version (OSV.dev, including MAL malicious-package records), release age (brand-new releases are higher-risk), deprecation/retraction/yank status with the upstream reason, versions missing from the registry index (what an unpublished or pulled — often malicious — release looks like), and typosquat suspicion (names one edit from a popular package). " +
				"Specs look like eco:name[@version] — npm:left-pad, pypi:requests@2.32.0, cargo:serde, go:github.com/gin-gonic/gin, maven:com.google.guava:guava, jsr:@std/http, swift:Alamofire/Alamofire. With no version, the registry's latest is looked up (npm, PyPI, crates.io, RubyGems, Packagist, Go, Hex, Pub, JSR, NuGet, Maven, CocoaPods, Terraform, conda, CRAN, Hackage, Bazel, Helm charts (helm:<repo-url>/<chart>), Ansible Galaxy (ansible:namespace.name — collections and classic roles), GitHub Actions, Swift, pre-commit:owner/repo hook repos, component:host/project/name GitLab CI components, orb:namespace/name CircleCI orbs, tool:node / tool:terraform asdf-mise tools verified against the tool's own repository tags). " +
				"Run this before adding any new dependency.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"packages": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "package specs, eco:name[@version] (e.g. [\"npm:left-pad\", \"pypi:requests@2.32.0\"])",
					},
					"only":       onlyProp,
					"fresh_days": freshProp,
					"offline":    offlineProp,
					"format":     formatProp,
				},
				"required": []string{"packages"},
			},
			"annotations": ro,
		},
		{
			"name":  "queue",
			"title": "Triage every open Dependabot/Renovate PR at once",
			"description": "Vet EVERY open dependency-update PR/MR of a repo, user, org, group, workspace, or project in one table, sorted most-alarming first: which introduce vulnerabilities, which are major or brand-new bumps, which look routine. " +
				"Scope: a GitHub owner or owner/repo, or a GitLab / Gitea / Bitbucket / Azure DevOps URL (e.g. gitlab.com/gitlab-org, codeberg.org/forgejo, bitbucket.org/atlassian, dev.azure.com/ORG/PROJECT). Defaults to Dependabot+Renovate authors; bot usernames vary on self-hosted forges — pass author to override, or \"any\" for every open PR touching a lockfile.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"scope":      strProp("GitHub owner or owner/repo, or a GitLab group/project, Gitea owner/repo, Bitbucket workspace/repo, or Azure DevOps project URL"),
					"author":     strProp(`bot accounts to search for (comma list; "any" = every open PR/MR that touches a lockfile)`),
					"limit":      map[string]any{"type": "integer", "description": "vet at most N pull/merge requests (default 30)"},
					"only":       onlyProp,
					"fresh_days": freshProp,
					"offline":    offlineProp,
					"format":     formatProp,
				},
				"required": []string{"scope"},
			},
			"annotations": ro,
		},
	}
}

func mcpToolCall(params json.RawMessage) (any, *mcpError) {
	var call struct {
		Name string `json:"name"`
		Args struct {
			URL        string   `json:"url"`
			Dir        string   `json:"dir"`
			Base       string   `json:"base"`
			Target     string   `json:"target"`
			OldPath    string   `json:"old_path"`
			NewPath    string   `json:"new_path"`
			Scope      string   `json:"scope"`
			Packages   []string `json:"packages"`
			Author     string   `json:"author"`
			Limit      int      `json:"limit"`
			Only       string   `json:"only"`
			FreshDays  *int     `json:"fresh_days"`
			Offline    bool     `json:"offline"`
			Changelogs bool     `json:"changelogs"`
			Format     string   `json:"format"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return nil, &mcpError{-32602, "invalid params: " + err.Error()}
	}
	a := call.Args
	freshDays := 7
	if a.FreshDays != nil {
		freshDays = *a.FreshDays
	}
	o := vetOptions{only: a.Only, freshDays: freshDays, noVulns: a.Offline, noMeta: a.Offline, changelogs: a.Changelogs}
	format := a.Format
	if format == "" {
		format = "markdown"
	}
	if format != "markdown" && format != "json" {
		return nil, &mcpError{-32602, fmt.Sprintf("invalid format %q (want markdown or json)", format)}
	}

	toolErr := func(msg string) (any, *mcpError) {
		return map[string]any{
			"content": []map[string]any{{"type": "text", "text": msg}},
			"isError": true,
		}, nil
	}

	var (
		v   *vetOutcome
		err error
	)
	switch call.Name {
	case "vet_url":
		if a.URL == "" {
			return nil, &mcpError{-32602, "vet_url needs a url"}
		}
		v, err = vetRemote(a.URL, o)
	case "vet_git":
		dir := a.Dir
		if dir == "" {
			dir = "."
		}
		v, err = vetGit(dir, a.Base, a.Target, o)
	case "vet_files":
		if a.OldPath == "" || a.NewPath == "" {
			return nil, &mcpError{-32602, "vet_files needs old_path and new_path"}
		}
		v, err = vetFiles(a.OldPath, a.NewPath, o)
	case "vet_package":
		if len(a.Packages) == 0 {
			return nil, &mcpError{-32602, "vet_package needs packages (specs like npm:left-pad or pypi:requests@2.32.0)"}
		}
		po := o
		po.changelogs = false
		v, err = vetPkg(a.Packages, po)
	case "audit":
		dir := a.Dir
		if dir == "" {
			dir = "."
		}
		ao := o
		ao.changelogs = false
		v, err = vetAudit(nil, dir, ao)
	case "queue":
		if a.Scope == "" {
			return nil, &mcpError{-32602, "queue needs a scope"}
		}
		qo := queueOpts{
			author: a.Author, limit: a.Limit,
			md: format == "markdown", jsonOut: format == "json",
			noVulns: a.Offline, noMeta: a.Offline,
			freshDays: freshDays, only: a.Only,
		}
		var buf bytes.Buffer
		if _, err := queueRun(a.Scope, qo, &buf); err != nil {
			return toolErr(err.Error())
		}
		return map[string]any{
			"content": []map[string]any{{"type": "text", "text": buf.String()}},
			"isError": false,
		}, nil
	default:
		return nil, &mcpError{-32602, "unknown tool: " + call.Name}
	}
	if err != nil {
		return toolErr(err.Error())
	}

	text, rerr := v.render(format)
	if rerr != nil {
		return toolErr(rerr.Error())
	}
	if format == "markdown" && len(v.warnings) > 0 {
		text += "\n> [!NOTE]\n"
		for _, w := range v.warnings {
			text += "> " + w + "\n"
		}
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": false,
	}, nil
}
