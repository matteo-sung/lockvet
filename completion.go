package main

import (
	"fmt"
	"strings"
	"time"
)

// Shell completion scripts and the man page, printed by
// `lockvet completion bash|zsh|fish` and `lockvet man`.
// Keep the flag/subcommand lists here in sync with usage in main.go.

const bashCompletion = `# bash completion for lockvet
# Install:  lockvet completion bash > /etc/bash_completion.d/lockvet
#      or:  echo 'source <(lockvet completion bash)' >> ~/.bashrc
_lockvet() {
    local cur prev words cword
    if declare -F _init_completion >/dev/null 2>&1; then
        _init_completion || return
    else
        COMPREPLY=()
        cur=${COMP_WORDS[COMP_CWORD]}
        prev=${COMP_WORDS[COMP_CWORD-1]}
        words=("${COMP_WORDS[@]}")
        cword=$COMP_CWORD
    fi

    local flags="-md -json -sarif -no-vulns -no-meta -offline -fresh-days -changelogs -only -comment -fail-on -author -limit -C -no-color -version -h"
    local subcmds="pr mr compare queue diff mcp completion man"

    case $prev in
        -C)
            if declare -F _filedir >/dev/null 2>&1; then _filedir -d; else
                COMPREPLY=( $(compgen -d -- "$cur") )
            fi
            return ;;
        -fail-on)
            COMPREPLY=( $(compgen -W "major vuln downgrade fresh deprecated unlisted scripts provenance license" -- "$cur") )
            return ;;
        -fresh-days|-limit|-only|-author)
            return ;;
    esac

    if [[ $cur == -* ]]; then
        COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
        return
    fi

    # Find the first non-flag argument (the subcommand, if any).
    local i sub="" seen=0
    for ((i=1; i < cword; i++)); do
        case ${words[i]} in
            -C|-fail-on|-fresh-days|-only|-author|-limit) ((i++)) ;;
            -*) ;;
            *) sub=${words[i]}; seen=$i; break ;;
        esac
    done

    if [[ -z $sub ]]; then
        COMPREPLY=( $(compgen -W "$subcmds" -- "$cur") )
        return
    fi
    case $sub in
        completion)
            COMPREPLY=( $(compgen -W "bash zsh fish" -- "$cur") ) ;;
        diff)
            if declare -F _filedir >/dev/null 2>&1; then _filedir; else
                COMPREPLY=( $(compgen -f -- "$cur") )
            fi ;;
    esac
}
complete -F _lockvet lockvet
`

const zshCompletion = `#compdef lockvet
# zsh completion for lockvet
# Install:  lockvet completion zsh > "${fpath[1]}/_lockvet"
#      or:  echo 'source <(lockvet completion zsh)' >> ~/.zshrc

_lockvet() {
    local -a subcmds
    subcmds=(
        'pr:vet a GitHub / Bitbucket / Azure DevOps pull request by URL, no clone'
        'mr:vet a GitLab merge request by URL, no clone'
        'compare:vet any two revisions or a single commit of a remote repo'
        'queue:triage every open Dependabot/Renovate PR of a repo, user, or org'
        'diff:vet two lockfiles or SBOM files on disk, no git'
        'mcp:run as a Model Context Protocol server (stdio) for AI assistants'
        'completion:print a shell completion script (bash, zsh, or fish)'
        'man:print the manual page (roff)'
    )
    local context state state_descr line
    typeset -A opt_args

    _arguments -S \
        '-md[markdown output (for PR comments)]' \
        '-json[JSON output]' \
        '-sarif[SARIF 2.1.0 output (GitHub Code Scanning)]' \
        '-no-vulns[skip the OSV.dev vulnerability check]' \
        '-no-meta[skip deps.dev metadata (release ages, deprecations, links)]' \
        '-offline[no network calls at all]' \
        '-fresh-days[flag versions published fewer than N days ago (default 7)]:days' \
        '-changelogs[fetch upstream release notes for every bump]' \
        '-only[only changes whose name or via-chain matches PAT (glob, comma list)]:pattern' \
        '-comment[post the report as a comment on the PR/MR]' \
        '-fail-on[exit 1 if the diff contains a condition (comma list)]:condition:_values -s , condition major vuln downgrade fresh deprecated unlisted scripts provenance license' \
        '-author[queue mode: bot accounts to search for (comma list, "any" ok)]:authors' \
        '-limit[queue mode: vet at most N pull/merge requests (default 30)]:n' \
        '-C[run as if started in dir]:directory:_files -/' \
        '-no-color[disable colors]' \
        '-version[print version]' \
        '1:subcommand or git revision:->first' \
        '*::argument:->rest' && return

    case $state in
        first)
            _describe -t subcmds 'lockvet subcommand' subcmds
            ;;
        rest)
            case $line[1] in
                completion) _values 'shell' bash zsh fish ;;
                diff) _files ;;
            esac
            ;;
    esac
}

# Called by the completion system when autoloaded from fpath; when this
# file is source'd directly, register the function instead.
if [ "${funcstack[1]}" = "_lockvet" ]; then
    _lockvet "$@"
else
    compdef _lockvet lockvet
fi
`

const fishCompletion = `# fish completion for lockvet
# Install:  lockvet completion fish > ~/.config/fish/completions/lockvet.fish
complete -c lockvet -f

# Subcommands (first argument)
complete -c lockvet -n __fish_use_subcommand -a pr -d 'vet a GitHub/Bitbucket/Azure DevOps pull request by URL'
complete -c lockvet -n __fish_use_subcommand -a mr -d 'vet a GitLab merge request by URL'
complete -c lockvet -n __fish_use_subcommand -a compare -d 'vet two revisions or a commit of a remote repo'
complete -c lockvet -n __fish_use_subcommand -a queue -d 'triage every open Dependabot/Renovate PR in one table'
complete -c lockvet -n __fish_use_subcommand -a diff -d 'vet two lockfiles or SBOMs on disk'
complete -c lockvet -n __fish_use_subcommand -a mcp -d 'run as a Model Context Protocol server (stdio)'
complete -c lockvet -n __fish_use_subcommand -a completion -d 'print a shell completion script'
complete -c lockvet -n __fish_use_subcommand -a man -d 'print the manual page (roff)'

complete -c lockvet -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish'
complete -c lockvet -n '__fish_seen_subcommand_from diff' -F

# Flags (Go-style single-dash long options)
complete -c lockvet -o md -d 'markdown output (for PR comments)'
complete -c lockvet -o json -d 'JSON output'
complete -c lockvet -o sarif -d 'SARIF 2.1.0 output (GitHub Code Scanning)'
complete -c lockvet -o no-vulns -d 'skip the OSV.dev vulnerability check'
complete -c lockvet -o no-meta -d 'skip deps.dev metadata (ages, deprecations, links)'
complete -c lockvet -o offline -d 'no network calls at all'
complete -c lockvet -o fresh-days -x -d 'flag versions younger than N days (default 7)'
complete -c lockvet -o changelogs -d 'fetch upstream release notes for every bump'
complete -c lockvet -o only -x -d 'only changes matching pattern (glob, comma list)'
complete -c lockvet -o comment -d 'post the report as a PR/MR comment'
complete -c lockvet -o fail-on -x -a 'major vuln downgrade fresh deprecated unlisted scripts provenance license' -d 'exit 1 on findings (comma list)'
complete -c lockvet -o author -x -d 'queue mode: bot accounts (comma list, "any" ok)'
complete -c lockvet -o limit -x -d 'queue mode: vet at most N PRs (default 30)'
complete -c lockvet -o C -x -a '(__fish_complete_directories)' -d 'run as if started in dir'
complete -c lockvet -o no-color -d 'disable colors'
complete -c lockvet -o version -d 'print version'
`

// manPage is the roff source for lockvet(1). %VERSION% and %DATE% are
// substituted at print time.
const manPage = `.TH LOCKVET 1 "%DATE%" "lockvet %VERSION%" "User Commands"
.SH NAME
lockvet \- explain any lockfile change before you merge it
.SH SYNOPSIS
.B lockvet
[\fIflags\fR] [\fIbase\fR [\fItarget\fR]]
.br
.B lockvet pr
\fIowner/repo\fR#\fIN\fR | \fIPR-URL\fR
.br
.B lockvet mr
\fIgroup/project\fR!\fIN\fR | \fIMR-URL\fR
.br
.B lockvet compare
\fIowner/repo base...head\fR | \fIcompare-or-commit-URL\fR
.br
.B lockvet queue
\fIowner\fR | \fIowner/repo\fR | \fIforge-URL\fR
.br
.B lockvet diff
\fIold-file\fR \fInew-file\fR
.br
.B lockvet completion
\fBbash\fR|\fBzsh\fR|\fBfish\fR
.SH DESCRIPTION
.B lockvet
reads two versions of a dependency lockfile and explains the difference:
what was added, removed, upgraded, or downgraded; which bumps are
major/breaking; which incoming versions are newly vulnerable (via OSV.dev)
and which vulnerabilities a bump fixes; how old every incoming release is;
which packages are deprecated upstream; which incoming versions their own
registry no longer lists (what an unpublished malicious release looks
like); and which bumps change their license.
Every change is labeled \fB(direct)\fR or \fIvia\fR its pull-in chain.
.PP
It understands 29 lockfile formats across the npm, pnpm, yarn, bun, Cargo,
uv, poetry, pipenv, pip, Go, Composer, RubyGems, Hex, pub, Gradle, NuGet,
Swift, CocoaPods, Deno, Nix, conda, R, Julia, Haskell, Gleam,
Terraform/OpenTofu, and Helm ecosystems, plus CycloneDX and SPDX JSON
SBOMs \(em all in one static binary.
.SH MODES
.TP
.B lockvet
With no arguments: working tree vs HEAD in the current git repo.
With one revision: working tree vs that revision.
With two revisions: revision vs revision.
.TP
.B lockvet pr \fR/\fB mr
Vet a pull or merge request by URL without cloning \(em GitHub, GitLab,
Bitbucket Cloud, Gitea/Forgejo (pr), and Azure DevOps are auto-detected.
Bare URLs work as the first argument too.
.TP
.B lockvet compare
Vet any two revisions, or a single commit against its first parent, of a
remote repository \(em accepts forge compare/commit URLs.
.TP
.B lockvet queue
Triage every open Dependabot/Renovate PR of a repo, user, org, group,
workspace, or project in one table, sorted most-alarming first.
.TP
.B lockvet diff
Vet two files on disk with no git: two lockfiles, or two CycloneDX/SPDX
JSON SBOMs (e.g. syft scans of two container images).
.TP
.B lockvet mcp
Run as a Model Context Protocol server on stdio, so AI assistants and
coding agents can vet lockfile changes: tools \fBvet_url\fR, \fBvet_git\fR,
\fBvet_files\fR, and \fBqueue\fR.
.SH OPTIONS
.TP
.B \-md
Markdown output, suitable for PR comments.
.TP
.B \-json
JSON output.
.TP
.B \-sarif
SARIF 2.1.0 output for code scanning; vulnerable, unresolved, and
deprecated incoming versions become alerts anchored to the exact lockfile
line.
.TP
.B \-no\-vulns
Skip the OSV.dev vulnerability check.
.TP
.B \-no\-meta
Skip the deps.dev metadata check (release ages, deprecations, license
changes, changelog links).
.TP
.B \-offline
No network calls at all (implies \fB\-no\-vulns \-no\-meta\fR).
.TP
.BI \-fresh\-days " N"
Flag versions published fewer than \fIN\fR days ago (default 7;
0 shows ages but never flags).
.TP
.B \-changelogs
Fetch upstream release notes for every bump \(em including the releases a
multi\-version jump skips over \(em and show them inline. GitHub\-hosted
upstreams; uses the GitHub API, so \fBGITHUB_TOKEN\fR or a logged\-in
\fBgh\fR raises the rate limit.
.TP
.BI \-only " PATTERN"
Only show changes whose name \(em or any package in their \fIvia\fR
chain \(em matches \fIPATTERN\fR (glob, case-insensitive, comma list).
.TP
.B \-comment
(pr/mr modes) Post the report as a comment on the pull or merge request;
reruns update the same comment in place.
.TP
.BI \-fail\-on " LIST"
Exit 1 if the diff contains any of: \fBmajor\fR, \fBvuln\fR,
\fBdowngrade\fR, \fBfresh\fR, \fBdeprecated\fR, \fBunlisted\fR, \fBscripts\fR, \fBprovenance\fR, \fBlicense\fR
(comma list).
.TP
.BI \-author " LIST"
(queue mode) Bot accounts to search for, comma list; \fBany\fR means
every open PR/MR that touches a lockfile.
.TP
.BI \-limit " N"
(queue mode) Vet at most \fIN\fR pull/merge requests (default 30).
.TP
.BI \-C " DIR"
Run as if started in \fIDIR\fR.
.TP
.B \-no\-color
Disable colors (the \fBNO_COLOR\fR environment variable is respected too).
.TP
.B \-version
Print version.
.SH EXIT STATUS
.B 0
on success,
.B 1
when a \fB\-fail\-on\fR condition matched,
.B 2
on errors and usage mistakes.
.SH ENVIRONMENT
.TP
.B GITHUB_TOKEN\fR, \fBGH_TOKEN
GitHub API token; the gh CLI's stored login is used as a fallback.
.TP
.B GITLAB_TOKEN\fR, \fBGL_TOKEN\fR, \fBCI_JOB_TOKEN
GitLab API token (\fB\-comment\fR needs a token with api scope).
.TP
.B BITBUCKET_TOKEN
Bitbucket Cloud access token or \fIuser:app\-password\fR.
.TP
.B GITEA_TOKEN\fR, \fBFORGEJO_TOKEN\fR, \fBCODEBERG_TOKEN
Gitea/Forgejo API token.
.TP
.B AZURE_DEVOPS_TOKEN\fR, \fBAZURE_DEVOPS_EXT_PAT\fR, \fBSYSTEM_ACCESSTOKEN
Azure DevOps personal access token or pipeline job token.
.TP
.B NO_COLOR
Disable colored output.
.SH EXAMPLES
.TP
Explain what a Dependabot PR really changes:
.B lockvet pr https://github.com/owner/repo/pull/42
.TP
Gate CI on new vulnerabilities and majors:
.B lockvet -fail-on vuln,major
.TP
Triage a whole org's dependency PRs:
.B lockvet queue grafana
.TP
Compare two releases of someone else's repo:
.B lockvet compare sharkdp/fd v10.2.0...v10.3.0
.TP
Diff two container images by SBOM:
.B lockvet diff old.cdx.json new.cdx.json
.SH SEE ALSO
Project page and full documentation:
.I https://github.com/matteo-sung/lockvet
.PP
Data sources:
.I https://osv.dev
(vulnerabilities),
.I https://deps.dev
(release metadata), plus the npm, PyPI, crates.io, RubyGems, Packagist,
NuGet, hex.pm and pub.dev registries, the CocoaPods CDN and trunk API,
and the Go module proxy themselves
(version listings, install scripts, provenance, Go retractions, and — for
Composer, Hex, Dart and CocoaPods — ages and deprecations, which deps.dev
does not carry).
`

// runCompletion handles `lockvet completion <shell>` and `lockvet man`.
func runCompletion(args []string) {
	if len(args) != 1 {
		fatal("usage: lockvet completion <bash|zsh|fish>")
	}
	switch args[0] {
	case "bash":
		fmt.Print(bashCompletion)
	case "zsh":
		fmt.Print(zshCompletion)
	case "fish":
		fmt.Print(fishCompletion)
	default:
		fatal(fmt.Sprintf("unknown shell %q (want bash, zsh, or fish)", args[0]))
	}
}

func runMan() {
	page := strings.ReplaceAll(manPage, "%VERSION%", effectiveVersion())
	page = strings.ReplaceAll(page, "%DATE%", time.Now().Format("January 2006"))
	fmt.Print(page)
}
