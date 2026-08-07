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
	"github.com/matteo-sung/lockvet/internal/jsrreg"
	"github.com/matteo-sung/lockvet/internal/latest"
	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/render"
)

// pkgEcoAliases maps every accepted spec prefix to a lockfile ecosystem.
// JSR is special-cased in parsePkgSpec (deno.lock records jsr packages
// inside the npm ecosystem under a "jsr:" name prefix).
var pkgEcoAliases = map[string]lock.Ecosystem{
	"npm":            lock.NPM,
	"pypi":           lock.PyPI,
	"pip":            lock.PyPI,
	"python":         lock.PyPI,
	"cargo":          lock.CratesIO,
	"crate":          lock.CratesIO,
	"crates":         lock.CratesIO,
	"crates.io":      lock.CratesIO,
	"rust":           lock.CratesIO,
	"gem":            lock.RubyGems,
	"gems":           lock.RubyGems,
	"rubygems":       lock.RubyGems,
	"ruby":           lock.RubyGems,
	"composer":       lock.Packagist,
	"packagist":      lock.Packagist,
	"php":            lock.Packagist,
	"go":             lock.Go,
	"golang":         lock.Go,
	"hex":            lock.Hex,
	"elixir":         lock.Hex,
	"pub":            lock.Pub,
	"dart":           lock.Pub,
	"flutter":        lock.Pub,
	"nuget":          lock.NuGet,
	"dotnet":         lock.NuGet,
	"maven":          lock.Maven,
	"mvn":            lock.Maven,
	"java":           lock.Maven,
	"pod":            lock.CocoaPods,
	"pods":           lock.CocoaPods,
	"cocoapods":      lock.CocoaPods,
	"terraform":      lock.Terraform,
	"tf":             lock.Terraform,
	"opentofu":       lock.Terraform,
	"conan":          lock.Conan,
	"conda":          lock.Conda,
	"pixi":           lock.Conda,
	"cran":           lock.CRAN,
	"r":              lock.CRAN,
	"bioconductor":   lock.Bioconductor,
	"julia":          lock.Julia,
	"hackage":        lock.Hackage,
	"bazel":          lock.Bazel,
	"bzlmod":         lock.Bazel,
	"haskell":        lock.Hackage,
	"actions":        lock.GitHubActions,
	"github-actions": lock.GitHubActions,
	"swift":          lock.SwiftURL,
	"swiftpm":        lock.SwiftURL,
	"spm":            lock.SwiftURL,
}

// pkgSpec is one parsed `eco:name[@version]` argument.
type pkgSpec struct {
	eco     lock.Ecosystem
	name    string // as the matching lockfile format would record it
	version string // empty = resolve latest from the registry
	channel string // conda only: the anaconda.org channel (default conda-forge)
	label   string // canonical spec, used as the report heading
}

// parsePkgSpec splits eco:name[@version]. The version separator is the
// LAST "@" past the first character of the name, so scoped npm names
// (npm:@types/node, npm:@types/node@24.0.0) parse naturally.
func parsePkgSpec(arg string) (pkgSpec, error) {
	ecoPart, rest, ok := strings.Cut(arg, ":")
	if !ok || ecoPart == "" || rest == "" {
		return pkgSpec{}, fmt.Errorf("package specs look like <ecosystem>:<name>[@version], e.g. npm:left-pad or pypi:requests@2.32.0 (got %q)", arg)
	}
	jsr := false
	ecoKey := strings.ToLower(ecoPart)
	if ecoKey == "jsr" {
		jsr = true
	}
	eco, known := pkgEcoAliases[ecoKey]
	if jsr {
		eco, known = lock.NPM, true
	}
	if !known {
		return pkgSpec{}, fmt.Errorf("unknown ecosystem %q — try npm, pypi, cargo, gem, composer, go, hex, pub, jsr, nuget, maven, pod, terraform, conan, conda, cran, julia, hackage, bazel, swift", ecoPart)
	}
	name, version := rest, ""
	if i := strings.LastIndex(rest, "@"); i > 0 {
		name, version = rest[:i], rest[i+1:]
	}
	name = strings.TrimSpace(lock.Sanitize(name))
	version = strings.TrimSpace(lock.Sanitize(version))
	if name == "" {
		return pkgSpec{}, fmt.Errorf("package specs look like <ecosystem>:<name>[@version] (got %q)", arg)
	}
	// Normalize per-ecosystem quirks the way the lockfile formats do.
	switch eco {
	case lock.Go:
		if version != "" && !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
	case lock.Packagist, lock.NuGet:
		name = strings.ToLower(name)
	case lock.SwiftURL:
		// Package.resolved records the repo URL without scheme or .git,
		// and versions without the v-prefix. `swift:owner/repo` implies
		// github.com, matching the actions shorthand.
		name = strings.TrimSuffix(strings.TrimSuffix(name, "/"), ".git")
		for _, prefix := range []string{"https://", "http://", "ssh://", "git@"} {
			name = strings.TrimPrefix(name, prefix)
		}
		name = strings.Replace(name, ":", "/", 1)
		if first, _, ok := strings.Cut(name, "/"); ok && !strings.Contains(first, ".") {
			name = "github.com/" + name
		}
		version = strings.TrimPrefix(version, "v")
	}
	channel := ""
	if eco == lock.Conda {
		channel = "conda-forge"
		if ch, rest, ok := strings.Cut(name, "/"); ok && ch != "" && rest != "" {
			channel, name = ch, rest
		}
	}
	if jsr {
		if !strings.HasPrefix(name, "@") {
			return pkgSpec{}, fmt.Errorf("JSR package names look like @scope/name (got %q)", name)
		}
		name = jsrreg.Prefix + name
	}
	labelName := strings.TrimPrefix(name, jsrreg.Prefix)
	if channel != "" && channel != "conda-forge" {
		labelName = channel + "/" + labelName
	}
	label := ecoKey + ":" + labelName
	if version != "" {
		label += "@" + version
	}
	return pkgSpec{eco: eco, name: name, version: version, channel: channel, label: label}, nil
}

// vetPkg resolves each spec (asking the registry for the latest version
// where none was given) and runs the standard pipeline over synthetic
// one-package diffs. Shared by the CLI and the MCP `vet_package` tool.
func vetPkg(args []string, o vetOptions) (*vetOutcome, error) {
	var diffs []diffx.FileDiff
	for _, arg := range args {
		spec, err := parsePkgSpec(arg)
		if err != nil {
			return nil, err
		}
		if spec.version == "" {
			if o.noMeta {
				return nil, fmt.Errorf("%s: -offline/-no-meta can't ask the registry what \"latest\" is — say which version to vet", spec.label)
			}
			lookupName := spec.name
			if spec.eco == lock.Conda && spec.channel != "" {
				lookupName = spec.channel + "/" + spec.name
			}
			v, err := latest.Resolve(spec.eco, lookupName)
			if err != nil {
				return nil, err
			}
			spec.version = v
			spec.label += "@" + v + " (latest)"
		}
		f := &lock.File{
			Path:      spec.label,
			Kind:      "pkg",
			Ecosystem: spec.eco,
			Packages:  map[string][]string{spec.name: {spec.version}},
		}
		if spec.eco == lock.Conda && spec.channel != "" {
			f.PkgChannel = map[string]string{lock.Sanitize(spec.name): spec.channel}
		}
		fd := diffx.Diff(nil, f)
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
