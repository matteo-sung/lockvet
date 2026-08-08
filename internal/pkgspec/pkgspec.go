// Package pkgspec parses `lockvet pkg` package specs — <ecosystem>:<name>[@version]
// — into the ecosystem, the name as the matching lockfile format would
// record it, and the version. Shared by the CLI, the MCP server, and the
// browser playground so every entry point accepts identical specs.
package pkgspec

import (
	"fmt"
	"strings"

	"github.com/matteo-sung/lockvet/internal/jsrreg"
	"github.com/matteo-sung/lockvet/internal/lock"
)

// ecoAliases maps every accepted spec prefix to a lockfile ecosystem.
// JSR is special-cased in Parse (deno.lock records jsr packages
// inside the npm ecosystem under a "jsr:" name prefix).
var ecoAliases = map[string]lock.Ecosystem{
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

// Spec is one parsed `eco:name[@version]` argument.
type Spec struct {
	Eco     lock.Ecosystem
	Name    string // as the matching lockfile format would record it
	Version string // empty = resolve latest from the registry
	Channel string // conda only: the anaconda.org channel (default conda-forge)
	Label   string // canonical spec, used as the report heading
}

// Parse splits eco:name[@version]. The version separator is the
// LAST "@" past the first character of the name, so scoped npm names
// (npm:@types/node, npm:@types/node@24.0.0) parse naturally.
func Parse(arg string) (Spec, error) {
	ecoPart, rest, ok := strings.Cut(arg, ":")
	if !ok || ecoPart == "" || rest == "" {
		return Spec{}, fmt.Errorf("package specs look like <ecosystem>:<name>[@version], e.g. npm:left-pad or pypi:requests@2.32.0 (got %q)", arg)
	}
	jsr := false
	ecoKey := strings.ToLower(ecoPart)
	if ecoKey == "jsr" {
		jsr = true
	}
	eco, known := ecoAliases[ecoKey]
	if jsr {
		eco, known = lock.NPM, true
	}
	if !known {
		return Spec{}, fmt.Errorf("unknown ecosystem %q — try npm, pypi, cargo, gem, composer, go, hex, pub, jsr, nuget, maven, pod, terraform, conan, conda, cran, julia, hackage, bazel, swift", ecoPart)
	}
	name, version := rest, ""
	if i := strings.LastIndex(rest, "@"); i > 0 {
		name, version = rest[:i], rest[i+1:]
	}
	name = strings.TrimSpace(lock.Sanitize(name))
	version = strings.TrimSpace(lock.Sanitize(version))
	if name == "" {
		return Spec{}, fmt.Errorf("package specs look like <ecosystem>:<name>[@version] (got %q)", arg)
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
			return Spec{}, fmt.Errorf("JSR package names look like @scope/name (got %q)", name)
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
	return Spec{Eco: eco, Name: name, Version: version, Channel: channel, Label: label}, nil
}

// LookupName is the name to ask the registry's latest-version resolver
// about (conda prefixes the channel).
func (s Spec) LookupName() string {
	if s.Eco == lock.Conda && s.Channel != "" {
		return s.Channel + "/" + s.Name
	}
	return s.Name
}

// File builds the synthetic one-package lockfile for the spec; diffing it
// against nothing runs the whole vetting pipeline over just this package.
// Version must be set (parsed or resolved) before calling.
func (s Spec) File() *lock.File {
	f := &lock.File{
		Path:      s.Label,
		Kind:      "pkg",
		Ecosystem: s.Eco,
		Packages:  map[string][]string{s.Name: {s.Version}},
	}
	if s.Eco == lock.Conda && s.Channel != "" {
		f.PkgChannel = map[string]string{lock.Sanitize(s.Name): s.Channel}
	}
	return f
}
