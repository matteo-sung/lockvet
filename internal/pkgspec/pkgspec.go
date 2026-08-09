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
	"ansible":        lock.Ansible,
	"galaxy":         lock.Ansible,
	"ansible-galaxy": lock.Ansible,
	"ansible-role":   lock.AnsibleRole,
	"helm":           lock.Helm,
	"chart":          lock.Helm,
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
	"pre-commit":     lock.PreCommit,
	"precommit":      lock.PreCommit,
	"component":      lock.GitLabCI,
	"gitlab-ci":      lock.GitLabCI,
	"orb":            lock.CircleCI,
	"circleci":       lock.CircleCI,
	"swift":          lock.SwiftURL,
	"swiftpm":        lock.SwiftURL,
	"spm":            lock.SwiftURL,
}

// Spec is one parsed `eco:name[@version]` argument.
type Spec struct {
	Eco     lock.Ecosystem
	Name    string // as the matching lockfile format would record it
	Version string // empty = resolve latest from the registry
	Channel string // conda: the anaconda.org channel; helm: the chart repository URL
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
		return Spec{}, fmt.Errorf("unknown ecosystem %q — try npm, pypi, cargo, gem, composer, go, hex, pub, jsr, nuget, maven, pod, helm, terraform, conan, conda, cran, julia, hackage, bazel, ansible, swift, orb", ecoPart)
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
	helmChannel := ""
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
	case lock.Helm:
		// Helm has no central registry: the spec names the chart
		// repository AND the chart — helm:<repo-url>/<chart>. The last
		// path segment is the chart name, the rest is the repository
		// (https:// implied). The repo URL lands in Channel, exactly
		// where the Chart.lock parser puts it.
		name = strings.TrimSuffix(name, "/")
		for _, prefix := range []string{"https://", "http://"} {
			name = strings.TrimPrefix(name, prefix)
		}
		i := strings.LastIndex(name, "/")
		if i <= 0 || !strings.Contains(name[:i], ".") {
			return Spec{}, fmt.Errorf("Helm specs name the chart repository and the chart: helm:<repo-url>/<chart>, e.g. helm:https://charts.bitnami.com/bitnami/postgresql (got %q)", rest)
		}
		channelURL := "https://" + name[:i]
		name = name[i+1:]
		version = strings.TrimPrefix(version, "v")
		helmChannel = channelURL
	case lock.PreCommit:
		// .pre-commit-config.yaml records the repo URL; names keep their
		// host ("github.com/psf/black"). `pre-commit:owner/repo` implies
		// github.com, matching the actions shorthand. Revs stay as
		// written: hook tags usually carry the v-prefix.
		name = strings.TrimSuffix(strings.TrimSuffix(name, "/"), ".git")
		for _, prefix := range []string{"https://", "http://", "ssh://", "git@"} {
			name = strings.TrimPrefix(name, prefix)
		}
		name = strings.Replace(name, ":", "/", 1)
		if first, _, ok := strings.Cut(name, "/"); ok && !strings.Contains(first, ".") {
			name = "github.com/" + name
		}
	case lock.GitLabCI:
		// CI/CD Catalog components are addressed
		// host/project-path/component-name, exactly as `include:
		// component:` writes them. gitlab.com is implied when the first
		// segment has no dot.
		name = strings.TrimSuffix(name, "/")
		for _, prefix := range []string{"https://", "http://"} {
			name = strings.TrimPrefix(name, prefix)
		}
		if first, _, ok := strings.Cut(name, "/"); ok && !strings.Contains(first, ".") {
			name = "gitlab.com/" + name
		}
		if strings.Count(name, "/") < 3 {
			return Spec{}, fmt.Errorf("component specs name the project and the component: component:<host>/<project-path>/<component>[@version], e.g. component:gitlab.com/components/opentofu/full-pipeline (got %q)", rest)
		}
	case lock.CircleCI:
		// Orbs are addressed namespace/orb-name, exactly as `orbs:`
		// entries pin them.
		if first, second, ok := strings.Cut(name, "/"); !ok || first == "" ||
			second == "" || strings.Contains(second, "/") {
			return Spec{}, fmt.Errorf("orb specs look like orb:<namespace>/<orb-name>[@version], e.g. orb:circleci/node or orb:circleci/node@5.1.0 (got %q)", rest)
		}
	}
	channel := helmChannel
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
	if eco == lock.Helm {
		labelName = strings.TrimPrefix(channel, "https://") + "/" + name
	}
	label := ecoKey + ":" + labelName
	if version != "" {
		label += "@" + version
	}
	return Spec{Eco: eco, Name: name, Version: version, Channel: channel, Label: label}, nil
}

// LookupName is the name to ask the registry's latest-version resolver
// about (conda prefixes the channel; helm prefixes the repository URL).
func (s Spec) LookupName() string {
	if s.Eco == lock.Conda && s.Channel != "" {
		return s.Channel + "/" + s.Name
	}
	if s.Eco == lock.Helm && s.Channel != "" {
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
	if (s.Eco == lock.Conda || s.Eco == lock.Helm) && s.Channel != "" {
		f.PkgChannel = map[string]string{lock.Sanitize(s.Name): s.Channel}
	}
	return f
}
