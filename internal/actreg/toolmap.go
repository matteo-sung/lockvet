package actreg

// The mise/asdf tool map: which repository a core tool's releases are
// tagged in, and how that repository spells its tags. A tool is only
// listed here when its repository carries a COMPLETE tag history for the
// versions asdf/mise install (that is what makes the ▲ not-a-release
// signal honest); tools that are not listed produce plain version rows
// with no repository claims.
//
// Backend-prefixed tools (`ubi:owner/repo`, `aqua:owner/repo`,
// `github:owner/repo`, `spm:owner/repo`) name their GitHub repository
// directly and need no map entry.

import (
	"fmt"
	"strings"

	"github.com/matteo-sung/lockvet/internal/taglink"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// toolStyle is one tag-spelling convention: tag = prefix + version (with
// "." replaced by sep) + suffix. The zero style is plain v1.2.3/1.2.3,
// which the generic resolver already tries.
type toolStyle struct{ prefix, sep, suffix string }

func (s toolStyle) tag(version string) string {
	mid := version
	if s.sep != "" && s.sep != "." {
		mid = strings.ReplaceAll(version, ".", s.sep)
	}
	return s.prefix + mid + s.suffix
}

// version maps a tag back to the version it spells, or "" when the tag
// does not follow this style.
func (s toolStyle) version(tag string) string {
	if !strings.HasPrefix(tag, s.prefix) || !strings.HasSuffix(tag, s.suffix) {
		return ""
	}
	mid := tag[len(s.prefix) : len(tag)-len(s.suffix)]
	if s.sep != "" && s.sep != "." {
		mid = strings.ReplaceAll(mid, s.sep, ".")
	}
	return mid
}

// defaultStyles: v-prefixed and bare tags — how most repos tag.
var defaultStyles = []toolStyle{{"v", ".", ""}, {"", ".", ""}}

type toolInfo struct {
	repo   string // owner/repo on github.com
	styles []toolStyle
}

var toolRepos = map[string]toolInfo{
	// Languages / runtimes.
	"node":    {repo: "nodejs/node"},
	"nodejs":  {repo: "nodejs/node"},
	"python":  {repo: "python/cpython"},
	"go":      {repo: "golang/go", styles: []toolStyle{{"go", ".", ""}}},
	"golang":  {repo: "golang/go", styles: []toolStyle{{"go", ".", ""}}},
	"ruby":    {repo: "ruby/ruby", styles: []toolStyle{{"v", "_", ""}}},
	"erlang":  {repo: "erlang/otp", styles: []toolStyle{{"OTP-", ".", ""}}},
	"elixir":  {repo: "elixir-lang/elixir"},
	"rust":    {repo: "rust-lang/rust"},
	"deno":    {repo: "denoland/deno"},
	"bun":     {repo: "oven-sh/bun", styles: []toolStyle{{"bun-v", ".", ""}}},
	"php":     {repo: "php/php-src", styles: []toolStyle{{"php-", ".", ""}}},
	"lua":     {repo: "lua/lua"},
	"julia":   {repo: "JuliaLang/julia"},
	"crystal": {repo: "crystal-lang/crystal"},
	"nim":     {repo: "nim-lang/Nim"},
	"zig":     {repo: "ziglang/zig"},
	"swift":   {repo: "swiftlang/swift", styles: []toolStyle{{"swift-", ".", "-RELEASE"}}},
	"kotlin":  {repo: "JetBrains/kotlin"},

	// Package/tool managers and JS toolchain.
	"pnpm":   {repo: "pnpm/pnpm"},
	"poetry": {repo: "python-poetry/poetry"},
	"uv":     {repo: "astral-sh/uv"},
	"ruff":   {repo: "astral-sh/ruff"},

	// Infrastructure as code.
	"terraform":  {repo: "hashicorp/terraform"},
	"opentofu":   {repo: "opentofu/opentofu"},
	"terragrunt": {repo: "gruntwork-io/terragrunt"},
	"packer":     {repo: "hashicorp/packer"},
	"vault":      {repo: "hashicorp/vault"},
	"consul":     {repo: "hashicorp/consul"},
	"nomad":      {repo: "hashicorp/nomad"},
	"pulumi":     {repo: "pulumi/pulumi"},

	// Kubernetes & containers.
	"kubectl":     {repo: "kubernetes/kubernetes"},
	"helm":        {repo: "helm/helm"},
	"helmfile":    {repo: "helmfile/helmfile"},
	"kustomize":   {repo: "kubernetes-sigs/kustomize", styles: []toolStyle{{"kustomize/v", ".", ""}}},
	"k9s":         {repo: "derailed/k9s"},
	"kind":        {repo: "kubernetes-sigs/kind"},
	"minikube":    {repo: "kubernetes/minikube"},
	"flux2":       {repo: "fluxcd/flux2"},
	"argocd":      {repo: "argoproj/argo-cd"},
	"eksctl":      {repo: "eksctl-io/eksctl"},
	"istioctl":    {repo: "istio/istio"},
	"skaffold":    {repo: "GoogleContainerTools/skaffold"},
	"kubeconform": {repo: "yannh/kubeconform"},
	"dive":        {repo: "wagoodman/dive"},
	"ko":          {repo: "ko-build/ko"},

	// Build tools.
	"cmake":      {repo: "Kitware/CMake"},
	"ninja":      {repo: "ninja-build/ninja"},
	"just":       {repo: "casey/just"},
	"task":       {repo: "go-task/task"},
	"bazel":      {repo: "bazelbuild/bazel"},
	"bazelisk":   {repo: "bazelbuild/bazelisk"},
	"buildifier": {repo: "bazelbuild/buildtools"},
	"protoc":     {repo: "protocolbuffers/protobuf"},
	"buf":        {repo: "bufbuild/buf"},
	"goreleaser": {repo: "goreleaser/goreleaser"},
	"dagger":     {repo: "dagger/dagger"},

	// Dev / CLI utilities.
	"gh":            {repo: "cli/cli"},
	"github-cli":    {repo: "cli/cli"},
	"direnv":        {repo: "direnv/direnv"},
	"jq":            {repo: "jqlang/jq", styles: []toolStyle{{"jq-", ".", ""}}},
	"yq":            {repo: "mikefarah/yq"},
	"shellcheck":    {repo: "koalaman/shellcheck"},
	"shfmt":         {repo: "mvdan/sh"},
	"golangci-lint": {repo: "golangci/golangci-lint"},
	"hugo":          {repo: "gohugoio/hugo"},
	"caddy":         {repo: "caddyserver/caddy"},
	"fzf":           {repo: "junegunn/fzf"},
	"ripgrep":       {repo: "BurntSushi/ripgrep"},
	"fd":            {repo: "sharkdp/fd"},
	"bat":           {repo: "sharkdp/bat"},
	"eza":           {repo: "eza-community/eza"},
	"delta":         {repo: "dandavison/delta"},
	"lazygit":       {repo: "jesseduffield/lazygit"},
	"starship":      {repo: "starship/starship"},
	"zoxide":        {repo: "ajeetdsouza/zoxide"},
	"tmux":          {repo: "tmux/tmux"},
	"neovim":        {repo: "neovim/neovim"},
	"zellij":        {repo: "zellij-org/zellij"},
	"nu":            {repo: "nushell/nushell"},
	"nushell":       {repo: "nushell/nushell"},
	"gum":           {repo: "charmbracelet/gum"},
	"dprint":        {repo: "dprint/dprint"},
	"act":           {repo: "nektos/act"},
	"awscli":        {repo: "aws/aws-cli"},
	"vale":          {repo: "errata-ai/vale"},
	"typos":         {repo: "crate-ci/typos"},
	"mkcert":        {repo: "FiloSottile/mkcert"},
	"watchexec":     {repo: "watchexec/watchexec", styles: []toolStyle{{"v", ".", ""}, {"cli-v", ".", ""}}},

	// Security / supply chain.
	"cosign":     {repo: "sigstore/cosign"},
	"syft":       {repo: "anchore/syft"},
	"grype":      {repo: "anchore/grype"},
	"trivy":      {repo: "aquasecurity/trivy"},
	"gitleaks":   {repo: "gitleaks/gitleaks"},
	"hadolint":   {repo: "hadolint/hadolint"},
	"actionlint": {repo: "rhysd/actionlint"},
	"sops":       {repo: "getsops/sops"},
	"age":        {repo: "FiloSottile/age"},

	// Databases.
	"postgres": {repo: "postgres/postgres", styles: []toolStyle{{"REL_", "_", ""}}},
	"redis":    {repo: "redis/redis"},
}

// toolInfoFor resolves a tool name (and, for repos that changed between
// major lines, the pinned version) to its repository info.
func toolInfoFor(name, version string) (toolInfo, bool) {
	if backend, rest, ok := strings.Cut(name, ":"); ok {
		switch strings.ToLower(backend) {
		case "ubi", "aqua", "github", "spm":
			if strings.Count(rest, "/") == 1 {
				return toolInfo{repo: rest}, true
			}
		}
		return toolInfo{}, false
	}
	lname := strings.ToLower(name)
	if lname == "yarn" {
		// yarn 1.x lives in yarnpkg/yarn (v1.22.22); berry (2+) tags
		// @yarnpkg/cli/4.9.2 in yarnpkg/berry.
		if strings.HasPrefix(strings.TrimPrefix(version, "v"), "1.") {
			return toolInfo{repo: "yarnpkg/yarn"}, true
		}
		return toolInfo{repo: "yarnpkg/berry",
			styles: []toolStyle{{"@yarnpkg/cli/", ".", ""}}}, true
	}
	ti, ok := toolRepos[lname]
	return ti, ok
}

// toolRepoURL returns the GitHub repository URL a tool pin is verified
// against, or "".
func toolRepoURL(c *diffx.Change) string {
	v := ""
	if len(c.New) > 0 {
		v = c.New[0]
	} else if len(c.Old) > 0 {
		v = c.Old[0]
	}
	ti, ok := toolInfoFor(c.Name, v)
	if !ok {
		return ""
	}
	return "https://github.com/" + ti.repo
}

// toolResolve resolves a tool version to the tag its repository spells it
// as: exact per-style candidates first, then — for short fuzzy pins like
// mise's `node = "22"` — the highest stable release on that line.
func toolResolve(name, version string, tags map[string]string) string {
	ti, ok := toolInfoFor(name, version)
	if !ok {
		return ""
	}
	styles := append(append([]toolStyle{}, ti.styles...), defaultStyles...)
	for _, s := range styles {
		if t := s.tag(version); tagExists(tags, t) {
			return t
		}
		// Tolerate the v-prefix inside styled specs too (ruby "v3.3.4").
		if alt := vSwap(version); alt != version {
			if t := s.tag(alt); tagExists(tags, t) {
				return t
			}
		}
	}
	// Fuzzy short pins: "22", "3.13" → the highest stable matching
	// release, mise-style.
	if strings.Count(version, ".") >= 2 || !VersionLike(version) ||
		strings.ContainsAny(version, "-+") {
		return ""
	}
	prefix := strings.TrimPrefix(version, "v")
	best, bestTag := "", ""
	for t := range tags {
		for _, s := range styles {
			sv := s.version(t)
			if sv == "" {
				continue
			}
			sv = strings.TrimPrefix(sv, "v")
			if !stableNumeric(sv) {
				continue
			}
			if sv != prefix && !strings.HasPrefix(sv, prefix+".") {
				continue
			}
			if best == "" || vers.Compare(best, sv) < 0 {
				best, bestTag = sv, t
			}
		}
	}
	if bestTag == version {
		return "" // the pin IS the tag; nothing to resolve
	}
	return bestTag
}

// ToolLatest resolves a mise/asdf tool's newest stable release — the
// highest tag that reverse-maps through the tool's tag convention to a
// plain dotted numeric version. Returned as the version a pin file would
// record ("22.5.1", not "v22.5.1").
func ToolLatest(name string) (string, error) {
	ti, ok := toolInfoFor(name, "")
	if !ok {
		return "", fmt.Errorf("tool %q is not in lockvet's tool→repository map — pass an explicit @version, or use ubi:owner/repo to name the GitHub repository directly", name)
	}
	tags, _, err := taglink.Refs("https://github.com/" + ti.repo)
	if err != nil || len(tags) == 0 {
		return "", fmt.Errorf("could not read tags from https://github.com/%s", ti.repo)
	}
	styles := append(append([]toolStyle{}, ti.styles...), defaultStyles...)
	best := ""
	for t := range tags {
		for _, s := range styles {
			sv := strings.TrimPrefix(s.version(t), "v")
			if sv == "" || !stableNumeric(sv) || !strings.Contains(sv, ".") {
				continue
			}
			if best == "" || vers.Compare(best, sv) < 0 {
				best = sv
			}
		}
	}
	if best == "" {
		return "", fmt.Errorf("no release-shaped tags in https://github.com/%s", ti.repo)
	}
	return best, nil
}

func tagExists(tags map[string]string, t string) bool {
	_, ok := tags[t]
	return ok
}

// stableNumeric reports whether a version string is purely numeric
// dotted-release shaped — no rc/beta/preview words, no build metadata.
// Used to keep fuzzy-pin resolution on stable releases only.
func stableNumeric(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		if b := v[i]; (b < '0' || b > '9') && b != '.' {
			return false
		}
	}
	return !strings.HasPrefix(v, ".") && !strings.HasSuffix(v, ".") &&
		!strings.Contains(v, "..")
}

// toolExactShaped reports whether a mise/asdf version pin is concrete
// enough to raise the not-a-release flag when it matches no tag: a purely
// numeric version with at least one dot. Fuzzy single-number pins ("22"),
// letter-suffixed builds ("3.13t") and pre-releases stay quiet.
func toolExactShaped(v string) bool {
	v = strings.TrimPrefix(v, "v")
	return strings.Contains(v, ".") && stableNumeric(v)
}
