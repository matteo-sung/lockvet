package lock

// GitHub Actions workflows pin dependencies too: every `uses:` line is a
// package (the action repository) at a version (a tag, branch, or commit
// SHA). Dependabot and Renovate bump these pins exactly like lockfile
// entries, and the March-2025 tj-actions/changed-files attack shipped
// through them — so lockvet treats workflow files as lockfile format #31.
//
// Matched paths: *.yml/*.yaml under .github/workflows (also .gitea/workflows
// and .forgejo/workflows — Gitea and Forgejo run the same syntax), plus
// action.yml/action.yaml anywhere (composite actions declare `uses:` steps).

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

// isWorkflowPath reports whether p is a CI workflow file whose `uses:`
// pins lockvet should read.
func isWorkflowPath(p string) bool {
	q := strings.ReplaceAll(p, "\\", "/")
	base := path.Base(q)
	if base == "action.yml" || base == "action.yaml" {
		return true
	}
	if !strings.HasSuffix(base, ".yml") && !strings.HasSuffix(base, ".yaml") {
		return false
	}
	dir := path.Dir(q)
	return strings.HasSuffix(dir, ".github/workflows") ||
		strings.HasSuffix(dir, ".gitea/workflows") ||
		strings.HasSuffix(dir, ".forgejo/workflows")
}

var usesLine = regexp.MustCompile(`^\s*(?:-\s+)?(?:"uses"|'uses'|uses)\s*:\s*(.+?)\s*$`)

// parseWorkflowUses extracts action pins from a workflow or composite
// action YAML. Line-based on purpose: `uses:` values are single-line
// scalars, and a full YAML parse buys nothing but fragility here.
func parseWorkflowUses(p string, data []byte) (*File, error) {
	f := newFile(p, "github-workflow", GitHubActions)
	for _, line := range strings.Split(string(data), "\n") {
		m := usesLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		name, ref, ok := splitUses(m[1])
		if !ok {
			continue
		}
		f.add(name, ref)
	}
	// Workflows have no dependency graph: every pin is a direct dependency.
	f.RootsKnown = true
	for name := range f.Packages {
		f.Roots = append(f.Roots, name)
	}
	sort.Strings(f.Roots)
	return f, nil
}

// splitUses turns a raw `uses:` value into (owner/repo, ref). Local paths
// (./x), docker images (docker://…) and dynamic expressions (${{ … }})
// are not registry dependencies and are skipped. Subpath actions
// (owner/repo/sub@ref) and reusable workflows
// (owner/repo/.github/workflows/ci.yml@ref) collapse onto the repository
// that ships them: that is what carries tags, advisories and releases.
func splitUses(v string) (name, ref string, ok bool) {
	// Strip surrounding quotes and any trailing comment.
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		v = v[1 : len(v)-1]
	} else if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	if v == "" || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "docker://") ||
		strings.Contains(v, "${{") {
		return "", "", false
	}
	at := strings.LastIndexByte(v, '@')
	if at <= 0 || at == len(v)-1 {
		return "", "", false
	}
	name, ref = v[:at], v[at+1:]
	parts := strings.Split(name, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	if !validRepoPart(parts[0]) || !validRepoPart(parts[1]) {
		return "", "", false
	}
	if strings.ContainsAny(ref, " \t\"'") {
		return "", "", false
	}
	return parts[0] + "/" + parts[1], ref, true
}

func validRepoPart(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return s != "" && s != "." && s != ".."
}

// FallbackParser guesses a parser for a file whose name is not a known
// lockfile basename (explicit two-file diffs, playground drops): YAML
// files are tried as CI workflows — strict: at least one `uses:` pin —
// then as Kubernetes manifests (top-level apiVersion: and kind:
// required), so a mis-named real lockfile still gets a helpful error —
// and everything else goes to SBOM content sniffing.
func FallbackParser(name string) *Parser {
	b := strings.ToLower(path.Base(strings.ReplaceAll(name, "\\", "/")))
	if strings.HasSuffix(b, ".yml") || strings.HasSuffix(b, ".yaml") {
		return &Parser{"github-workflow", GitHubActions, func(p string, data []byte) (*File, error) {
			f, err := parseWorkflowUses(p, data)
			if err == nil && len(f.Packages) > 0 {
				return f, nil
			}
			if kf, kerr := parseK8sManifest(p, data); kerr == nil {
				return kf, nil
			}
			if err == nil {
				err = errFallbackNoUses
			}
			return nil, err
		}}
	}
	return SBOMParser()
}

var errFallbackNoUses = errNoUses{}

type errNoUses struct{}

func (errNoUses) Error() string {
	return "no `uses:` action pins found (tried it as a CI workflow and as a Kubernetes manifest)"
}
