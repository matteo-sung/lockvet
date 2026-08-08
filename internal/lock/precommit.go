package lock

// pre-commit configs pin dependencies too: every entry under `repos:` in
// .pre-commit-config.yaml names a hook repository at an exact `rev:` — a
// release tag or commit SHA that pre-commit clones and RUNS on every commit
// on every contributor's machine. `pre-commit autoupdate` and Renovate bump
// these pins exactly like lockfile entries, so lockvet treats the config as
// lockfile format #39 and verifies each rev against the hook repository's
// real tags (internal/actreg — the same machinery as GitHub Actions
// workflow pins).
//
// Package names keep their host ("github.com/psf/black"): hook repos live
// on any git forge, not just github.com.

import (
	"regexp"
	"sort"
	"strings"
)

var preCommitKey = regexp.MustCompile(`^\s*(?:-\s+)?(repo|rev)\s*:\s*(.+?)\s*$`)

// parsePreCommitConfig extracts repo+rev pins from .pre-commit-config.yaml.
// Line-based on purpose (the module is dependency-free): `repo:` and `rev:`
// values are single-line scalars, and hook entries carry neither key.
func parsePreCommitConfig(p string, data []byte) (*File, error) {
	f := newFile(p, "pre-commit-config", PreCommit)
	repo, rev := "", "" // pending fields of the current repos: item
	flush := func() {
		if repo != "" && rev != "" {
			f.add(repo, rev)
		}
		repo, rev = "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		m := preCommitKey.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		v := yamlScalar(m[2])
		if v == "" {
			continue
		}
		switch m[1] {
		case "repo":
			flush() // a new list item begins
			repo = preCommitRepoName(v)
		case "rev":
			if strings.ContainsAny(v, " \t") {
				continue
			}
			rev = v
			if repo != "" {
				flush()
			}
		}
	}
	flush()
	f.RootsKnown = true
	for name := range f.Packages {
		f.Roots = append(f.Roots, name)
	}
	sort.Strings(f.Roots)
	return f, nil
}

// yamlScalar strips surrounding quotes or a trailing comment from a
// single-line YAML scalar value.
func yamlScalar(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	if i := strings.Index(v, " #"); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v
}

// preCommitRepoName canonicalises a `repo:` URL into host/path form
// ("github.com/psf/black"), or "" for entries that name no fetchable
// repository (`repo: local`, `repo: meta`, relative paths).
func preCommitRepoName(v string) string {
	if v == "local" || v == "meta" || strings.HasPrefix(v, ".") || strings.Contains(v, "${{") {
		return ""
	}
	for _, prefix := range []string{"https://", "http://", "git://", "ssh://"} {
		v = strings.TrimPrefix(v, prefix)
	}
	// git@host:owner/repo → host/owner/repo
	v = strings.TrimPrefix(v, "git@")
	v = strings.Replace(v, ":", "/", 1)
	v = strings.TrimSuffix(strings.TrimSuffix(v, "/"), ".git")
	host, path, ok := strings.Cut(v, "/")
	if !ok || !strings.Contains(host, ".") || path == "" {
		return ""
	}
	return v
}
