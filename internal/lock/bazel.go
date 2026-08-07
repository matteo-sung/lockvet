package lock

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// parseBazelLock reads MODULE.bazel.lock (bzlmod, Bazel 7+).
//
// Modern lockfiles (Bazel 7.2+) record no dependency graph — just
// registryFileHashes, the exact registry files consulted during
// resolution. The MODULE.bazel entries cover every candidate version the
// resolver looked at; the SELECTED version of a module is the one whose
// source.json hash is recorded (Bazel fetches source.json only for
// modules it actually materializes). That yields name, version, the
// registry host the module resolves from, and a content pin (the
// source.json file hash — it changing for the same version means the
// registry's description of that release changed underneath you).
//
// Older lockfiles (Bazel 7.0/7.1, lockFileVersion ≤ 5) carry the full
// moduleDepGraph: selected versions, dependency edges (via-chains work),
// root deps, and the archive's own SRI integrity from repoSpec.
//
// Modules under non-registry overrides (git_override, local_path_override)
// appear with version "_" in old lockfiles and not at all in modern ones —
// either way they are never judged against the registry. selectedYankedVersions
// (written when the build passes --allow_yanked_versions) lands in
// PkgYanked: the lockfile itself admitting a yanked version is in use.
func parseBazelLock(p string, data []byte) (*File, error) {
	var doc struct {
		LockFileVersion     int               `json:"lockFileVersion"`
		RegistryFileHashes  map[string]string `json:"registryFileHashes"`
		SelectedYanked      map[string]string `json:"selectedYankedVersions"`
		LocalOverrideHashes map[string]string `json:"localOverrideHashes"`
		ModuleDepGraph      map[string]struct {
			Name     string            `json:"name"`
			Version  string            `json:"version"`
			Deps     map[string]string `json:"deps"`
			RepoSpec struct {
				RuleClassName string `json:"ruleClassName"`
				Attributes    struct {
					Integrity string `json:"integrity"`
				} `json:"attributes"`
			} `json:"repoSpec"`
		} `json:"moduleDepGraph"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	f := newFile(p, "MODULE.bazel.lock", Bazel)

	// Modern shape: selected modules are the ones with a source.json hash.
	for rawURL, hash := range doc.RegistryFileHashes {
		name, version, host, ok := bazelSourceJSON(rawURL)
		if !ok {
			continue
		}
		f.add(name, version)
		f.setPin(name, version, hash, host)
		if host != "" && host != "bcr.bazel.build" {
			// Private/alternate registry: its contents are unknown to the
			// Bazel Central Registry — no registry-metadata judgements.
			f.markNonRegistry(name)
		}
	}

	// Old shape: full dependency graph.
	for key, entry := range doc.ModuleDepGraph {
		name, version := entry.Name, entry.Version
		if name == "" {
			name, version, _ = strings.Cut(key, "@")
		}
		if key == "<root>" || name == "" {
			continue
		}
		if version == "" || version == "_" {
			continue // built-in (bazel_tools) or non-registry override
		}
		f.add(name, version)
		if in := entry.RepoSpec.Attributes.Integrity; in != "" {
			f.setPin(name, version, in, "")
		}
		if rc := entry.RepoSpec.RuleClassName; rc != "" && rc != "http_archive" {
			f.markNonRegistry(name)
		}
		for _, dep := range entry.Deps {
			depName, depVer, _ := strings.Cut(dep, "@")
			if depVer == "_" || depName == "" {
				continue
			}
			f.addEdge(name, depName)
		}
	}
	if root, ok := doc.ModuleDepGraph["<root>"]; ok {
		for _, dep := range root.Deps {
			depName, depVer, _ := strings.Cut(dep, "@")
			if depVer == "_" || depName == "" {
				continue
			}
			f.addRoot(depName)
		}
	}
	for name := range doc.LocalOverrideHashes {
		if name != "<root>" && name != "" {
			f.markNonRegistry(name)
		}
	}

	for kv, reason := range doc.SelectedYanked {
		name, version, ok := strings.Cut(kv, "@")
		if !ok || name == "" || version == "" {
			continue
		}
		if f.PkgYanked == nil {
			f.PkgYanked = map[string]string{}
		}
		f.PkgYanked[Sanitize(name)+"@"+Sanitize(version)] = Sanitize(reason)
	}

	if len(f.Packages) == 0 && doc.LockFileVersion == 0 {
		return nil, errors.New("not a MODULE.bazel.lock (no lockFileVersion)")
	}
	return f, nil
}

// bazelSourceJSON matches a registryFileHashes key of the form
// {registry}/modules/{name}/{version}/source.json and returns the module
// name, version and registry host.
func bazelSourceJSON(rawURL string) (name, version, host string, ok bool) {
	if !strings.HasSuffix(rawURL, "/source.json") {
		return "", "", "", false
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", "", "", false
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	// .../modules/{name}/{version}/source.json — registries may live
	// under a path prefix, so search for the "modules" segment.
	for i := 0; i+3 < len(segs); i++ {
		if segs[i] == "modules" && segs[i+3] == "source.json" {
			n, err1 := url.PathUnescape(segs[i+1])
			v, err2 := url.PathUnescape(segs[i+2])
			if err1 != nil || err2 != nil || n == "" || v == "" {
				return "", "", "", false
			}
			return Sanitize(n), Sanitize(v), strings.ToLower(u.Host), true
		}
	}
	return "", "", "", false
}
