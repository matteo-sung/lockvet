package lock

import (
	"encoding/json"
	"sort"
	"strings"
)

// ---- vcpkg.json / vcpkg-configuration.json (vcpkg, C/C++) ----
//
// vcpkg manifests barely pin individual versions — the baseline commit
// does: every dependency resolves to the version the microsoft/vcpkg
// registry recorded at the pinned "builtin-baseline" commit, so the
// baseline IS the lockfile for a vcpkg project. lockvet reports it as a
// package ("builtin-baseline") whose version is the commit, which gets
// the flake.lock treatment downstream: rev...rev compare links, the
// commit's own date as the release age, and — via internal/vcpkgreg —
// a check that the commit actually exists in microsoft/vcpkg (a baseline
// only reachable in a fork is the poisoned-registry shape: the build
// works on the attacker's checkout and nowhere else).
//
// "overrides" entries DO pin exact port versions ("1.2.3", port-version
// suffix rendered "1.2.3#2" like vcpkg's own docs). They are verified
// against the registry's versions database (versions/{c}-/{name}.json),
// which is append-only — a version no port has ever shipped is real
// evidence. Dependency entries themselves ("version>=") are minimum
// constraints, not pins, and claim nothing.
//
// vcpkg-configuration.json (standalone, or embedded under
// "vcpkg-configuration") pins per-registry baselines the same way:
// "default-registry" and "registry <host/path>" rows. A default-registry
// swapped to a different repository changes the resolution source for
// every port — that rides the pins host machinery and surfaces as ⇄.
// When the default registry is replaced, overlay-ports are declared, or
// a custom registry claims packages, override pins can resolve outside
// microsoft/vcpkg (an overlay shadows any port with any version), so
// those overrides are marked NonRegistry and never checked against the
// official database — microsoft/terminal pins fmt to an overlay-only
// version exactly this way. Overlays passed only on the command line or
// in a separate vcpkg-configuration.json are invisible here; the
// outgoing-version gate in internal/vcpkgreg protects those (a project
// steadily on overlay versions never has its OLD version in the official
// database either, so no claim is made).
//
// vcpkg's own JSON parser accepts C++-style comments; stripJSONC (shared
// with devcontainer.json) runs first.

func parseVcpkgManifest(p string, data []byte) (*File, error) {
	f := newFile(p, "vcpkg.json", Vcpkg)
	var doc struct {
		BuiltinBaseline string `json:"builtin-baseline"`
		Overrides       []struct {
			Name          string `json:"name"`
			Version       string `json:"version"`
			VersionSemver string `json:"version-semver"`
			VersionDate   string `json:"version-date"`
			VersionString string `json:"version-string"`
			PortVersion   int    `json:"port-version"`
		} `json:"overrides"`
		Configuration json.RawMessage `json:"vcpkg-configuration"`
	}
	if err := json.Unmarshal(stripJSONC(data), &doc); err != nil {
		return nil, err
	}

	if sha := strings.ToLower(strings.TrimSpace(doc.BuiltinBaseline)); isCommitSha(sha) {
		f.add("builtin-baseline", shortSha(sha))
		f.setPkgRepo("builtin-baseline", vcpkgOfficialRepo)
	}

	var names []string
	for _, o := range doc.Overrides {
		ver := o.Version
		for _, alt := range []string{o.VersionSemver, o.VersionDate, o.VersionString} {
			if ver == "" {
				ver = alt
			}
		}
		ver = strings.TrimSpace(ver)
		if o.Name == "" || ver == "" {
			continue
		}
		if o.PortVersion > 0 {
			ver += "#" + itoa(o.PortVersion)
		}
		f.add(o.Name, ver)
		names = append(names, o.Name)
	}

	if len(doc.Configuration) > 0 {
		custom := addVcpkgConfig(f, doc.Configuration)
		markVcpkgCustomOverrides(f, names, custom)
	}
	return f, nil
}

func parseVcpkgConfiguration(p string, data []byte) (*File, error) {
	f := newFile(p, "vcpkg-configuration.json", Vcpkg)
	clean := stripJSONC(data)
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(clean, &probe); err != nil {
		return nil, err
	}
	addVcpkgConfig(f, clean)
	return f, nil
}

const vcpkgOfficialRepo = "https://github.com/microsoft/vcpkg"

// vcpkgCustom describes which packages resolve outside the official
// registry: all of them (default registry replaced, or overlay-ports
// declared — an overlay can shadow ANY port with a version the official
// database never listed, so no override claim is safe), or the listed
// patterns (custom registries' "packages" globs).
type vcpkgCustom struct {
	defaultReplaced bool
	overlays        bool
	patterns        []string
}

// addVcpkgConfig records the registry baseline pins a configuration
// object carries and reports which packages resolve from custom
// registries.
func addVcpkgConfig(f *File, raw json.RawMessage) vcpkgCustom {
	var cfg struct {
		DefaultRegistry *struct {
			Kind       string `json:"kind"`
			Repository string `json:"repository"`
			Baseline   string `json:"baseline"`
		} `json:"default-registry"`
		Registries []struct {
			Kind       string   `json:"kind"`
			Repository string   `json:"repository"`
			Baseline   string   `json:"baseline"`
			Packages   []string `json:"packages"`
		} `json:"registries"`
		OverlayPorts []string `json:"overlay-ports"`
	}
	var custom vcpkgCustom
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return custom
	}
	custom.overlays = len(cfg.OverlayPorts) > 0

	if r := cfg.DefaultRegistry; r != nil {
		sha := strings.ToLower(strings.TrimSpace(r.Baseline))
		host := ""
		repo := ""
		switch r.Kind {
		case "builtin":
			host = vcpkgRegistryHost(vcpkgOfficialRepo)
			repo = vcpkgOfficialRepo
		case "git":
			host = vcpkgRegistryHost(r.Repository)
			repo = vcpkgBrowsableRepo(r.Repository)
			if host != vcpkgRegistryHost(vcpkgOfficialRepo) {
				custom.defaultReplaced = true
			}
		}
		if isCommitSha(sha) && host != "" {
			f.add("default-registry", shortSha(sha))
			f.setPin("default-registry", shortSha(sha), "", host)
			if repo != "" {
				f.setPkgRepo("default-registry", repo)
			}
		}
	}

	for _, r := range cfg.Registries {
		if r.Kind != "git" {
			// filesystem/artifact registries pin local paths or tool
			// archives; nothing verifiable here.
			if r.Kind != "" {
				custom.patterns = append(custom.patterns, r.Packages...)
			}
			continue
		}
		custom.patterns = append(custom.patterns, r.Packages...)
		sha := strings.ToLower(strings.TrimSpace(r.Baseline))
		host := vcpkgRegistryHost(r.Repository)
		if !isCommitSha(sha) || host == "" {
			continue
		}
		name := "registry " + host
		f.add(name, shortSha(sha))
		if repo := vcpkgBrowsableRepo(r.Repository); repo != "" {
			f.setPkgRepo(name, repo)
		}
	}
	sort.Strings(custom.patterns)
	return custom
}

// markVcpkgCustomOverrides marks override packages that resolve from a
// custom registry (or a replaced default registry) as NonRegistry so the
// official versions database is never consulted for them.
func markVcpkgCustomOverrides(f *File, names []string, custom vcpkgCustom) {
	for _, n := range names {
		if custom.defaultReplaced || custom.overlays || vcpkgPatternMatch(custom.patterns, n) {
			f.markNonRegistry(n)
		}
	}
}

// vcpkgPatternMatch implements the registry "packages" glob subset:
// exact names plus a trailing '*' wildcard ("boost*").
func vcpkgPatternMatch(patterns []string, name string) bool {
	for _, p := range patterns {
		if p == name {
			return true
		}
		if strings.HasSuffix(p, "*") && strings.HasPrefix(name, p[:len(p)-1]) {
			return true
		}
	}
	return false
}

// vcpkgRegistryHost canonicalizes a registry repository URL for the pins
// host slot, so "https://github.com/x/y.git", "git@github.com:x/y" and
// the builtin form all agree.
func vcpkgRegistryHost(repoURL string) string {
	u := strings.TrimSpace(strings.ToLower(repoURL))
	if u == "" {
		return ""
	}
	for _, pre := range []string{"https://", "http://", "ssh://git@", "git://"} {
		u = strings.TrimPrefix(u, pre)
	}
	if rest, ok := strings.CutPrefix(u, "git@"); ok {
		u = strings.Replace(rest, ":", "/", 1)
	}
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	u = strings.TrimSuffix(strings.TrimSuffix(u, "/"), ".git")
	if u == "" || strings.HasPrefix(u, "/") || !strings.Contains(u, "/") {
		return ""
	}
	return u
}

// vcpkgBrowsableRepo returns an https URL for compare links, or "".
func vcpkgBrowsableRepo(repoURL string) string {
	host := vcpkgRegistryHost(repoURL)
	if host == "" {
		return ""
	}
	return "https://" + host
}

func isCommitSha(s string) bool {
	if len(s) < 7 || len(s) > 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func shortSha(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// setPkgRepo records the package's browsable source repository.
func (f *File) setPkgRepo(name, repo string) {
	if name == "" || repo == "" {
		return
	}
	if f.PkgRepo == nil {
		f.PkgRepo = map[string]string{}
	}
	f.PkgRepo[Sanitize(name)] = repo
}
