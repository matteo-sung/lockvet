package lock

import (
	"encoding/json"
	"regexp"
	"strings"
)

// ---- Pipfile.lock (pipenv) ----

func parsePipfileLock(p string, data []byte) (*File, error) {
	f := newFile(p, "Pipfile.lock", PyPI)
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	// _meta.sources: named indexes; the hosts let the diff spot a package
	// resolution moving between a private index and PyPI.
	srcHost := map[string]string{}
	if raw, ok := doc["_meta"]; ok {
		var meta struct {
			Sources []struct {
				Name string `json:"name"`
				URL  string `json:"url"`
			} `json:"sources"`
		}
		if json.Unmarshal(raw, &meta) == nil {
			for _, s := range meta.Sources {
				srcHost[s.Name] = HostOf(s.URL)
			}
		}
	}
	for _, section := range []string{"default", "develop"} {
		raw, ok := doc[section]
		if !ok {
			continue
		}
		var pkgs map[string]struct {
			Version string   `json:"version"`
			Hashes  []string `json:"hashes"`
			Index   string   `json:"index"`
			Git     string   `json:"git"`
			Path    string   `json:"path"`
			File    string   `json:"file"`
		}
		if err := json.Unmarshal(raw, &pkgs); err != nil {
			continue // section may hold non-package metadata in odd files
		}
		for name, pkg := range pkgs {
			cname := normalizePyPI(name)
			f.add(cname, strings.TrimPrefix(pkg.Version, "=="))
			if pkg.Git != "" || pkg.Path != "" || pkg.File != "" {
				f.markNonRegistry(cname)
				continue
			}
			host := srcHost[pkg.Index]
			if host == "" && len(srcHost) == 1 {
				for _, h := range srcHost {
					host = h
				}
			}
			f.setPin(cname, strings.TrimPrefix(pkg.Version, "=="),
				strings.Join(pkg.Hashes, " "), host)
		}
	}
	return f, nil
}

// ---- mix.lock (Elixir / Hex) ----
//
//	"phoenix": {:hex, :phoenix, "1.7.10", "aaaaaaaa...", [:mix], [...], "hexpm", "bbbb..."},
//
// Only :hex entries carry a registry version; :git/:path entries are skipped.
// The map key is the OTP application name; the Hex PACKAGE name is the
// atom after :hex — they differ for renamed forks ("chatterbox": {:hex,
// :ts_chatterbox, ...}), and the package name is what hex.pm and OSV
// know, so that is the name lockvet reports. Entries resolved from a
// private/self-hosted Hex repo (the repo element after the deps list is
// not "hexpm") are NonRegistry — hex.pm knows nothing about them and
// must not judge their versions.

// Both checksum elements are sha256 by definition (hex.pm's registry
// format), so the parser captures whatever value sits in those positions
// and labels it itself — hex-validating in the regex let a malformed
// replacement fall out of integrity diffing entirely, so same-version
// checksum swaps to a bad-width value compared as "no change" (the
// build.zig.zon bug class, v0.6.6).
var mixHexRe = regexp.MustCompile(`^\s*"([^"]+)":\s*\{:hex,\s*:([A-Za-z0-9_]+),\s*"([^"]+)"(?:,\s*"([^"\s]*)")?`)
var mixRepoRe = regexp.MustCompile(`\],\s*"([^"]+)"(?:,\s*"([^"\s]+)")?\},?\s*$`)

func parseMixLock(p string, data []byte) (*File, error) {
	f := newFile(p, "mix.lock", Hex)
	for _, line := range strings.Split(string(data), "\n") {
		if m := mixHexRe.FindStringSubmatch(line); m != nil {
			f.add(m[2], m[3])
			// Inner checksum (4th element, sha256 of the tarball contents)
			// plus the outer checksum (last element, sha256 of the tarball)
			// when present: hex.pm tarballs are immutable per version, so
			// a same-version checksum change means the artifact moved.
			hashes := strings.ToLower(strings.TrimSpace(m[4]))
			if hashes != "" {
				hashes = "sha256:" + hashes
			}
			r := mixRepoRe.FindStringSubmatch(line)
			if r != nil && r[2] != "" {
				hashes = strings.TrimSpace(hashes + " sha256:" + strings.ToLower(r[2]))
			}
			f.setPin(m[2], m[3], hashes, "")
			if r != nil && r[1] != "hexpm" {
				f.markNonRegistry(m[2])
			}
		}
	}
	return f, nil
}

// ---- pubspec.lock (Dart / Flutter) ----
//
// packages:
//   args:
//     dependency: transitive
//     source: hosted
//     version: "2.4.2"
//
// Indentation-driven; only entries under the top-level `packages:` key count.
// Entries whose source is not `hosted` (git, path, sdk — the Flutter SDK's
// own packages report version 0.0.0) or whose hosted URL is a private
// server rather than pub.dev are marked NonRegistry: pub.dev knows nothing
// about them, so registry-backed checks must not flag them.

var pubNameRe = regexp.MustCompile(`^  ([A-Za-z0-9._-]+):\s*$`)
var pubVersionRe = regexp.MustCompile(`^    version:\s*"?([^"\s]+)"?\s*$`)
var pubSourceRe = regexp.MustCompile(`^    source:\s*"?([^"\s]+)"?\s*$`)
var pubHostedURLRe = regexp.MustCompile(`^      url:\s*"?([^"\s]+)"?\s*$`)

// Any value on the sha256 line is captured — the field is sha256 by
// spec, so a malformed-width swap must compare (and flag) within the
// algorithm instead of silently vanishing from the hash set.
var pubSha256Re = regexp.MustCompile(`^      sha256:\s*"?([^"\s]+)"?\s*$`)

func parsePubspecLock(p string, data []byte) (*File, error) {
	f := newFile(p, "pubspec.lock", Pub)
	inPackages := false
	name, version, source, hostURL, sha := "", "", "", "", ""
	flush := func() {
		if name == "" || version == "" {
			name, version, source, hostURL, sha = "", "", "", "", ""
			return
		}
		f.add(name, version)
		host := strings.TrimSuffix(hostURL, "/")
		hosted := source == "" || source == "hosted"
		public := host == "" || host == "https://pub.dev" || host == "https://pub.dartlang.org"
		if !hosted || !public {
			f.markNonRegistry(name)
		}
		if hosted {
			pinHost := HostOf(host)
			if pinHost == "" && sha != "" {
				pinHost = "pub.dev" // hosted default when no url recorded
			}
			f.setPin(name, version, withPrefixIfSet("sha256:", strings.ToLower(sha)), pinHost)
		}
		name, version, source, hostURL, sha = "", "", "", "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "packages:":
			inPackages = true
			continue
		case line != "" && line[0] != ' ': // any other top-level key (sdks:, ...)
			flush()
			inPackages = false
			continue
		}
		if !inPackages {
			continue
		}
		if m := pubNameRe.FindStringSubmatch(line); m != nil {
			flush()
			name = m[1]
			continue
		}
		if m := pubVersionRe.FindStringSubmatch(line); m != nil {
			version = m[1]
			continue
		}
		if m := pubSourceRe.FindStringSubmatch(line); m != nil {
			source = m[1]
			continue
		}
		if m := pubHostedURLRe.FindStringSubmatch(line); m != nil {
			hostURL = m[1]
			continue
		}
		if m := pubSha256Re.FindStringSubmatch(line); m != nil {
			sha = m[1]
		}
	}
	flush()
	return f, nil
}

// withPrefixIfSet prepends prefix when s is non-empty.
func withPrefixIfSet(prefix, s string) string {
	if s == "" {
		return ""
	}
	return prefix + s
}

// joinHashes space-joins the non-empty hash notations into one integrity
// set (the comparator's hashesByAlgo splits on whitespace).
func joinHashes(hs ...string) string {
	out := ""
	for _, h := range hs {
		if h == "" {
			continue
		}
		if out != "" {
			out += " "
		}
		out += h
	}
	return out
}

// ---- gradle.lockfile (Gradle dependency locking) ----
//
//	org.example:artifact:1.2.3=compileClasspath,runtimeClasspath
//
// OSV's Maven package names are "group:artifact".

var gradleLineRe = regexp.MustCompile(`^([^:=\s]+:[^:=\s]+):([^:=\s]+)=`)

func parseGradleLockfile(p string, data []byte) (*File, error) {
	f := newFile(p, "gradle.lockfile", Maven)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := gradleLineRe.FindStringSubmatch(line); m != nil {
			f.add(m[1], m[2])
		}
	}
	return f, nil
}

// ---- packages.lock.json (NuGet) ----
//
// {"version":1,"dependencies":{"net6.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.1"}}}}
// "Project" entries are local project references, not registry packages.

func parseNuGetLock(p string, data []byte) (*File, error) {
	f := newFile(p, "packages.lock.json", NuGet)
	var doc struct {
		Dependencies map[string]map[string]struct {
			Type     string `json:"type"`
			Resolved string `json:"resolved"`
		} `json:"dependencies"`
	}
	// NuGet reads this file with Newtonsoft's JsonTextReader, which accepts
	// // and /* */ comments (and trailing commas) by default — so a
	// hand-annotated packages.lock.json restores fine but would fail here
	// under strict JSON. Same class of bug as the commented-bun.lock fix;
	// strict machine-generated files pass through stripJSONC unchanged.
	if err := json.Unmarshal(stripJSONC(data), &doc); err != nil {
		return nil, err
	}
	for _, framework := range doc.Dependencies {
		for name, pkg := range framework {
			if strings.EqualFold(pkg.Type, "Project") || pkg.Resolved == "" {
				continue
			}
			f.add(name, pkg.Resolved)
			// NOTE: contentHash is deliberately NOT recorded. NuGet's 2018
			// repository-resigning changed the contentHash of every package
			// published before it, so old lockfiles legitimately disagree
			// with regenerated ones (seen live on runtime.native.* 4.3.0).
		}
	}
	return f, nil
}

// ---- Package.resolved (Swift Package Manager) ----
//
// v2/v3: {"pins":[{"identity":..,"location":"https://github.com/a/b.git","state":{"version":"1.2.3"}}]}
// v1:    {"object":{"pins":[{"package":..,"repositoryURL":..,"state":{"version":..}}]}}
// OSV's SwiftURL package names are the repo URL without scheme or .git suffix.

type swiftPin struct {
	Location      string `json:"location"`
	RepositoryURL string `json:"repositoryURL"`
	State         struct {
		Version  string `json:"version"`
		Revision string `json:"revision"`
	} `json:"state"`
}

func parseSwiftResolved(p string, data []byte) (*File, error) {
	f := newFile(p, "Package.resolved", SwiftURL)
	var doc struct {
		Pins   []swiftPin `json:"pins"`
		Object struct {
			Pins []swiftPin `json:"pins"`
		} `json:"object"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	pins := doc.Pins
	if len(pins) == 0 {
		pins = doc.Object.Pins
	}
	for _, pin := range pins {
		url := pin.Location
		if url == "" {
			url = pin.RepositoryURL
		}
		name := swiftURLName(url)
		f.add(name, pin.State.Version)
		// The pinned commit for the version's tag. A same-version revision
		// change means the upstream tag was moved — released tags are
		// supposed to be immutable.
		if pin.State.Version != "" && pin.State.Revision != "" {
			f.setPin(name, pin.State.Version,
				"commit:"+strings.ToLower(pin.State.Revision), "")
		}
	}
	return f, nil
}

func swiftURLName(url string) string {
	url = strings.TrimSuffix(strings.TrimSpace(url), "/")
	url = strings.TrimSuffix(url, ".git")
	for _, prefix := range []string{"https://", "http://", "ssh://", "git@"} {
		url = strings.TrimPrefix(url, prefix)
	}
	return strings.Replace(url, ":", "/", 1) // git@host:org/repo -> host/org/repo
}
