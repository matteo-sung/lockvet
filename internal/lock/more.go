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
	for _, section := range []string{"default", "develop"} {
		raw, ok := doc[section]
		if !ok {
			continue
		}
		var pkgs map[string]struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(raw, &pkgs); err != nil {
			continue // section may hold non-package metadata in odd files
		}
		for name, pkg := range pkgs {
			f.add(normalizePyPI(name), strings.TrimPrefix(pkg.Version, "=="))
		}
	}
	return f, nil
}

// ---- mix.lock (Elixir / Hex) ----
//
//	"phoenix": {:hex, :phoenix, "1.7.10", "aaaaaaaa...", [:mix], [...], "hexpm", "bbbb..."},
//
// Only :hex entries carry a registry version; :git/:path entries are skipped.

var mixHexRe = regexp.MustCompile(`^\s*"([^"]+)":\s*\{:hex,\s*:[^,]+,\s*"([^"]+)"`)

func parseMixLock(p string, data []byte) (*File, error) {
	f := newFile(p, "mix.lock", Hex)
	for _, line := range strings.Split(string(data), "\n") {
		if m := mixHexRe.FindStringSubmatch(line); m != nil {
			f.add(m[1], m[2])
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

var pubNameRe = regexp.MustCompile(`^  ([A-Za-z0-9._-]+):\s*$`)
var pubVersionRe = regexp.MustCompile(`^    version:\s*"?([^"\s]+)"?\s*$`)

func parsePubspecLock(p string, data []byte) (*File, error) {
	f := newFile(p, "pubspec.lock", Pub)
	inPackages := false
	name := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "packages:":
			inPackages = true
			continue
		case line != "" && line[0] != ' ': // any other top-level key (sdks:, ...)
			inPackages = false
			continue
		}
		if !inPackages {
			continue
		}
		if m := pubNameRe.FindStringSubmatch(line); m != nil {
			name = m[1]
			continue
		}
		if m := pubVersionRe.FindStringSubmatch(line); m != nil && name != "" {
			f.add(name, m[1])
			name = ""
		}
	}
	return f, nil
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
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	for _, framework := range doc.Dependencies {
		for name, pkg := range framework {
			if strings.EqualFold(pkg.Type, "Project") || pkg.Resolved == "" {
				continue
			}
			f.add(name, pkg.Resolved)
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
		Version string `json:"version"`
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
		f.add(swiftURLName(url), pin.State.Version)
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
