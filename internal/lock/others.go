package lock

import (
	"encoding/json"
	"regexp"
	"strings"
)

// ---- TOML [[package]] blocks: Cargo.lock, uv.lock, poetry.lock ----
//
// All three formats pin packages as:
//   [[package]]
//   name = "foo"
//   version = "1.2.3"
// A full TOML parser is unnecessary for this shape.

var tomlKVRe = regexp.MustCompile(`^(name|version)\s*=\s*"([^"]*)"\s*$`)

func parseTOMLPackages(kind string, eco Ecosystem) func(string, []byte) (*File, error) {
	return func(p string, data []byte) (*File, error) {
		f := newFile(p, kind, eco)
		var name, version string
		inPackage := false
		flush := func() {
			if inPackage {
				f.add(name, version)
			}
			name, version = "", ""
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "[") { // any new table/array-of-tables
				flush()
				inPackage = line == "[[package]]"
				continue
			}
			if !inPackage {
				continue
			}
			if m := tomlKVRe.FindStringSubmatch(line); m != nil {
				if m[1] == "name" {
					name = m[2]
				} else {
					version = m[2]
				}
			}
		}
		flush()
		return f, nil
	}
}

// ---- requirements.txt (only exact `==` pins) ----

var reqLineRe = regexp.MustCompile(`^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.!+*_-]+)`)

func parseRequirementsTxt(p string, data []byte) (*File, error) {
	f := newFile(p, "requirements.txt", PyPI)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if i := strings.IndexByte(line, ';'); i >= 0 { // env markers
			line = strings.TrimSpace(line[:i])
		}
		if m := reqLineRe.FindStringSubmatch(line); m != nil {
			f.add(normalizePyPI(m[1]), m[2])
		}
	}
	return f, nil
}

// normalizePyPI lowercases and collapses ._- to - per PEP 503.
var pypiSepRe = regexp.MustCompile(`[-_.]+`)

func normalizePyPI(name string) string {
	return pypiSepRe.ReplaceAllString(strings.ToLower(name), "-")
}

// ---- go.mod ----

func parseGoMod(p string, data []byte) (*File, error) {
	f := newFile(p, "go.mod", Go)
	inRequire := false
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		switch {
		case line == "require (":
			inRequire = true
			continue
		case inRequire && line == ")":
			inRequire = false
			continue
		}
		fields := strings.Fields(line)
		if inRequire && len(fields) == 2 {
			f.add(fields[0], strings.TrimPrefix(fields[1], "v"))
		} else if len(fields) == 3 && fields[0] == "require" {
			f.add(fields[1], strings.TrimPrefix(fields[2], "v"))
		}
	}
	return f, nil
}

// ---- composer.lock ----

func parseComposerLock(p string, data []byte) (*File, error) {
	f := newFile(p, "composer.lock", Packagist)
	var doc struct {
		Packages    []struct{ Name, Version string } `json:"packages"`
		PackagesDev []struct{ Name, Version string } `json:"packages-dev"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	for _, pkg := range append(doc.Packages, doc.PackagesDev...) {
		f.add(pkg.Name, strings.TrimPrefix(pkg.Version, "v"))
	}
	return f, nil
}

// ---- Gemfile.lock ----

var gemSpecRe = regexp.MustCompile(`^    ([A-Za-z0-9._-]+) \(([0-9][^)]*)\)\s*$`)

func parseGemfileLock(p string, data []byte) (*File, error) {
	f := newFile(p, "Gemfile.lock", RubyGems)
	inSpecs := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.TrimSpace(line) == "specs:":
			inSpecs = true
			continue
		case line != "" && line[0] != ' ': // new top-level section (GEM, PLATFORMS, ...)
			inSpecs = false
			continue
		}
		if !inSpecs {
			continue
		}
		if m := gemSpecRe.FindStringSubmatch(line); m != nil {
			f.add(m[1], m[2])
		}
	}
	return f, nil
}
