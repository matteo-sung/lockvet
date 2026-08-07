package lock

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ---- Podfile.lock (CocoaPods) ----
//
// PODS:
//   - Alamofire (5.4.4)
//   - Firebase/Core (8.9.0):
//     - FirebaseCore (= 8.9.0)
// DEPENDENCIES:
//   - Alamofire (~> 5.4)
// SPEC REPOS:
//   trunk:
//     - Alamofire
// EXTERNAL SOURCES:
//   LocalPod:
//     :path: "../LocalPod"
//
// Only top-level PODS entries (two-space indent) carry resolved versions;
// deeper lines are dependency *requirements*, not pins — but they name the
// dependencies, so they build the via-chain graph. Subspecs like
// Firebase/Core resolve to the parent pod's version; OSV advisories and
// the trunk registry use the base pod name, so everything collapses to
// that. DEPENDENCIES lists the Podfile's own pods (roots). Pods pinned
// from git/path (EXTERNAL SOURCES) or served by a private specs repo
// (any SPEC REPOS key besides trunk / the legacy CocoaPods/Specs mirror)
// are NonRegistry: registry-metadata checks skip them.

var (
	podLineRe     = regexp.MustCompile(`^  - "?([^" (]+)"? \(([^()]+)\)`)
	podDepRe      = regexp.MustCompile(`^ {4,}- "?([^" (]+)"?`)
	podEntryRe    = regexp.MustCompile(`^  - "?([^" (]+)"?`)
	podSrcKeyRe   = regexp.MustCompile(`^  "?([^"]+?)"?:\s*$`)
	podChecksumRe = regexp.MustCompile(`^  "?([^":]+?)"?:\s*([0-9a-fA-F]{40})\s*$`)
	podSrcPodRe   = regexp.MustCompile(`^ {4}- "?([^" (]+)"?`)
	podExtKeyRe   = regexp.MustCompile(`^  "?([^"]+?)"?:\s*$`)
	podPublicSrc  = regexp.MustCompile(`(?i)^(trunk|.*github\.com[:/]cocoapods/specs.*)$`)
)

// twoSpaceIndent reports whether the line is indented by exactly two
// spaces (a section key), not deeper (a nested attribute or list item).
func twoSpaceIndent(s string) bool {
	return strings.HasPrefix(s, "  ") && len(s) > 2 && s[2] != ' '
}

// podBase collapses a subspec (Firebase/Core) to its base pod (Firebase).
func podBase(name string) string {
	if i := strings.IndexByte(name, '/'); i > 0 {
		return name[:i]
	}
	return name
}

func parsePodfileLock(p string, data []byte) (*File, error) {
	f := newFile(p, "Podfile.lock", CocoaPods)
	section := ""
	parent := ""      // current top-level pod in PODS
	srcPublic := true // whether the current SPEC REPOS key is the public registry
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if len(trimmed) > 0 && trimmed[0] != ' ' {
			section = strings.TrimSuffix(trimmed, ":")
			parent = ""
			continue
		}
		switch section {
		case "PODS":
			if m := podLineRe.FindStringSubmatch(trimmed); m != nil {
				parent = podBase(m[1])
				f.add(parent, m[2])
			} else if m := podDepRe.FindStringSubmatch(trimmed); m != nil && parent != "" {
				f.addEdge(parent, podBase(m[1]))
			}
		case "DEPENDENCIES":
			if m := podEntryRe.FindStringSubmatch(trimmed); m != nil {
				f.addRoot(podBase(m[1]))
			}
		case "SPEC REPOS":
			if m := podSrcPodRe.FindStringSubmatch(trimmed); m != nil {
				if !srcPublic {
					f.markNonRegistry(podBase(m[1]))
				}
			} else if twoSpaceIndent(trimmed) {
				if m := podSrcKeyRe.FindStringSubmatch(trimmed); m != nil {
					srcPublic = podPublicSrc.MatchString(m[1])
				}
			}
		case "EXTERNAL SOURCES":
			if twoSpaceIndent(trimmed) {
				if m := podExtKeyRe.FindStringSubmatch(trimmed); m != nil {
					f.markNonRegistry(podBase(m[1]))
				}
			}
		case "SPEC CHECKSUMS":
			// "  Alamofire: 02b66283...40hex" — SHA-1 of the resolved
			// podspec. Applied to the version pinned in PODS above; a
			// same-version checksum change means the published spec (and
			// so what it downloads) was altered under an existing version.
			if m := podChecksumRe.FindStringSubmatch(trimmed); m != nil {
				name := Sanitize(m[1])
				if f.NonRegistry[name] {
					// Local development pods (Flutter/React-Native plugin
					// pods via :path, git pins) re-hash whenever their
					// podspec is edited — only trunk pods are immutable.
					continue
				}
				for _, v := range f.Packages[name] {
					f.setPin(name, v, strings.ToLower(m[2]), "")
				}
			}
		}
	}
	return f, nil
}

// ---- deno.lock (Deno) ----
//
// v3: {"version":"3","packages":{"jsr":{"@std/path@1.0.0":{}},"npm":{"chalk@5.3.0":{}}}}
// v4+: {"version":"4","jsr":{"@std/assert@1.0.5":{}},"npm":{"chalk@5.3.0":{}}}
//
// npm entries are queried against OSV's npm ecosystem; JSR has no OSV
// ecosystem yet, so jsr entries are tracked with a "jsr:" prefix (diffed
// and explained, no vuln data).

func parseDenoLock(p string, data []byte) (*File, error) {
	f := newFile(p, "deno.lock", NPM)
	var doc struct {
		NPM      map[string]json.RawMessage `json:"npm"`
		JSR      map[string]json.RawMessage `json:"jsr"`
		Packages struct {
			NPM map[string]json.RawMessage `json:"npm"`
			JSR map[string]json.RawMessage `json:"jsr"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	npm, jsr := doc.NPM, doc.JSR
	if len(npm) == 0 && len(jsr) == 0 {
		npm, jsr = doc.Packages.NPM, doc.Packages.JSR
	}
	pin := func(name, ver string, raw json.RawMessage) {
		var meta struct {
			Integrity string `json:"integrity"`
		}
		if json.Unmarshal(raw, &meta) == nil && meta.Integrity != "" {
			f.setPin(name, ver, meta.Integrity, "")
		}
	}
	for key, raw := range npm {
		if name, ver, ok := denoKey(key); ok {
			f.add(name, ver)
			pin(name, ver, raw)
		}
	}
	for key, raw := range jsr {
		if name, ver, ok := denoKey(key); ok {
			f.add("jsr:"+name, ver)
			pin("jsr:"+name, ver, raw)
		}
	}
	return f, nil
}

// denoKey splits "name@1.2.3" / "@scope/name@1.2.3", dropping any
// "_peer@x" suffix Deno appends for peer-dependency duplicates.
// Note: npm names may contain '_' (string_decoder) but versions may not,
// so the peer suffix is cut after the name/version split, not before.
func denoKey(key string) (name, version string, ok bool) {
	name, version = splitNameAtVersion(key)
	if j := strings.IndexByte(version, '_'); j >= 0 {
		version = version[:j]
	}
	return name, version, name != "" && version != ""
}

// ---- flake.lock (Nix) ----
//
// {"nodes":{"nixpkgs":{"locked":{"lastModified":1720000000,"rev":"abc...",
//  "owner":"NixOS","repo":"nixpkgs","type":"github"}},"root":{...}},
//  "root":"root","version":7}
//
// Flake inputs pin git revisions, not versions. lockvet reports each input
// as "<commit-date>.<short-rev>" so the diff reads chronologically:
// upgraded/downgraded is judged by commit date, and levels are suppressed
// (no semver in Nix).

func parseFlakeLock(p string, data []byte) (*File, error) {
	f := newFile(p, "flake.lock", Nix)
	var doc struct {
		Nodes map[string]struct {
			Locked struct {
				Rev          string `json:"rev"`
				Ref          string `json:"ref"`
				NarHash      string `json:"narHash"`
				LastModified int64  `json:"lastModified"`
			} `json:"locked"`
		} `json:"nodes"`
		Root string `json:"root"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	for name, node := range doc.Nodes {
		if name == doc.Root {
			continue // the root node is the flake itself
		}
		l := node.Locked
		id := l.Rev
		if id == "" {
			id = strings.TrimPrefix(l.NarHash, "sha256-")
		}
		if len(id) > 8 {
			id = id[:8]
		}
		var ver string
		switch {
		case l.LastModified > 0 && id != "":
			ver = fmt.Sprintf("%s.%s", time.Unix(l.LastModified, 0).UTC().Format("2006-01-02"), id)
		case l.LastModified > 0:
			ver = time.Unix(l.LastModified, 0).UTC().Format("2006-01-02")
		case id != "":
			ver = id
		default:
			continue // follows-only node without its own pin
		}
		f.add(name, ver)
	}
	return f, nil
}

// ---- renv.lock (R) ----
//
// renv's lockfile is JSON: {"R": {...}, "Packages": {"dplyr": {"Package":
// "dplyr", "Version": "1.1.4", "Source": "Repository", "Repository":
// "CRAN", "Requirements": ["cli", "generics", ...]}}}.
//
// Bioconductor packages carry Source/Repository "Bioconductor" and are
// queried against OSV's Bioconductor ecosystem via File.PkgEco; everything
// else (CRAN, RSPM, GitHub remotes of CRAN packages) uses CRAN.
// Requirements name base R packages ("R", "utils", ...) that never appear
// in Packages; edges are only recorded between locked packages.
// R versions use '-' as a component separator ("1.8-4"); vers treats the
// suffix as a comparable alnum run, which orders and classifies dash
// bumps correctly (1.8-2 -> 1.8-4 = patch).

// renvNA replaces bare NA tokens with null: real-world renv.lock files
// sometimes carry R's missing value serialized unquoted ("OS_type": NA),
// which is not valid JSON. Strings are left untouched.
func renvNA(data []byte) []byte {
	out := make([]byte, 0, len(data))
	inStr := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inStr {
			out = append(out, c)
			if c == '\\' && i+1 < len(data) {
				i++
				out = append(out, data[i])
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
			out = append(out, c)
			continue
		}
		if c == 'N' && i+1 < len(data) && data[i+1] == 'A' &&
			(i == 0 || !isAlnumByte(data[i-1])) &&
			(i+2 >= len(data) || !isAlnumByte(data[i+2])) {
			out = append(out, "null"...)
			i++
			continue
		}
		out = append(out, c)
	}
	return out
}

func isAlnumByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func parseRenvLock(p string, data []byte) (*File, error) {
	data = renvNA(data)
	var doc struct {
		Packages map[string]struct {
			Package      string   `json:"Package"`
			Version      string   `json:"Version"`
			Source       string   `json:"Source"`
			Repository   string   `json:"Repository"`
			Requirements []string `json:"Requirements"`
		} `json:"Packages"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	f := newFile(p, "renv.lock", CRAN)
	for key, pkg := range doc.Packages {
		name := pkg.Package
		if name == "" {
			name = key
		}
		if pkg.Version == "" {
			continue
		}
		f.add(name, pkg.Version)
		if strings.EqualFold(pkg.Source, "Bioconductor") ||
			strings.EqualFold(pkg.Repository, "Bioconductor") {
			if f.PkgEco == nil {
				f.PkgEco = map[string]Ecosystem{}
			}
			f.PkgEco[Sanitize(name)] = Bioconductor
		}
	}
	for key, pkg := range doc.Packages {
		name := pkg.Package
		if name == "" {
			name = key
		}
		for _, req := range pkg.Requirements {
			if _, locked := doc.Packages[req]; locked {
				f.addEdge(name, req)
			}
		}
	}
	return f, nil
}
