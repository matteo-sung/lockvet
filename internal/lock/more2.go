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
//
// Only top-level entries (two-space indent) carry resolved versions;
// deeper lines are dependency *requirements*, not pins. Subspecs like
// Firebase/Core resolve to the parent pod's version; OSV advisories use
// the base pod name, so we record that.

var podLineRe = regexp.MustCompile(`^  - "?([^" (]+)"? \(([^()]+)\)`)

func parsePodfileLock(p string, data []byte) (*File, error) {
	f := newFile(p, "Podfile.lock", CocoaPods)
	inPods := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if trimmed == "PODS:" {
			inPods = true
			continue
		}
		if inPods && len(trimmed) > 0 && trimmed[0] != ' ' {
			break // next top-level section (DEPENDENCIES:, SPEC REPOS:, ...)
		}
		if !inPods {
			continue
		}
		if m := podLineRe.FindStringSubmatch(trimmed); m != nil {
			name := m[1]
			if i := strings.IndexByte(name, '/'); i > 0 {
				name = name[:i] // subspec -> base pod
			}
			f.add(name, m[2])
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
	for key := range npm {
		if name, ver, ok := denoKey(key); ok {
			f.add(name, ver)
		}
	}
	for key := range jsr {
		if name, ver, ok := denoKey(key); ok {
			f.add("jsr:"+name, ver)
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
