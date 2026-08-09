package lock

import (
	"encoding/json"
	"sort"
	"strings"
)

// parseConanLock parses Conan lockfiles (conan.lock).
//
// Conan 2.x lockfiles ("version": "0.4"/"0.5") are flat JSON arrays of
// pinned references — requires, build_requires, python_requires,
// config_requires — each of the shape
//
//	name/version[@user/channel][#recipe-revision][%timestamp]
//
// ConanCenter references carry no user/channel; a reference WITH
// user/channel comes from a private remote or a local export, so those
// packages are marked NonRegistry and never checked against ConanCenter.
// The flat format records no dependency graph.
//
// The #recipe-revision is recorded as an integrity pin ("rrev:<hex>"):
// the revision hashes the RECIPE — the build script Conan will run — so
// a same-version revision change is the recipe's bytes changing under an
// unchanged version. Recipes get re-exported legitimately all the time
// (conan-center-index maintains recipes independently of upstream
// releases), so diffx renders that change NEUTRALLY like a container
// same-tag digest bump, not as an integrity alarm — visible, not loud.
//
// Conan 1.x lockfiles keep a "graph_lock" object with numbered nodes and
// per-node requires edges; node "0" is the consumer project, so its
// requires are the direct dependencies and the edges give via-chains.
func parseConanLock(path string, data []byte) (*File, error) {
	f := newFile(path, "conan.lock", Conan)

	var v2 struct {
		Version        string   `json:"version"`
		Requires       []string `json:"requires"`
		BuildRequires  []string `json:"build_requires"`
		PythonRequires []string `json:"python_requires"`
		ConfigRequires []string `json:"config_requires"`
		GraphLock      *struct {
			Nodes map[string]struct {
				Ref      string   `json:"ref"`
				Requires []string `json:"requires"`
				Path     string   `json:"path"`
			} `json:"nodes"`
		} `json:"graph_lock"`
	}
	if err := json.Unmarshal(data, &v2); err != nil {
		return nil, err
	}

	if v2.GraphLock != nil && len(v2.GraphLock.Nodes) > 0 {
		// Conan 1.x graph lock: refs plus a real dependency graph.
		nameOf := map[string]string{}
		ids := make([]string, 0, len(v2.GraphLock.Nodes))
		for id := range v2.GraphLock.Nodes {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			n := v2.GraphLock.Nodes[id]
			if n.Ref == "" {
				continue // consumer project node
			}
			name, ver, rrev, nonReg := splitConanRef(n.Ref)
			if name == "" || ver == "" {
				continue
			}
			f.add(name, ver)
			nameOf[id] = name
			if rrev != "" {
				f.setPin(name, ver, "rrev:"+rrev, "")
			}
			if nonReg {
				f.markNonRegistry(name)
			}
		}
		for _, id := range ids {
			n := v2.GraphLock.Nodes[id]
			from := nameOf[id]
			for _, to := range n.Requires {
				if from == "" {
					// consumer node: its requires are the roots.
					if r := nameOf[to]; r != "" {
						f.addRoot(r)
					}
					continue
				}
				if t := nameOf[to]; t != "" {
					f.addEdge(from, t)
				}
			}
		}
		return f, nil
	}

	for _, list := range [][]string{v2.Requires, v2.BuildRequires, v2.PythonRequires, v2.ConfigRequires} {
		for _, ref := range list {
			name, ver, rrev, nonReg := splitConanRef(ref)
			if name == "" || ver == "" {
				continue
			}
			f.add(name, ver)
			if rrev != "" {
				f.setPin(name, ver, "rrev:"+rrev, "")
			}
			if nonReg {
				f.markNonRegistry(name)
			}
		}
	}
	return f, nil
}

// splitConanRef splits "name/version[@user/channel][#rrev][%ts]" and
// reports whether the reference names a user/channel (i.e. does not come
// from ConanCenter, whose references never carry one). The recipe
// revision is returned lowercased when it is hash-shaped (Conan writes
// an md5 or sha256 hex digest); anything else comes back empty so a
// hostile file cannot inject arbitrary strings into the pin set.
func splitConanRef(ref string) (name, version, rrev string, nonRegistry bool) {
	if i := strings.IndexByte(ref, '%'); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.IndexByte(ref, '#'); i >= 0 {
		rrev = strings.ToLower(strings.TrimSpace(ref[i+1:]))
		if !conanRevShaped(rrev) {
			rrev = ""
		}
		ref = ref[:i]
	}
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		// "@_/_" is Conan's spelling of "no user/channel".
		if uc := ref[i+1:]; uc != "_/_" && uc != "" {
			nonRegistry = true
		}
		ref = ref[:i]
	}
	name, version, ok := strings.Cut(ref, "/")
	if !ok || strings.Contains(version, "/") {
		return "", "", "", false
	}
	return strings.TrimSpace(name), strings.TrimSpace(version), rrev, nonRegistry
}

// conanRevShaped reports whether s looks like a Conan recipe revision:
// a hex digest (md5 = 32, sha1 = 40, sha256 = 64; ≥ 8 tolerated for
// truncated forms seen in tooling output).
func conanRevShaped(s string) bool {
	if len(s) < 8 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
