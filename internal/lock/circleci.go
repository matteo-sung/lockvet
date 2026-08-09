package lock

// CircleCI configuration pins dependencies too — format #48. Two kinds
// of pins live in .circleci/config.yml:
//
//   - `orbs:` map entries — `node: circleci/node@5.1.0` — pin reusable
//     CI packages from the CircleCI orb registry. Published orb
//     versions are immutable and the orb's commands RUN in every
//     pipeline, so the pins get the registry treatment
//     (internal/orbreg: ages, registry-verified unlisted versions,
//     source repositories). Floating pins (`volatile`, `5`, `5.1`)
//     resolve to the release they fetch today. `dev:*` versions are
//     mutable-by-design and expire — claim-free (NonRegistry).
//     Inline orb definitions (a mapping, not a scalar ref) pin nothing.
//   - docker executor `- image:` entries are container pulls the
//     runner performs — they get the Dockerfile registry treatment
//     (internal/ocireg). `machine:` executor images are CircleCI VM
//     image labels, not OCI refs, and are skipped.
//
// The registry queried is circleci.com's. Self-hosted CircleCI Server
// installs keep their own orb store, but private Server orbs live in
// namespaces the public registry answers null for — and a null orb
// makes no claims — so the honest failure mode is silence, not a
// false flag.
//
// Discovery: any *.yml / *.yaml under a .circleci/ directory segment.
// config.yml is the reserved entrypoint and parses ungated; other
// files there (continuation configs, fragments) sit behind a CI-shape
// gate (jobs:, workflows:, orbs:, executors:, or version: 2.x) so
// unrelated YAML stays silent.

import "strings"

// isCircleCIPath reports whether p is a *.yml/*.yaml file under a
// .circleci/ directory segment.
func isCircleCIPath(p string) bool {
	q := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	if !strings.HasSuffix(q, ".yml") && !strings.HasSuffix(q, ".yaml") {
		return false
	}
	for _, seg := range strings.Split(q, "/") {
		if seg == ".circleci" {
			return true
		}
	}
	return false
}

// parseCircleCI parses .circleci/config.yml (ungated).
func parseCircleCI(p string, data []byte) (*File, error) {
	return scanCircleCI(p, data, false), nil
}

// circleCILenient parses other YAML under .circleci/ (continuation
// configs, fragments): only files shaped like CircleCI configuration
// produce rows.
func circleCILenient(p string, data []byte) (*File, error) {
	return scanCircleCI(p, data, true), nil
}

func scanCircleCI(p string, data []byte, gated bool) *File {
	f := newFile(p, "circleci", Docker)
	type pathEnt struct {
		indent int
		key    string
	}
	var kpath []pathEnt
	top := func() string {
		if len(kpath) == 0 {
			return ""
		}
		return kpath[len(kpath)-1].key
	}

	sawCI := false
	blockSkip := -1
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue // blank lines never close a block scalar
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if blockSkip >= 0 {
			if indent > blockSkip {
				continue
			}
			blockSkip = -1
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == "---" || strings.HasPrefix(trimmed, "--- ") {
			kpath = kpath[:0]
			continue
		}
		isItem := trimmed == "-" || strings.HasPrefix(trimmed, "- ")
		for len(kpath) > 0 && kpath[len(kpath)-1].indent >= indent {
			kpath = kpath[:len(kpath)-1]
		}
		if isItem {
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			// A block scalar opened by a list item (- run: |) is opaque.
			if rest != "" && (rest[0] == '|' || rest[0] == '>') &&
				strings.TrimLeft(rest[1:], "+-0123456789") == "" {
				blockSkip = indent
				continue
			}
			if top() == "docker" {
				// `- image: cimg/node:18.16` — a docker executor entry.
				if v, ok := yamlKeyValue(rest, "image"); ok && !templated(v) {
					addImageRef(f, v, nil)
				}
			}
			continue
		}
		key, val, ok := strings.Cut(trimmed, ":")
		if !ok || strings.Contains(strings.TrimSpace(key), " ") {
			continue
		}
		k := strings.Trim(strings.TrimSpace(key), `"'`)
		v := strings.TrimSpace(val)
		if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		if strings.HasPrefix(v, "&") {
			if _, rest, ok := strings.Cut(v, " "); ok {
				v = strings.TrimSpace(rest)
			} else {
				v = ""
			}
		}
		if strings.HasPrefix(v, "*") {
			v = ""
		}
		// Block scalar body (command: |) is opaque — an image: line in
		// an embedded shell script is not a pin.
		if v != "" && (v[0] == '|' || v[0] == '>') &&
			strings.TrimLeft(v[1:], "+-0123456789") == "" {
			blockSkip = indent
			continue
		}

		if len(kpath) == 0 {
			switch k {
			case "jobs", "workflows", "orbs", "executors":
				sawCI = true
			case "version":
				if v == "2" || v == "2.0" || v == "2.1" {
					sawCI = true
				}
			}
		}

		if v == "" {
			kpath = append(kpath, pathEnt{indent, k})
			continue
		}
		v = strings.Trim(v, `"'`)
		switch {
		case len(kpath) == 1 && kpath[0].key == "orbs":
			addCircleOrb(f, v)
		case k == "image" && top() == "docker" && !templated(v):
			// Mapping form under a docker item continuation is rare but
			// harmless; machine: images never satisfy top()=="docker".
			addImageRef(f, v, nil)
		}
	}
	if gated && !sawCI {
		return newFile(p, "circleci", Docker)
	}
	rootsFromPackages(f)
	return f
}

// templated reports whether a value carries CircleCI parameter or
// environment templating and therefore cannot be resolved statically.
func templated(v string) bool {
	return strings.Contains(v, "<<") || strings.Contains(v, "$")
}

// addCircleOrb records one `alias: namespace/orb@version` reference.
func addCircleOrb(f *File, ref string) {
	ref = yamlScalar(ref)
	if ref == "" || strings.ContainsAny(ref, " \t") || templated(ref) {
		return
	}
	at := strings.LastIndexByte(ref, '@')
	if at <= 0 || at == len(ref)-1 {
		return
	}
	name, ver := ref[:at], ref[at+1:]
	ns, orb, ok := strings.Cut(name, "/")
	if !ok || ns == "" || orb == "" || strings.Contains(orb, "/") {
		return
	}
	f.add(name, ver)
	if f.PkgEco == nil {
		f.PkgEco = map[string]Ecosystem{}
	}
	f.PkgEco[Sanitize(name)] = CircleCI
	if strings.HasPrefix(ver, "dev:") {
		// Dev versions are mutable and expire after 90 days — nothing
		// registry-verifiable about them.
		f.markNonRegistry(name)
	}
}
