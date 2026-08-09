package lock

// GitLab CI configuration pins dependencies too — format #47. Two kinds
// of pins live in .gitlab-ci.yml:
//
//   - `include: component:` references CI/CD Catalog components at an
//     exact version — `gitlab.com/comp/proj/name@2.0.1`. The version is
//     a tag, commit SHA, branch, `~latest`, or a semver range shorthand
//     (`2`, `2.0` → the latest matching release). Renovate's gitlabci
//     manager bumps these pins like lockfile entries, and the component's
//     code RUNS in every pipeline — the tj-actions attack shape applies
//     verbatim. lockvet verifies each pin against the component project's
//     real tags (internal/actreg, the GitHub Actions machinery).
//   - job / default `image:` and `services:` refs are container pulls
//     the runner performs — they get the Dockerfile registry treatment
//     (internal/ocireg: digest-vs-tag, unknown tags, ages).
//
// `include: project:` + `ref:` pins are tracked as version rows but stay
// claim-free (NonRegistry): the include names a project on the SAME
// GitLab instance as the pipeline, and the instance's host is not
// recorded in the file — resolving the path against gitlab.com could
// verify (or accuse) the wrong project entirely.
//
// Discovery: .gitlab-ci.yml / .gitlab-ci.yaml by basename (plus
// suffix-named variants like backend.gitlab-ci.yml), and *.yml files
// under a .gitlab/ directory — the conventional home for included CI
// fragments — behind a CI-shape gate (the file must carry stages:,
// include:, workflow:, default:, or a script: key) so issue-template
// and agent-config YAML stays silent.

import "strings"

// parseGitLabCI parses a reserved-basename GitLab CI file.
func parseGitLabCI(p string, data []byte) (*File, error) {
	return scanGitLabCI(p, data, false), nil
}

// gitlabCILenient parses a .gitlab/-directory YAML file: only files
// shaped like CI configuration produce rows, everything else parses to
// an empty file so audit walks stay quiet.
func gitlabCILenient(p string, data []byte) (*File, error) {
	return scanGitLabCI(p, data, true), nil
}

// isGitLabCIPath reports whether p is a *.yml/*.yaml file under a
// .gitlab/ directory segment (included CI fragments conventionally live
// in .gitlab/ci/).
func isGitLabCIPath(p string) bool {
	q := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	if !strings.HasSuffix(q, ".yml") && !strings.HasSuffix(q, ".yaml") {
		return false
	}
	for _, seg := range strings.Split(q, "/") {
		if seg == ".gitlab" || seg == ".gitlab-ci" {
			// .gitlab/ci/ is the conventional fragment home; a .gitlab-ci/
			// directory is the other common layout (mesa, fdo projects).
			return true
		}
	}
	return false
}

func scanGitLabCI(p string, data []byte, gated bool) *File {
	f := newFile(p, "gitlab-ci", Docker)
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

	// Pending include:-list item (project includes span several lines).
	var incl struct {
		active       bool
		project, ref string
	}
	flushIncl := func() {
		if incl.active {
			addGitLabProjectInclude(f, incl.project, incl.ref)
		}
		incl.active = false
		incl.project, incl.ref = "", ""
	}

	sawCI := false // CI-shape gate for lenient files

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
			flushIncl()
			kpath = kpath[:0]
			continue
		}
		isItem := trimmed == "-" || strings.HasPrefix(trimmed, "- ")
		for len(kpath) > 0 && kpath[len(kpath)-1].indent >= indent {
			if top() == "include" {
				flushIncl()
			}
			kpath = kpath[:len(kpath)-1]
		}
		underInclude := len(kpath) > 0 && kpath[0].key == "include"
		if isItem {
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			// A block scalar opened by a list item (script: - |) is
			// opaque, exactly like one opened by a key.
			if rest != "" && (rest[0] == '|' || rest[0] == '>') &&
				strings.TrimLeft(rest[1:], "+-0123456789") == "" {
				blockSkip = indent
				continue
			}
			switch {
			case top() == "services":
				// `- postgres:16` or `- name: postgres:16`.
				if v, ok := yamlKeyValue(rest, "name"); ok {
					addImageRef(f, v, nil)
				} else if rest != "" && !strings.Contains(rest, ": ") &&
					!strings.HasSuffix(rest, ":") {
					addImageRef(f, yamlScalar(rest), nil)
				}
			case underInclude:
				flushIncl() // a new include list item begins
				if v, ok := yamlKeyValue(rest, "component"); ok {
					addGitLabComponent(f, v)
				} else if v, ok := yamlKeyValue(rest, "project"); ok {
					incl.active, incl.project = true, yamlScalar(v)
				} else if rest != "" && strings.Contains(rest, ":") &&
					!strings.HasPrefix(rest, "'") && !strings.HasPrefix(rest, `"`) {
					// - local:/- template:/- remote: — nothing to pin;
					// keep the item open so its sub-keys are consumed.
					incl.active = true
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
		// Anchors/aliases, same rules as the values-file scanner.
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
		// Block scalar body (script: |) is opaque — an `image:` line in
		// an embedded shell script or config blob is not a pin.
		if v != "" && (v[0] == '|' || v[0] == '>') &&
			strings.TrimLeft(v[1:], "+-0123456789") == "" {
			blockSkip = indent
			continue
		}

		if len(kpath) == 0 {
			switch k {
			case "stages", "include", "workflow", "default":
				sawCI = true
			}
		}
		switch k {
		case "script", "before_script", "after_script":
			sawCI = true
		}

		if v == "" {
			kpath = append(kpath, pathEnt{indent, k})
			continue
		}
		v = strings.Trim(v, `"'`)
		switch {
		case k == "image" && !underInclude && top() != "variables":
			// `variables:` blocks can define a lowercase `image` variable;
			// everywhere else a scalar image: is a pull the runner performs.
			addImageRef(f, v, nil)
		case k == "name" && top() == "image":
			addImageRef(f, v, nil)
		case underInclude && incl.active && k == "ref":
			incl.ref = v
		case underInclude && incl.active && k == "project" && incl.project == "":
			incl.project = v
		case underInclude && k == "component" && len(kpath) == 1:
			// Mapping form: include:\n  component: …
			addGitLabComponent(f, v)
		}
	}
	flushIncl()
	if gated && !sawCI {
		return newFile(p, "gitlab-ci", Docker)
	}
	rootsFromPackages(f)
	return f
}

// yamlKeyValue extracts the value if s is a single-line `key: value`
// mapping for exactly the wanted key.
func yamlKeyValue(s, key string) (string, bool) {
	k, v, ok := strings.Cut(s, ":")
	if !ok || strings.Trim(strings.TrimSpace(k), `"'`) != key {
		return "", false
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return "", false
	}
	return yamlScalar(v), true
}

// addGitLabComponent records one `component:` reference —
// host/project-path/component-name@version.
func addGitLabComponent(f *File, ref string) {
	ref = yamlScalar(ref)
	if ref == "" || strings.ContainsAny(ref, " \t") {
		return
	}
	at := strings.LastIndexByte(ref, '@')
	if at <= 0 || at == len(ref)-1 {
		return
	}
	name, ver := ref[:at], ref[at+1:]
	if strings.Contains(ver, "$") {
		return
	}
	nonReg := false
	for _, pre := range []string{"$CI_SERVER_FQDN/", "${CI_SERVER_FQDN}/"} {
		if strings.HasPrefix(name, pre) {
			// The instance's own host: real, but unknowable from here.
			name, nonReg = strings.TrimPrefix(name, pre), true
			break
		}
	}
	if strings.Contains(name, "$") {
		return // other variables: not resolvable
	}
	segs := strings.Split(name, "/")
	if nonReg {
		if len(segs) < 3 { // namespace/project/component at minimum
			return
		}
	} else {
		// host/namespace/project/component at minimum, host has a dot.
		if len(segs) < 4 || !strings.Contains(segs[0], ".") {
			return
		}
	}
	f.add(name, ver)
	if f.PkgEco == nil {
		f.PkgEco = map[string]Ecosystem{}
	}
	f.PkgEco[Sanitize(name)] = GitLabCI
	if nonReg {
		f.markNonRegistry(name)
	}
}

// addGitLabProjectInclude records one `include: project:` pin. Claim-free
// by design: the file does not record which GitLab instance hosts the
// project, so no registry or tag verification is possible.
func addGitLabProjectInclude(f *File, project, ref string) {
	project, ref = yamlScalar(project), yamlScalar(ref)
	if project == "" || ref == "" || !strings.Contains(project, "/") ||
		strings.ContainsAny(project+ref, "$ \t") {
		return
	}
	f.add(project, ref)
	if f.PkgEco == nil {
		f.PkgEco = map[string]Ecosystem{}
	}
	f.PkgEco[Sanitize(project)] = GitLabCI
	f.markNonRegistry(project)
}
