package lock

// Ansible Galaxy requirements files. `ansible-galaxy install -r
// requirements.yml` resolves two kinds of content: collections
// (namespace.name, from galaxy.ansible.com or a private Automation
// Hub) and roles (owner.name, from the classic v1 role index). Teams
// pin exact versions for reproducible provisioning, and Renovate bumps
// them — but there is no OSV.dev ecosystem and no deps.dev coverage,
// so nothing vets those bumps. internal/ansreg is the metadata layer.
//
// The basename requirements.yml/.yaml is shared with Helm v2 chart
// requirements, so the dispatcher sniffs: a dependencies: block is
// Helm, collections:/roles: blocks (or the old top-level role list)
// are Ansible.
//
// What counts as a pin: only exact versions (8.6.0, v3.1.2, 2.2 —
// role tags are often two-part). Range constraints (>=1.0.0, *) are
// not pins and are skipped entirely, like Chart.yaml ranges.
//
// NonRegistry: git/file/url/dir/subdirs type collections, URL- and
// git-sourced roles, and collections whose source: names any host
// other than galaxy.ansible.com (private Automation Hubs answer only
// with auth; no claims about them).

import (
	"errors"
	"strings"
)

var errNotRequirements = errors.New("not a Helm or Ansible requirements file")

// sniffRequirementsYAML routes the shared requirements.yml basename:
// Helm v2 chart files carry dependencies:, Ansible Galaxy files carry
// collections:/roles: (or are a bare top-level role list).
func sniffRequirementsYAML(p string, data []byte) (*File, error) {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "---" {
			continue
		}
		if strings.HasPrefix(line, " ") {
			continue
		}
		switch {
		case trimmed == "dependencies:":
			return parseHelmRequirementsYAML(p, data)
		case trimmed == "collections:", trimmed == "roles:":
			return parseAnsibleRequirements(p, data)
		case strings.HasPrefix(trimmed, "- "), trimmed == "-":
			// Old-style ansible-galaxy role files are a bare list of
			// src/version items at the top level.
			return parseAnsibleRequirements(p, data)
		}
	}
	return nil, errNotRequirements
}

// ansibleExactVersion reports whether a requirements.yml version value
// is an exact pin. Role versions are git tags, frequently two-part
// (2.2), so one dot is enough; branch names (master, main) and range
// constraints (>=1.0.0) are not pins.
func ansibleExactVersion(v string) bool {
	v = strings.TrimPrefix(v, "v")
	if v == "" || v[0] < '0' || v[0] > '9' {
		return false
	}
	dots := 0
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
		case c == '.':
			dots++
		case c == '-' || c == '+':
			return dots >= 1 && i > 0
		default:
			return false
		}
	}
	return dots >= 1 && dots <= 2
}

// galaxyName reports whether s is a Galaxy-form dotted name
// (namespace.collection / owner.role): exactly one dot, word
// characters either side.
func galaxyName(s string) bool {
	ns, name, ok := strings.Cut(s, ".")
	if !ok || ns == "" || name == "" || strings.Contains(name, ".") {
		return false
	}
	for _, part := range [2]string{ns, name} {
		for i := 0; i < len(part); i++ {
			c := part[i]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

// parseAnsibleRequirements reads an Ansible Galaxy requirements file:
// collections: and roles: blocks, or the old bare top-level role list.
func parseAnsibleRequirements(p string, data []byte) (*File, error) {
	f := newFile(p, "requirements.yml", Ansible)
	const (
		secNone = iota
		secCollections
		secRoles
	)
	section := secNone
	var name, src, version, source, typ string
	inItem := false
	flush := func(sec int) {
		defer func() { name, src, version, source, typ = "", "", "", "", ""; inItem = false }()
		if !inItem {
			return
		}
		nm := name
		if sec == secRoles && !galaxyName(nm) && galaxyName(src) {
			// roles list `src: owner.role` galaxy form; name: (if any)
			// is only the local install alias.
			nm = src
		}
		if nm == "" {
			if src == "" {
				return
			}
			nm = src
		}
		if sec == secCollections {
			// Collections accept pip-style specifiers; `==2.1.0`
			// is an exact pin spelled with an operator
			// (trailofbits/algo pins this way). Other operators
			// (>=, !=, ~=, wildcards) are ranges, not pins.
			version = strings.TrimSpace(strings.TrimPrefix(version, "=="))
		}
		if version == "" || !ansibleExactVersion(version) {
			return
		}
		f.add(nm, version)
		f.addRoot(nm)
		key := Sanitize(nm)
		if sec == secRoles {
			if f.PkgEco == nil {
				f.PkgEco = map[string]Ecosystem{}
			}
			f.PkgEco[key] = AnsibleRole
		}
		switch typ {
		case "", "galaxy":
		default:
			// git, file, url, dir, subdirs: not a Galaxy release.
			f.markNonRegistry(key)
		}
		if !galaxyName(nm) || (sec == secRoles && src != "" && !galaxyName(src)) {
			// URL/path names and URL-sourced roles: real pins worth
			// diffing, but nothing Galaxy can answer for.
			f.markNonRegistry(key)
		}
		if source != "" {
			h := strings.TrimPrefix(strings.TrimPrefix(source, "https://"), "http://")
			if i := strings.IndexByte(h, '/'); i >= 0 {
				h = h[:i]
			}
			if !strings.EqualFold(h, "galaxy.ansible.com") {
				// A private Automation Hub / Galaxy instance: answers
				// only with auth, so no registry claims.
				f.markNonRegistry(key)
			}
		}
	}
	itemIndent := -1
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || trimmed == "---" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 && !strings.HasPrefix(trimmed, "- ") && trimmed != "-" {
			// Top-level key.
			flush(section)
			switch strings.TrimSuffix(trimmed, ":") {
			case "collections":
				section = secCollections
			case "roles":
				section = secRoles
			default:
				section = secNone
			}
			itemIndent = -1
			continue
		}
		if indent == 0 && section == secNone && (strings.HasPrefix(trimmed, "- ") || trimmed == "-") {
			// Bare top-level list: the old role-file shape.
			section = secRoles
		}
		if section == secNone {
			continue
		}
		item := trimmed
		if strings.HasPrefix(item, "- ") || item == "-" {
			if itemIndent >= 0 && indent > itemIndent {
				// A nested list inside the current item (signatures:
				// blocks and the like): not a new entry.
				continue
			}
			flush(section)
			itemIndent = indent
			inItem = true
			if item == "-" {
				continue
			}
			item = strings.TrimSpace(item[2:])
			if !strings.Contains(item, ":") || strings.HasPrefix(item, "http") {
				// Bare scalar entry (- community.docker): no version,
				// no pin.
				inItem = false
				continue
			}
		} else if itemIndent >= 0 && indent <= itemIndent {
			// Left the list (new top-level handled above; deeper
			// structures like signatures: blocks are skipped below).
			flush(section)
			continue
		}
		if !inItem {
			continue
		}
		key, val, ok := strings.Cut(item, ":")
		if !ok {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		switch strings.TrimSpace(key) {
		case "name":
			name = val
		case "src":
			src = val
		case "version":
			version = val
		case "source":
			source = val
		case "type":
			typ = val
		}
	}
	flush(section)
	return f, nil
}
