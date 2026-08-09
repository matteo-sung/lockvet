package lock

// Helm values files pin container images too — format #45. The standard
// chart convention keeps an image: mapping with repository:/tag:
// children (Bitnami-style adds registry:/digest:), and Renovate's
// helm-values manager bumps exactly those lines — in values.yaml at
// chart roots, in per-environment overlay files, and in arbitrarily
// named helmfile/Argo value overlays. Nothing vets those bumps: charts
// have no OSV ecosystem and the values file names no chart version —
// but the image pins inside it get the full Dockerfile registry
// treatment (digest-vs-tag verification, unknown tags, ages, same-tag
// digest moves).
//
// Noise design, in order of trust:
//   - Files NAMED like values files (values.yaml, values-prod.yml,
//     app.values.yaml, staging-values.yaml) read both the structured
//     image: {repository:, tag:} shape and bare `image: ref` scalars —
//     scalars only when a tag or digest is present, so `image: nginx`
//     and asset paths never pin anything.
//   - Files merely DISCOVERED (GitOps dir conventions, changed-YAML
//     sniffing, playground drops) require the structured shape: an
//     `image:` mapping with repository: and tag: children is
//     distinctively Helm, while `image:` scalars appear in too many
//     YAML dialects to trust without a name or an apiVersion gate.
//   - Block scalar bodies (config: |) are opaque app config — a values
//     file embeds whole configuration files, and an image: line inside
//     one belongs to the embedded app, not to this file's pins.
//   - Templated fields ({{ … }}, $(VAR), ${VAR}) are not pins.

import "strings"

// isHelmValuesName reports whether a basename follows a Helm values-file
// naming convention.
func isHelmValuesName(base string) bool {
	b := strings.ToLower(base)
	if !strings.HasSuffix(b, ".yaml") && !strings.HasSuffix(b, ".yml") {
		return false
	}
	if b == "values.yaml" || b == "values.yml" {
		return true
	}
	// values-prod.yaml, values.staging.yml — and the reversed
	// conventions my-app-values.yaml, my-app.values.yaml,
	// my_app_values.yml.
	if strings.HasPrefix(b, "values-") || strings.HasPrefix(b, "values.") {
		return true
	}
	stem := strings.TrimSuffix(strings.TrimSuffix(b, ".yaml"), ".yml")
	return strings.HasSuffix(stem, "-values") || strings.HasSuffix(stem, ".values") ||
		strings.HasSuffix(stem, "_values")
}

// parseHelmValuesFile parses a convention-named Helm values file.
// Lenient by design: a values file with no image pins is an empty file,
// never a warning — most values files configure charts without pinning
// images, and directory walks must stay quiet over them.
func parseHelmValuesFile(p string, data []byte) (*File, error) {
	return scanHelmValues(p, data, true), nil
}

// scanHelmValues extracts container-image pins from a values-shaped YAML
// document. allowScalar additionally reads bare `image: ref` scalar
// values (convention-named values files only).
func scanHelmValues(p string, data []byte, allowScalar bool) *File {
	f := newFile(p, "helm-values", Docker)
	type pathEnt struct {
		indent int
		key    string
	}
	var kpath []pathEnt
	var img struct {
		active                            bool
		idx                               int // index in kpath of the image: entry
		registry, repository, tag, digest string
	}
	tmpl := func(s string) bool {
		return strings.Contains(s, "{{") || strings.Contains(s, "$(") ||
			strings.Contains(s, "${")
	}
	flushImg := func() {
		if img.active && img.repository != "" && img.tag != "" &&
			!tmpl(img.registry) && !tmpl(img.repository) &&
			!tmpl(img.tag) && !tmpl(img.digest) {
			ref := img.repository
			if img.registry != "" {
				ref = strings.TrimSuffix(img.registry, "/") + "/" + ref
			}
			ref += ":" + img.tag
			if img.digest != "" {
				ref += "@" + img.digest
			}
			addImageRef(f, ref, nil)
		}
		img.active = false
		img.registry, img.repository, img.tag, img.digest = "", "", "", ""
	}
	blockSkip := -1 // when ≥0: inside a block scalar opened at this key indent
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
			flushImg()
			kpath = kpath[:0]
			continue
		}
		// Maintain the mapping key path exactly like the manifest
		// parser: list items never push, they only close deeper paths.
		isItem := trimmed == "-" || strings.HasPrefix(trimmed, "- ")
		for len(kpath) > 0 && kpath[len(kpath)-1].indent >= indent {
			if img.active && img.idx == len(kpath)-1 {
				flushImg()
			}
			kpath = kpath[:len(kpath)-1]
		}
		if isItem {
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
		// YAML anchors: plain scalars can't start with & — strip the
		// anchor, the value follows (`tag: &app-image 1.2.3@sha256:…`
		// is the home-ops Renovate shape). Aliases (*name) can't be
		// resolved by a line scanner; treat them as no value.
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
		// Block scalar header (|, >, with optional indentation/chomping
		// modifiers): the body is opaque — skip it entirely.
		if v != "" && (v[0] == '|' || v[0] == '>') &&
			strings.TrimLeft(v[1:], "+-0123456789") == "" {
			blockSkip = indent
			continue
		}
		if v == "" {
			kpath = append(kpath, pathEnt{indent, k})
			if k == "image" {
				flushImg()
				img.active = true
				img.idx = len(kpath) - 1
			}
			continue
		}
		v = strings.Trim(v, `"'`)
		switch {
		case img.active && len(kpath) == img.idx+1:
			// Direct child of the tracked image: map.
			switch k {
			case "registry":
				img.registry = v
			case "repository":
				img.repository = v
			case "tag":
				img.tag = v
			case "digest":
				img.digest = v
			}
		case allowScalar && k == "image" && !tmpl(v) &&
			!strings.ContainsAny(v, "{}[],"):
			// Bare scalar form — only refs that actually pin something
			// (a tag or digest) count, so `image: nginx` stays silent.
			if _, tag, digest, ok := splitImageRef(v); ok &&
				(tag != "" || digest != "") {
				addImageRef(f, v, nil)
			}
		}
	}
	flushImg()
	return f
}
