package lock

// Kubernetes manifests and kustomizations pin container images too:
// every `image:` under a containers list is a pull the cluster will
// perform, and kustomization.yaml `images:` transformers override those
// pins with newTag / digest values that Renovate and Flux image
// automation bump exactly like lockfile entries. lockvet reads both —
// format #42 (manifests) and #43 (kustomization.yaml) — and the pins get
// the same registry verification as Dockerfile/Compose images
// (internal/ocireg: digest-vs-tag, unknown tags, Docker Hub ages), while
// kustomization `helmCharts:` entries ride the Helm chart-repository
// layer (internal/helmreg) like Chart.yaml dependencies.
//
// Discovery: kustomization.yaml/.yml (and bare Kustomization) match by
// basename anywhere. Plain manifests have no reserved filename, so
// lockvet takes *.yaml/*.yml files that either live under a directory
// named k8s/, kubernetes/ or manifests/, or carry a .k8s.yaml suffix,
// or use one of the conventional workload basenames (deployment.yaml,
// statefulset.yaml, …). The parser is strict about content — a document
// must declare top-level apiVersion: and kind: to count — and
// path-matched files that turn out not to be Kubernetes YAML parse to an
// empty file instead of erroring, so audit walks over mixed directories
// stay quiet. Files under a templates/ segment are excluded: Helm chart
// templates interpolate their image references and are not manifests the
// cluster sees.

import (
	"errors"
	"path"
	"regexp"
	"strings"
)

// isK8sManifestPath reports whether p looks like a plain Kubernetes
// manifest by location or naming convention. kustomization files are
// matched separately by basename.
func isK8sManifestPath(p string) bool {
	q := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	base := path.Base(q)
	if !strings.HasSuffix(base, ".yml") && !strings.HasSuffix(base, ".yaml") {
		return false
	}
	segs := strings.Split(path.Dir(q), "/")
	for _, seg := range segs {
		if seg == "templates" {
			// Helm chart template: image refs are {{ interpolated }};
			// even literal ones aren't what the cluster resolves.
			return false
		}
	}
	if strings.HasSuffix(base, ".k8s.yaml") || strings.HasSuffix(base, ".k8s.yml") {
		return true
	}
	switch strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml") {
	case "deployment", "statefulset", "daemonset", "replicaset", "cronjob", "pod":
		return true
	}
	for _, seg := range segs {
		switch seg {
		case "k8s", "kubernetes", "manifests", "deploy", "overlays", "base",
			"clusters", "gitops":
			// The k8s/kustomize/GitOps directory conventions. Over-matching
			// is nearly free: the parser requires top-level apiVersion: and
			// kind:, and non-Kubernetes YAML parses to an empty file.
			return true
		}
	}
	return false
}

var errNotK8s = errors.New("no Kubernetes documents found (need top-level apiVersion: and kind:)")

// containerListKey matches the PodSpec list keys whose items carry
// image: — containers, initContainers, ephemeralContainers — at any
// nesting depth (Pod, Deployment template, CronJob jobTemplate, …).
var containerListKey = regexp.MustCompile(`^(?:"?(containers|initContainers|ephemeralContainers)"?)\s*:\s*(?:#.*)?$`)

// parseK8sManifest reads container image pins from a (possibly
// multi-document) Kubernetes manifest. Strict: at least one document
// must declare top-level apiVersion: and kind:, otherwise errNotK8s.
// A valid manifest with no containers (Service, ConfigMap, …) parses to
// an empty file. Besides PodSpec containers lists, `images:` blocks of
// kustomization-transformer entries (name / newName / newTag / digest)
// are read wherever they appear — Flux `Kustomization` CRs carry exactly
// that shape under spec.images, and Renovate bumps their newTag values.
func parseK8sManifest(p string, data []byte) (*File, error) {
	f := newFile(p, "kubernetes-manifest", Docker)
	sawK8sDoc := false
	sawAPIVersion, sawKind := false, false
	// The innermost open block: a containers-style list (items carry
	// image:) or an images-transformer list (items carry name/newTag/…).
	const (
		blkContainers = iota
		blkImages
	)
	type openBlock struct{ indent, kind int }
	var blocks []openBlock
	var name, newName, newTag, digest string
	flushImage := func() {
		eff := newName
		if eff == "" {
			eff = name
		}
		if eff != "" && (newTag != "" || digest != "") {
			ref := eff
			if newTag != "" {
				ref += ":" + newTag
			}
			if digest != "" {
				ref += "@" + digest
			}
			addImageRef(f, ref, nil)
		}
		name, newName, newTag, digest = "", "", "", ""
	}
	closeTo := func(n int) {
		for len(blocks) > n {
			if blocks[len(blocks)-1].kind == blkImages {
				flushImage()
			}
			blocks = blocks[:len(blocks)-1]
		}
	}
	resetDoc := func() {
		if sawAPIVersion && sawKind {
			sawK8sDoc = true
		}
		sawAPIVersion, sawKind = false, false
		closeTo(0)
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "---" || strings.HasPrefix(trimmed, "--- ") {
			resetDoc()
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		if indent == 0 {
			switch {
			case strings.HasPrefix(trimmed, "apiVersion:"):
				sawAPIVersion = true
			case strings.HasPrefix(trimmed, "kind:"):
				sawKind = true
			}
		}
		// Close any blocks this line steps out of. A line at the block's
		// own indent continues it only as a list item.
		for len(blocks) > 0 {
			top := blocks[len(blocks)-1]
			if indent > top.indent || (indent == top.indent && (trimmed == "-" || strings.HasPrefix(trimmed, "- "))) {
				break
			}
			closeTo(len(blocks) - 1)
		}
		if len(blocks) > 0 {
			top := blocks[len(blocks)-1]
			item := trimmed
			if strings.HasPrefix(item, "- ") {
				if top.kind == blkImages {
					flushImage()
				}
				item = strings.TrimSpace(item[2:])
			} else if item == "-" {
				if top.kind == blkImages {
					flushImage()
				}
				continue
			}
			switch top.kind {
			case blkContainers:
				if v, ok := cutImageValue(item); ok {
					addImageRef(f, v, nil)
				}
			case blkImages:
				key, val, ok := strings.Cut(item, ":")
				if !ok {
					continue
				}
				val = strings.Trim(strings.TrimSpace(val), `"'`)
				if i := strings.Index(val, " #"); i >= 0 {
					val = strings.TrimSpace(val[:i])
				}
				if strings.Contains(val, "{{") || strings.Contains(val, "$(") || strings.Contains(val, "${") {
					val = ""
				}
				switch strings.Trim(strings.TrimSpace(key), `"'`) {
				case "name":
					name = val
				case "newName":
					newName = val
				case "newTag":
					newTag = val
				case "digest":
					digest = val
				}
			}
			continue
		}
		if containerListKey.MatchString(trimmed) {
			blocks = append(blocks, openBlock{indent, blkContainers})
		} else if imagesListKey.MatchString(trimmed) {
			blocks = append(blocks, openBlock{indent, blkImages})
		}
	}
	resetDoc()
	if !sawK8sDoc {
		return nil, errNotK8s
	}
	rootsFromPackages(f)
	return f, nil
}

// imagesListKey matches a kustomization-style images-transformer list key
// (Flux Kustomization CR spec.images, kustomize images:).
var imagesListKey = regexp.MustCompile(`^"?images"?\s*:\s*(?:#.*)?$`)

// cutImageValue extracts the value of an `image:` mapping line, minus
// quotes and trailing comments. Values still carrying template or
// variable syntax ({{ … }}, $(VAR), ${VAR}) are not pins.
func cutImageValue(item string) (string, bool) {
	key, val, ok := strings.Cut(item, ":")
	if !ok {
		return "", false
	}
	if k := strings.Trim(strings.TrimSpace(key), `"'`); k != "image" {
		return "", false
	}
	val = strings.TrimSpace(val)
	if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
		val = val[1 : len(val)-1]
	} else if i := strings.Index(val, " #"); i >= 0 {
		val = strings.TrimSpace(val[:i])
	}
	if val == "" || strings.Contains(val, "{{") || strings.Contains(val, "$(") ||
		strings.Contains(val, "${") {
		return "", false
	}
	return val, true
}

// k8sManifestLenient wraps parseK8sManifest for path-matched discovery:
// a file that isn't Kubernetes YAML at all parses to an empty file, so
// directory walks and git diffs over mixed trees produce no warnings.
func k8sManifestLenient(p string, data []byte) (*File, error) {
	f, err := parseK8sManifest(p, data)
	if errors.Is(err, errNotK8s) {
		return newFile(p, "kubernetes-manifest", Docker), nil
	}
	return f, err
}

// parseKustomization reads the two pinning blocks of a
// kustomization.yaml: `images:` transformer entries (name / newName /
// newTag / digest — the effective pin is what the cluster pulls after
// kustomize build) and `helmCharts:` entries (name / version / repo —
// the same shape Chart.yaml dependencies carry, checked against the
// chart repository's own index). A kustomization with neither block is
// a valid, empty file — overlays made only of resources: are everywhere.
func parseKustomization(p string, data []byte) (*File, error) {
	f := newFile(p, "kustomization.yaml", Docker)
	const (
		secNone = iota
		secImages
		secHelmCharts
	)
	section := secNone
	// Current list-entry fields.
	var name, newName, newTag, digest, version, repo string
	flush := func() {
		switch section {
		case secImages:
			eff := newName
			if eff == "" {
				eff = name
			}
			if eff != "" && (newTag != "" || digest != "") {
				ref := eff
				if newTag != "" {
					ref += ":" + newTag
				}
				if digest != "" {
					ref += "@" + digest
				}
				addImageRef(f, ref, nil)
			}
		case secHelmCharts:
			if name != "" && version != "" && exactSemver(version) {
				f.add(name, version) // rootsFromPackages marks roots at the end
				if f.PkgEco == nil {
					f.PkgEco = map[string]Ecosystem{}
				}
				f.PkgEco[Sanitize(name)] = Helm
				switch {
				case strings.HasPrefix(repo, "https://"), strings.HasPrefix(repo, "http://"):
					if f.PkgChannel == nil {
						f.PkgChannel = map[string]string{}
					}
					f.PkgChannel[Sanitize(name)] = strings.TrimRight(repo, "/")
				case strings.HasPrefix(repo, "file://"), repo == "":
					f.markNonRegistry(Sanitize(name))
					// oci:// refs: a real registry with no index.yaml —
					// no channel, no claims.
				}
			}
		}
		name, newName, newTag, digest, version, repo = "", "", "", "", "", ""
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "-") {
			flush()
			switch strings.TrimSpace(trimmed) {
			case "images:":
				section = secImages
			case "helmCharts:":
				section = secHelmCharts
			default:
				section = secNone
			}
			continue
		}
		if section == secNone {
			continue
		}
		item := trimmed
		if strings.HasPrefix(item, "- ") {
			flush()
			item = strings.TrimSpace(item[2:])
		} else if item == "-" {
			flush()
			continue
		}
		key, val, ok := strings.Cut(item, ":")
		if !ok {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		if i := strings.Index(val, " #"); i >= 0 {
			val = strings.TrimSpace(val[:i])
		}
		switch strings.Trim(strings.TrimSpace(key), `"'`) {
		case "name":
			name = val
		case "newName":
			newName = val
		case "newTag":
			newTag = val
		case "digest":
			digest = val
		case "version":
			version = val
		case "repo":
			repo = val
		}
	}
	flush()
	rootsFromPackages(f)
	return f, nil
}
