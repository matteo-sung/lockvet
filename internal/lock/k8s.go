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
	case "deployment", "statefulset", "daemonset", "replicaset", "cronjob", "pod",
		"helmrelease", "helm-release", "release", "ocirepository", "helmrepository",
		"application", "applicationset", "appset":
		// The middle five are the Flux CR file conventions
		// (apps/base/<name>/release.yaml in the flux2 examples,
		// app/ocirepository.yaml in home-ops layouts); the last three
		// are the Argo CD ones.
		return true
	}
	for _, seg := range segs {
		switch seg {
		case "k8s", "kubernetes", "manifests", "deploy", "overlays", "base",
			"clusters", "gitops", "apps", "infrastructure", "infra",
			"flux", "flux-system", "chart", "charts",
			"argocd", "argo", "argo-cd", "applications", "applicationsets":
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

// helmRepoRef is a HelmRepository document's registry pointer: the
// chart repository URL and type ("oci" for OCI registries, which have
// no index.yaml to verify against).
type helmRepoRef struct {
	url, typ string
	conflict bool // two same-name HelmRepository docs with different URLs
}

// helmReleasePin is one HelmRelease document's chart pin, resolved
// against same-file HelmRepository docs after the whole file is read.
type helmReleasePin struct {
	chart, version   string
	srcKind, srcName string
	repoV1           string // Flux v1 spec.chart.repository (direct URL)
}

// parseK8sManifest reads container image pins from a (possibly
// multi-document) Kubernetes manifest. Strict: at least one document
// must declare top-level apiVersion: and kind:, otherwise errNotK8s.
// A valid manifest with no containers (Service, ConfigMap, …) parses to
// an empty file. Besides PodSpec containers lists, `images:` blocks of
// kustomization-transformer entries (name / newName / newTag / digest)
// are read wherever they appear — Flux `Kustomization` CRs carry exactly
// that shape under spec.images, and Renovate bumps their newTag values.
// Argo CD `Application` CRs (and `ApplicationSet` templates) are read
// too: a spec.source with chart: pins a Helm chart at targetRevision,
// and the inline repoURL gives the chart-repository layer its index —
// multi-source spec.sources lists included. Git-source Applications
// (path: instead of chart:) pin a repo revision, not a chart; they are
// left alone.
// Flux `HelmRelease` CRs are read too: an exact spec.chart.spec.version
// pin becomes a Helm-ecosystem package, and when the sourceRef's
// HelmRepository lives in the same file its URL rides along so the
// chart-repository layer (internal/helmreg) can verify the bump. A
// sourceRef defined elsewhere, or an OCI/Git source, still yields the
// version row — just no registry claims (nothing to honestly check).
func parseK8sManifest(p string, data []byte) (*File, error) {
	f := newFile(p, "kubernetes-manifest", Docker)
	sawK8sDoc := false
	sawAPIVersion, sawKind := false, false
	// The innermost open block: a containers-style list (items carry
	// image:) or an images-transformer list (items carry name/newTag/…).
	const (
		blkContainers = iota
		blkImages
		blkArgoSources
	)
	type openBlock struct{ indent, kind int }
	var blocks []openBlock
	var name, newName, newTag, digest string
	// Key-path tracker for the Flux CR fields (mapping keys only; list
	// items never push). Paths we read are fixed and shallow, so a
	// line-based stack is enough — block scalars can't collide because
	// their content always sits under the scalar key's parent path.
	type pathEnt struct {
		indent int
		key    string
	}
	var kpath []pathEnt
	pathIs := func(want string) bool {
		parts := strings.Split(want, ".")
		if len(kpath) != len(parts) {
			return false
		}
		for i, p := range parts {
			if kpath[i].key != p {
				return false
			}
		}
		return true
	}
	// Per-document Flux CR state.
	var docKind, docName string
	var repoURL, repoType string
	var ociURL, ociTag, ociDigest string
	var rel helmReleasePin
	// Argo CD Application (and ApplicationSet template) sources: a
	// spec.source with chart: pins a Helm chart at targetRevision from
	// repoURL — the same shape a Flux HelmRelease pins, with the
	// repository URL carried inline. Multi-source Applications keep a
	// list under spec.sources; each chart-bearing item counts.
	type argoSource struct {
		chart, repoURL, rev string
		childIndent         int // direct-child key indent inside a list item
	}
	var argoSrc argoSource  // the single spec.source mapping
	var argoItem argoSource // the open spec.sources list item
	var argoDone []argoSource
	flushArgoItem := func() {
		if argoItem.chart != "" {
			argoDone = append(argoDone, argoItem)
		}
		argoItem = argoSource{}
	}
	// A Helm-values image mapping inside a HelmRelease document:
	// `image:` with repository:/tag: (Bitnami-style registry:, digest:)
	// children — the standard chart convention, and the exact shape Flux
	// v1's image automation bumped in its Auto-release commits. Only
	// read under a values: path so arbitrary CRs can't feed it.
	var img struct {
		active                            bool
		idx                               int // index in kpath of the image: entry
		registry, repository, tag, digest string
	}
	flushImg := func() {
		if img.active && img.repository != "" && img.tag != "" {
			ref := img.repository
			if img.registry != "" {
				ref = strings.TrimSuffix(img.registry, "/") + "/" + ref
			}
			ref += ":" + img.tag
			if img.digest != "" {
				ref += "@" + img.digest
			}
			if !strings.Contains(ref, "{{") && !strings.Contains(ref, "$(") &&
				!strings.Contains(ref, "${") {
				addImageRef(f, ref, nil)
			}
		}
		img.active = false
		img.registry, img.repository, img.tag, img.digest = "", "", "", ""
	}
	// Per-file accumulators.
	repos := map[string]*helmRepoRef{}
	var releases []helmReleasePin
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
			switch blocks[len(blocks)-1].kind {
			case blkImages:
				flushImage()
			case blkArgoSources:
				flushArgoItem()
			}
			blocks = blocks[:len(blocks)-1]
		}
	}
	resetDoc := func() {
		if sawAPIVersion && sawKind {
			sawK8sDoc = true
		}
		switch docKind {
		case "HelmRepository":
			if docName != "" && repoURL != "" {
				typ := repoType
				if strings.HasPrefix(repoURL, "oci://") {
					typ = "oci"
				}
				if prev, ok := repos[docName]; ok {
					if prev.url != repoURL {
						prev.conflict = true
					}
				} else {
					repos[docName] = &helmRepoRef{url: repoURL, typ: typ}
				}
			}
		case "HelmRelease":
			// Only exact semver pins count (ranges track the repo's
			// latest — nothing is pinned). Charts with a path shape
			// (./charts/x from a GitRepository source) are not registry
			// packages.
			if rel.chart != "" && exactSemver(rel.version) &&
				!strings.Contains(rel.chart, "/") {
				releases = append(releases, rel)
			}
		case "Application", "ApplicationSet":
			// Argo CD: close any open spec.sources block so the last
			// list item is flushed, then turn chart-bearing sources
			// into Helm pins. Only exact revisions count (ranges and
			// branch-like revisions track the repo, not a pin), and
			// templated fields (ApplicationSet {{ … }} parameters)
			// are not literal pins.
			closeTo(0)
			if argoSrc.chart != "" {
				argoDone = append(argoDone, argoSrc)
			}
			for _, s := range argoDone {
				if s.chart == "" || strings.Contains(s.chart, "/") ||
					strings.Contains(s.chart, "{{") || !exactSemver(s.rev) {
					continue
				}
				url := s.repoURL
				if strings.Contains(url, "{{") {
					url = ""
				}
				releases = append(releases, helmReleasePin{
					chart: s.chart, version: s.rev, repoV1: url,
				})
			}
		case "OCIRepository":
			// Flux's modern chart/artifact source: spec.url is an OCI
			// reference and spec.ref.tag / spec.ref.digest pin it —
			// exactly an image pin, so it gets the Dockerfile registry
			// treatment (digest-vs-tag, unknown tags, ages). Renovate
			// bumps ref.tag in HelmRelease-chartRef setups.
			if repo, ok := strings.CutPrefix(ociURL, "oci://"); ok &&
				repo != "" && (ociTag != "" || ociDigest != "") {
				ref := repo
				if ociTag != "" {
					ref += ":" + ociTag
				}
				if ociDigest != "" {
					ref += "@" + ociDigest
				}
				addImageRef(f, ref, nil)
			}
		}
		sawAPIVersion, sawKind = false, false
		docKind, docName, repoURL, repoType = "", "", "", ""
		ociURL, ociTag, ociDigest = "", "", ""
		rel = helmReleasePin{}
		argoSrc, argoItem, argoDone = argoSource{}, argoSource{}, nil
		flushImg()
		kpath = kpath[:0]
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
		// Maintain the mapping key path and capture Flux CR fields.
		// List items never push; they only close deeper paths.
		isItem := trimmed == "-" || strings.HasPrefix(trimmed, "- ")
		for len(kpath) > 0 && kpath[len(kpath)-1].indent >= indent {
			if img.active && img.idx == len(kpath)-1 {
				flushImg()
			}
			kpath = kpath[:len(kpath)-1]
		}
		if !isItem {
			if key, val, ok := strings.Cut(trimmed, ":"); ok && !strings.Contains(strings.TrimSpace(key), " ") {
				k := strings.Trim(strings.TrimSpace(key), `"'`)
				v := strings.TrimSpace(val)
				if i := strings.Index(v, " #"); i >= 0 {
					v = strings.TrimSpace(v[:i])
				}
				// YAML anchors: plain scalars can't start with & — a
				// leading &name is always an anchor, the value follows
				// (`tag: &hass-image 2026.8.1@sha256:…` is the home-ops
				// Renovate shape). Aliases (*name) can't be resolved by
				// a line scanner; treat them as no value.
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
				if v == "" || strings.HasPrefix(v, "#") {
					kpath = append(kpath, pathEnt{indent, k})
					if k == "image" && docKind == "HelmRelease" {
						underValues := false
						for _, e := range kpath[:len(kpath)-1] {
							if e.key == "values" {
								underValues = true
								break
							}
						}
						if underValues {
							flushImg()
							img.active = true
							img.idx = len(kpath) - 1
						}
					}
				} else {
					v = strings.Trim(v, `"'`)
					switch {
					case img.active && len(kpath) == img.idx+1:
						// Direct child of the tracked values image: map.
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
					case indent == 0 && k == "kind":
						docKind = v
					case pathIs("metadata") && k == "name":
						docName = v
					case docKind == "HelmRepository" && pathIs("spec") && k == "url":
						repoURL = v
					case docKind == "HelmRepository" && pathIs("spec") && k == "type":
						repoType = strings.ToLower(v)
					case docKind == "OCIRepository" && pathIs("spec") && k == "url":
						ociURL = v
					case docKind == "OCIRepository" && pathIs("spec.ref"):
						switch k {
						case "tag":
							ociTag = v
						case "digest":
							ociDigest = v
							// ref.semver is a range — nothing is pinned.
						}
					case docKind == "HelmRelease" && pathIs("spec.chart.spec"):
						switch k {
						case "chart":
							rel.chart = v
						case "version":
							rel.version = v
						}
					case docKind == "HelmRelease" && pathIs("spec.chart.spec.sourceRef"):
						switch k {
						case "kind":
							rel.srcKind = v
						case "name":
							rel.srcName = v
						}
					case docKind == "HelmRelease" && pathIs("spec.chart"):
						// Flux v1 (helm.fluxcd.io/v1) flat chart shape.
						switch k {
						case "name":
							rel.chart = v
						case "version":
							rel.version = v
						case "repository":
							rel.repoV1 = v
						}
					case (docKind == "Application" && pathIs("spec.source")) ||
						(docKind == "ApplicationSet" && pathIs("spec.template.spec.source")):
						switch k {
						case "chart":
							argoSrc.chart = v
						case "repoURL":
							argoSrc.repoURL = v
						case "targetRevision":
							argoSrc.rev = v
						}
					}
				}
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
			keyIndent := indent
			if strings.HasPrefix(item, "- ") {
				switch top.kind {
				case blkImages:
					flushImage()
				case blkArgoSources:
					flushArgoItem()
				}
				item = strings.TrimSpace(item[2:])
				keyIndent = indent + (len(trimmed) - len(item))
			} else if item == "-" {
				switch top.kind {
				case blkImages:
					flushImage()
				case blkArgoSources:
					flushArgoItem()
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
			case blkArgoSources:
				// Only direct children of the list item count: a
				// source's nested maps (helm: parameters, block-scalar
				// values) sit deeper and must not feed the pin.
				if argoItem.childIndent == 0 {
					argoItem.childIndent = keyIndent
				}
				if keyIndent != argoItem.childIndent {
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
				case "chart":
					argoItem.chart = val
				case "repoURL":
					argoItem.repoURL = val
				case "targetRevision":
					argoItem.rev = val
				}
			}
			continue
		}
		if containerListKey.MatchString(trimmed) {
			blocks = append(blocks, openBlock{indent, blkContainers})
		} else if imagesListKey.MatchString(trimmed) {
			blocks = append(blocks, openBlock{indent, blkImages})
		} else if argoSourcesKey.MatchString(trimmed) &&
			((docKind == "Application" && pathIs("spec.sources")) ||
				(docKind == "ApplicationSet" && pathIs("spec.template.spec.sources"))) {
			blocks = append(blocks, openBlock{indent, blkArgoSources})
		}
	}
	resetDoc()
	if !sawK8sDoc {
		return nil, errNotK8s
	}
	// Resolve HelmRelease pins against same-file HelmRepository docs.
	for _, r := range releases {
		f.add(r.chart, r.version)
		n := Sanitize(r.chart)
		if f.PkgEco == nil {
			f.PkgEco = map[string]Ecosystem{}
		}
		f.PkgEco[n] = Helm
		url := r.repoV1
		if url == "" && r.srcKind == "HelmRepository" && r.srcName != "" {
			if repo, ok := repos[r.srcName]; ok && !repo.conflict && repo.typ != "oci" {
				url = repo.url
			}
		}
		if strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://") {
			if f.PkgChannel == nil {
				f.PkgChannel = map[string]string{}
			}
			f.PkgChannel[n] = strings.TrimRight(url, "/")
		}
		// No resolvable HTTP repository (sourceRef in another file,
		// OCI registry, Git source): the version row still renders,
		// but no index.yaml exists to check — no registry claims.
	}
	rootsFromPackages(f)
	return f, nil
}

// imagesListKey matches a kustomization-style images-transformer list key
// (Flux Kustomization CR spec.images, kustomize images:).
var imagesListKey = regexp.MustCompile(`^"?images"?\s*:\s*(?:#.*)?$`)

// argoSourcesKey matches an Argo CD multi-source list key; the caller
// additionally requires the spec.sources path inside an Application (or
// spec.template.spec.sources inside an ApplicationSet).
var argoSourcesKey = regexp.MustCompile(`^"?sources"?\s*:\s*(?:#.*)?$`)

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

// SniffableYAML reports whether a changed file that no basename or path
// convention claims is still worth a content sniff as a Kubernetes
// manifest. GitOps repos keep workload manifests under arbitrary layouts
// (default/nzbget/nzbget.yaml); the strict top-level apiVersion: + kind:
// gate inside the parser makes over-matching free, so in diff modes —
// where the changed-file list is small — every other YAML file
// qualifies. Helm chart templates stay excluded: their image references
// are {{ interpolated }}. Directory walks (audit) keep convention-based
// discovery instead: sniffing every YAML in a large tree would read far
// more than it finds.
func SniffableYAML(p string) bool {
	q := strings.ToLower(strings.ReplaceAll(p, "\\", "/"))
	base := path.Base(q)
	if !strings.HasSuffix(base, ".yml") && !strings.HasSuffix(base, ".yaml") {
		return false
	}
	for _, seg := range strings.Split(path.Dir(q), "/") {
		if seg == "templates" {
			return false
		}
	}
	return ByBasename(p) == nil
}

// SniffParser parses files admitted by SniffableYAML: Kubernetes YAML
// gets the manifest treatment, anything else parses to an empty file.
func SniffParser() *Parser {
	return &Parser{"kubernetes-manifest", Docker, k8sManifestLenient}
}

// SniffBudget is the default cap PathFilter puts on content-sniff
// candidates per remote fetch.
const SniffBudget = 20

// PathFilter returns a fresh predicate for remote diff fetches: every
// known lockfile path always passes, and up to sniffBudget other YAML
// files (SniffableYAML) pass for content sniffing — the cap keeps a big
// refactor PR from ballooning the number of file downloads. The closure
// is stateful; make one per fetch and do not share across goroutines.
func PathFilter(sniffBudget int) func(string) bool {
	return func(p string) bool {
		if ByBasename(p) != nil {
			return true
		}
		if sniffBudget > 0 && SniffableYAML(p) {
			sniffBudget--
			return true
		}
		return false
	}
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
