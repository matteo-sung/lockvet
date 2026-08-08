package lock

import (
	"reflect"
	"strings"
	"testing"
)

func TestIsK8sManifestPath(t *testing.T) {
	yes := []string{
		"k8s/app.yaml", "deploy/kubernetes/web.yml", "manifests/db.yaml",
		"infra/k8s/base/api.yaml", "svc.k8s.yaml", "app.k8s.yml",
		"deployment.yaml", "config/statefulset.yml", "cronjob.yaml",
		`infra\k8s\api.yaml`, "daemonset.yaml", "pod.yaml", "replicaset.yaml",
		"oci/dis-apim/base/flux-kustomize.yaml", "clusters/prod/app.yaml",
		"overlays/dev/patch.yaml", "gitops/web.yml", "deploy/web.yaml",
		"apps/base/podinfo/release.yaml", "helmrelease.yaml",
		"observability/grafana/app/ocirepository.yaml",
		"infrastructure/controllers/weave.yaml", "flux-system/sync.yaml",
	}
	no := []string{
		"app.yaml", "config/settings.yml", "k8s/README.md",
		"charts/web/templates/deployment.yaml", // Helm template
		"k8s/templates/app.yaml",               // templates segment anywhere
		"deployment.json", "kustomization.yaml",
	}
	for _, p := range yes {
		if !isK8sManifestPath(p) {
			t.Errorf("isK8sManifestPath(%q) = false, want true", p)
		}
	}
	for _, p := range no {
		if isK8sManifestPath(p) {
			t.Errorf("isK8sManifestPath(%q) = true, want false", p)
		}
	}
}

func TestParseK8sManifest(t *testing.T) {
	data := []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      initContainers:
        - name: migrate
          image: ghcr.io/acme/migrate:v1.2.0
      containers:
      - name: web
        image: nginx:1.25.3@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        env:
          - name: SIDEcar_IMAGE
            value: not-an-image
      - name: sidecar
        image: "quay.io/acme/sidecar:2.0"
---
apiVersion: batch/v1
kind: CronJob
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: job
              image: busybox:1.36 # comment
            - name: templated
              image: {{ .Values.image }}
            - name: varref
              image: $(REGISTRY)/app:1.0
---
apiVersion: v1
kind: Service
spec:
  ports:
    - port: 80
`)
	f, err := parseK8sManifest("k8s/app.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"ghcr.io/acme/migrate": {"v1.2.0"},
		"nginx":                {"1.25.3"},
		"quay.io/acme/sidecar": {"2.0"},
		"busybox":              {"1.36"},
	}
	if !reflect.DeepEqual(f.Packages, want) {
		t.Fatalf("packages = %v, want %v", f.Packages, want)
	}
	if got := f.Pin("nginx", "1.25.3").Integrity; got == "" {
		t.Fatal("nginx digest pin missing")
	}
	if !f.RootsKnown || len(f.Roots) != len(want) {
		t.Fatalf("roots = %v", f.Roots)
	}
}

func TestParseK8sManifestNotK8s(t *testing.T) {
	data := []byte("services:\n  web:\n    image: nginx:1.25\n")
	if _, err := parseK8sManifest("manifests/app.yaml", data); err == nil {
		t.Fatal("want errNotK8s for non-Kubernetes YAML")
	}
	// Lenient wrapper: same content parses to an empty file.
	f, err := k8sManifestLenient("manifests/app.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Packages) != 0 {
		t.Fatalf("packages = %v, want none", f.Packages)
	}
	// image: keys outside containers blocks are not pins.
	cr := []byte(`apiVersion: example.com/v1
kind: Widget
spec:
  image: nginx:1.25
`)
	f, err = parseK8sManifest("k8s/widget.yaml", cr)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Packages) != 0 {
		t.Fatalf("packages = %v, want none (image outside containers)", f.Packages)
	}
}

func TestParseK8sManifestBlockBoundaries(t *testing.T) {
	// A sibling key at the containers indent closes the block; image keys
	// after it are not pins.
	data := []byte(`apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        image: alpine:3.21
      volumes:
        - name: cfg
          configMap:
            name: image
      nodeSelector:
        image: not-a-pin
`)
	f, err := parseK8sManifest("k8s/app.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"alpine": {"3.21"}}
	if !reflect.DeepEqual(f.Packages, want) {
		t.Fatalf("packages = %v, want %v", f.Packages, want)
	}
}

func TestParseKustomization(t *testing.T) {
	data := []byte(`apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deployment.yaml
images:
  - name: nginx
    newTag: "1.25.3"
  - name: old/app
    newName: ghcr.io/acme/app
    newTag: v2.1.0
  - name: postgres
    digest: sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
  - name: rename-only
    newName: ghcr.io/acme/renamed
helmCharts:
  - name: cert-manager
    repo: https://charts.jetstack.io
    version: v1.14.4
  - name: local-chart
    repo: file://../charts/local
    version: 1.0.0
  - name: oci-chart
    repo: oci://ghcr.io/acme/charts
    version: 2.0.0
  - name: ranged
    repo: https://charts.example.com
    version: ">=1.0.0"
`)
	f, err := parseKustomization("kustomization.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"nginx":            {"1.25.3"},
		"ghcr.io/acme/app": {"v2.1.0"},
		"postgres":         {"sha256:0123456789ab"},
		"cert-manager":     {"v1.14.4"},
		"local-chart":      {"1.0.0"},
		"oci-chart":        {"2.0.0"},
	}
	if !reflect.DeepEqual(f.Packages, want) {
		t.Fatalf("packages = %v, want %v", f.Packages, want)
	}
	if got := f.Pin("postgres", "sha256:0123456789ab").Integrity; got == "" {
		t.Fatal("postgres digest pin missing")
	}
	if f.PkgEco["cert-manager"] != Helm {
		t.Fatalf("cert-manager eco = %v", f.PkgEco["cert-manager"])
	}
	if got := f.PkgChannel["cert-manager"]; got != "https://charts.jetstack.io" {
		t.Fatalf("cert-manager channel = %q", got)
	}
	if !f.NonRegistry["local-chart"] {
		t.Fatal("local-chart should be NonRegistry")
	}
	if f.NonRegistry["oci-chart"] || f.PkgChannel["oci-chart"] != "" {
		t.Fatal("oci-chart: no channel, no NonRegistry (no claims)")
	}
	if f.Ecosystem != Docker {
		t.Fatalf("file eco = %v", f.Ecosystem)
	}
	if !f.RootsKnown || len(f.Roots) != len(want) {
		t.Fatalf("roots = %v", f.Roots)
	}
}

func TestParseKustomizationEmpty(t *testing.T) {
	data := []byte("resources:\n  - ../base\npatches:\n  - path: patch.yaml\n")
	f, err := parseKustomization("kustomization.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Packages) != 0 {
		t.Fatalf("packages = %v, want none", f.Packages)
	}
}

func TestByBasenameK8s(t *testing.T) {
	if p := ByBasename("infra/k8s/app.yaml"); p == nil || p.Kind != "kubernetes-manifest" {
		t.Fatalf("k8s path parser = %+v", p)
	}
	if p := ByBasename("overlays/prod/kustomization.yaml"); p == nil || p.Kind != "kustomization.yaml" {
		t.Fatalf("kustomization parser = %+v", p)
	}
	// Reserved basenames win over the k8s directory match.
	if p := ByBasename("k8s/pnpm-lock.yaml"); p == nil || p.Kind != "pnpm-lock.yaml" {
		t.Fatalf("pnpm under k8s/ = %+v", p)
	}
	// Workflow dirs win over everything.
	if p := ByBasename(".github/workflows/deployment.yaml"); p == nil || p.Kind != "github-workflow" {
		t.Fatalf("workflow parser = %+v", p)
	}
}

func TestParseK8sManifestFluxImages(t *testing.T) {
	// Flux Kustomization CRs carry kustomize images-transformer entries
	// under spec.images — the exact shape Renovate bumps.
	data := []byte(`apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: op
spec:
  path: ./default
  images:
    - name: controller
      newName: acr.example.io/ghcr.io/acme/operator
      # renovate: datasource=docker
      newTag: v1.0.0
    - name: sidecar
      newTag: ${TAG}
  sourceRef:
    kind: OCIRepository
`)
	f, err := parseK8sManifest("flux-kustomize.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"acr.example.io/ghcr.io/acme/operator": {"v1.0.0"}}
	if !reflect.DeepEqual(f.Packages, want) {
		t.Fatalf("packages = %v, want %v", f.Packages, want)
	}
}

func TestParseK8sManifestHelmRelease(t *testing.T) {
	// Same-file HelmRepository: the chart pin gets the repo URL as its
	// channel so helmreg can verify the bump.
	data := []byte(`apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: podinfo
  namespace: flux-system
spec:
  interval: 5m
  url: https://stefanprodan.github.io/podinfo/
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: podinfo
spec:
  interval: 50m
  chart:
    spec:
      chart: podinfo
      version: "6.5.0" # pinned
      sourceRef:
        kind: HelmRepository
        name: podinfo
        namespace: flux-system
  values:
    replicaCount: 2
`)
	f, err := parseK8sManifest("apps/base/podinfo/release.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["podinfo"]; !reflect.DeepEqual(got, []string{"6.5.0"}) {
		t.Fatalf("podinfo versions = %v", got)
	}
	if f.PkgEco["podinfo"] != Helm {
		t.Fatalf("podinfo eco = %v, want Helm", f.PkgEco["podinfo"])
	}
	if got := f.PkgChannel["podinfo"]; got != "https://stefanprodan.github.io/podinfo" {
		t.Fatalf("podinfo channel = %q", got)
	}
}

func TestParseK8sManifestHelmReleaseUnresolved(t *testing.T) {
	// sourceRef defined in another file: version row, no channel.
	rel := []byte(`apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: web
spec:
  chart:
    spec:
      chart: nginx
      version: 15.1.2
      sourceRef:
        kind: HelmRepository
        name: bitnami
`)
	f, err := parseK8sManifest("clusters/prod/helmrelease.yaml", rel)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["nginx"]; !reflect.DeepEqual(got, []string{"15.1.2"}) {
		t.Fatalf("nginx versions = %v", got)
	}
	if got := f.PkgChannel["nginx"]; got != "" {
		t.Fatalf("channel = %q, want none", got)
	}
	if f.PkgEco["nginx"] != Helm {
		t.Fatalf("eco = %v", f.PkgEco["nginx"])
	}
}

func TestParseK8sManifestHelmReleaseOCIAndRanges(t *testing.T) {
	data := []byte(`apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: oci-repo
spec:
  type: oci
  url: oci://registry-1.docker.io/bitnamicharts
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: redis
spec:
  chart:
    spec:
      chart: redis
      version: 18.4.0
      sourceRef:
        kind: HelmRepository
        name: oci-repo
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: ranged
spec:
  chart:
    spec:
      chart: tracked
      version: ">=6.0.0"
      sourceRef:
        kind: HelmRepository
        name: oci-repo
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: from-git
spec:
  chart:
    spec:
      chart: ./charts/app
      version: 1.0.0
      sourceRef:
        kind: GitRepository
        name: repo
`)
	f, err := parseK8sManifest("k8s/releases.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	// OCI source: pin recorded, no index.yaml channel to check.
	if got := f.Packages["redis"]; !reflect.DeepEqual(got, []string{"18.4.0"}) {
		t.Fatalf("redis versions = %v", got)
	}
	if got := f.PkgChannel["redis"]; got != "" {
		t.Fatalf("redis channel = %q, want none", got)
	}
	// Range: nothing pinned, no row.
	if _, ok := f.Packages["tracked"]; ok {
		t.Fatal("range version must not be recorded")
	}
	// Git path chart: not a registry package.
	if len(f.Packages) != 1 {
		t.Fatalf("packages = %v, want only redis", f.Packages)
	}
}

func TestParseK8sManifestHelmReleaseV1(t *testing.T) {
	// Flux v1 flat chart shape carries the repo URL directly.
	data := []byte(`apiVersion: helm.fluxcd.io/v1
kind: HelmRelease
metadata:
  name: grafana
spec:
  chart:
    repository: https://grafana.github.io/helm-charts
    name: grafana
    version: 6.50.7
`)
	f, err := parseK8sManifest("releases/helm-release.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["grafana"]; !reflect.DeepEqual(got, []string{"6.50.7"}) {
		t.Fatalf("grafana versions = %v", got)
	}
	if got := f.PkgChannel["grafana"]; got != "https://grafana.github.io/helm-charts" {
		t.Fatalf("channel = %q", got)
	}
}

func TestParseK8sManifestHelmRepoConflict(t *testing.T) {
	// Two same-name HelmRepository docs with different URLs: ambiguous,
	// no channel claim.
	data := []byte(`apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: charts
spec:
  url: https://a.example.com/charts
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata:
  name: charts
spec:
  url: https://b.example.com/charts
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: app
spec:
  chart:
    spec:
      chart: app
      version: 1.2.3
      sourceRef:
        kind: HelmRepository
        name: charts
`)
	f, err := parseK8sManifest("k8s/app.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.PkgChannel["app"]; got != "" {
		t.Fatalf("channel = %q, want none on conflict", got)
	}
	if got := f.Packages["app"]; !reflect.DeepEqual(got, []string{"1.2.3"}) {
		t.Fatalf("app versions = %v", got)
	}
}

func TestParseK8sManifestOCIRepository(t *testing.T) {
	data := []byte(`apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: flux-operator
spec:
  interval: 30m
  ref:
    tag: 0.58.0
  url: oci://ghcr.io/controlplaneio-fluxcd/charts/flux-operator
---
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: ranged
spec:
  ref:
    semver: ">=1.0.0"
  url: oci://ghcr.io/acme/charts/tracked
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: flux-operator
spec:
  chartRef:
    kind: OCIRepository
    name: flux-operator
  values:
    web:
      enabled: true
`)
	f, err := parseK8sManifest("kubernetes/flux-operator.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"ghcr.io/controlplaneio-fluxcd/charts/flux-operator": {"0.58.0"},
	}
	if !reflect.DeepEqual(f.Packages, want) {
		t.Fatalf("packages = %v, want %v", f.Packages, want)
	}
}

func TestSniffableYAML(t *testing.T) {
	yes := []string{
		"default/nzbget/nzbget.yaml", // billimek old layout: no dir/name convention
		"nzbget.yml",
		"services/media/sonarr.yaml",
		`services\media\sonarr.yaml`, // backslash separators (file mode on Windows)
	}
	for _, p := range yes {
		if !SniffableYAML(p) {
			t.Errorf("SniffableYAML(%q) = false, want true", p)
		}
	}
	no := []string{
		"k8s/deployment.yaml",          // already claimed by convention
		"package-lock.json",            // not YAML
		"pnpm-lock.yaml",               // claimed by basename
		".github/workflows/ci.yml",     // claimed as a workflow
		"chart/templates/deploy.yaml",  // helm template: interpolated refs
		"mychart/templates/svc.yml",    // helm template
		"README.md",                    // not YAML
		"docker-compose.override.yaml", // claimed by prefix rule
		".pre-commit-config.yaml",      // claimed by basename
	}
	for _, p := range no {
		if SniffableYAML(p) {
			t.Errorf("SniffableYAML(%q) = true, want false", p)
		}
	}
}

func TestPathFilterBudget(t *testing.T) {
	f := PathFilter(2)
	// Known lockfiles never consume the sniff budget.
	for _, p := range []string{"go.mod", "k8s/deployment.yaml", "yarn.lock"} {
		if !f(p) {
			t.Errorf("filter(%q) = false, want true", p)
		}
	}
	if !f("a/a.yaml") || !f("b/b.yaml") {
		t.Fatal("first two sniff candidates should pass")
	}
	if f("c/c.yaml") {
		t.Fatal("third sniff candidate should be over budget")
	}
	// Known lockfiles still pass after the budget is spent.
	if !f("Cargo.lock") {
		t.Error("filter(Cargo.lock) = false after budget spent, want true")
	}
	if SniffBudget < 10 {
		t.Errorf("SniffBudget = %d, suspiciously small", SniffBudget)
	}
}

func TestSniffParserLenient(t *testing.T) {
	p := SniffParser()
	f, err := p.Parse("app/app.yaml", []byte("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx:1.25.3\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["nginx"]; len(got) != 1 || got[0] != "1.25.3" {
		t.Fatalf("packages = %v, want nginx 1.25.3", f.Packages)
	}
	// Non-Kubernetes YAML parses to an empty file, never an error.
	f, err = p.Parse("mkdocs.yml", []byte("site_name: docs\nnav:\n  - Home: index.md\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Packages) != 0 {
		t.Fatalf("packages = %v, want empty", f.Packages)
	}
}

func TestParseK8sManifestHelmValuesImage(t *testing.T) {
	data := []byte(`---
apiVersion: helm.fluxcd.io/v1
kind: HelmRelease
metadata:
  name: home-assistant
spec:
  chart:
    repository: https://charts.example.com/
    name: home-assistant
    version: 0.13.3
  values:
    image:
      repository: homeassistant/home-assistant
      tag: 0.110.4
    sidecar:
      image:
        registry: docker.io
        repository: bitnami/nginx
        tag: "1.25.3"
    templated:
      image:
        repository: '{{ .Values.repo }}'
        tag: 1.0.0
    tagless:
      image:
        repository: ghcr.io/example/app
    ports:
      - port: 8123
`)
	f, err := parseK8sManifest("default/home-assistant/home-assistant.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	for pkg, vers := range map[string]string{
		"homeassistant/home-assistant": "0.110.4",
		"docker.io/bitnami/nginx":      "1.25.3",
		"home-assistant":               "0.13.3", // the chart pin still reads
	} {
		got := f.Packages[Sanitize(pkg)]
		if len(got) != 1 || got[0] != vers {
			t.Errorf("package %q = %v, want [%s]", pkg, got, vers)
		}
	}
	for _, absent := range []string{"{{ .Values.repo }}", "ghcr.io/example/app"} {
		if _, ok := f.Packages[Sanitize(absent)]; ok {
			t.Errorf("package %q should not be read (templated / no tag)", absent)
		}
	}
}

func TestParseK8sManifestValuesImageOnlyHelmRelease(t *testing.T) {
	// The repository/tag mapping convention is chart-specific: outside a
	// HelmRelease values: block it must not be read.
	data := []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data: {}
---
apiVersion: example.io/v1
kind: SomeOperator
spec:
  values:
    image:
      repository: example/app
      tag: 1.0.0
`)
	f, err := parseK8sManifest("k8s/config.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Packages) != 0 {
		t.Fatalf("packages = %v, want empty", f.Packages)
	}
}

func TestParseK8sManifestValuesImageAnchoredTag(t *testing.T) {
	// The current home-ops Renovate shape: app-template controllers with
	// a YAML anchor and an embedded digest on the tag value. Aliases
	// (*name) can't be resolved by a line scanner and must stay silent.
	data := []byte(`---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: home-assistant
spec:
  chartRef:
    kind: OCIRepository
    name: app-template
  values:
    controllers:
      home-assistant:
        containers:
          app:
            image:
              repository: ghcr.io/home-operations/home-assistant
              tag: &hass-image 2026.8.1@sha256:e1f54eb0306d7ded8b3cdee70c21178413cd175aa3e526452af0e086a39ecc51
          code:
            image:
              repository: ghcr.io/coder/code-server
              tag: *hass-image
`)
	f, err := parseK8sManifest("kubernetes/default/home-assistant/home-assistant.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	name := Sanitize("ghcr.io/home-operations/home-assistant")
	if got := f.Packages[name]; len(got) != 1 || got[0] != "2026.8.1" {
		t.Errorf("anchored tag: packages[%s] = %v, want [2026.8.1]", name, got)
	}
	if pin, ok := f.Pins[name]["2026.8.1"]; !ok || !strings.Contains(pin.Integrity, "sha256:e1f54eb") {
		t.Errorf("anchored tag digest pin = %+v, want sha256:e1f54eb…", pin)
	}
	if _, ok := f.Packages[Sanitize("ghcr.io/coder/code-server")]; ok {
		t.Error("alias tag (*name) must not produce a package")
	}
}

func TestParseK8sManifestArgoApplication(t *testing.T) {
	// Argo CD Application with a Helm chart source: chart +
	// targetRevision + inline repoURL → a Helm pin with a channel.
	data := []byte(`apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: sealed-secrets
  namespace: argocd
spec:
  project: default
  source:
    chart: sealed-secrets
    repoURL: https://bitnami-labs.github.io/sealed-secrets/
    targetRevision: 1.16.1
    helm:
      releaseName: sealed-secrets
      values: |
        chart: decoy
        targetRevision: 9.9.9
  destination:
    server: https://kubernetes.default.svc
    namespace: kubeseal
---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: guestbook
spec:
  source:
    repoURL: https://github.com/argoproj/argocd-example-apps.git
    targetRevision: HEAD
    path: guestbook
  destination:
    server: https://kubernetes.default.svc
`)
	f, err := parseK8sManifest("argocd/sealed-secrets.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["sealed-secrets"]; !reflect.DeepEqual(got, []string{"1.16.1"}) {
		t.Fatalf("sealed-secrets versions = %v (packages %v)", got, f.Packages)
	}
	if f.PkgEco["sealed-secrets"] != Helm {
		t.Fatalf("eco = %v, want Helm", f.PkgEco["sealed-secrets"])
	}
	if got := f.PkgChannel["sealed-secrets"]; got != "https://bitnami-labs.github.io/sealed-secrets" {
		t.Fatalf("channel = %q", got)
	}
	if len(f.Packages) != 1 {
		t.Fatalf("git-source app leaked packages: %v", f.Packages)
	}
}

func TestParseK8sManifestArgoMultiSource(t *testing.T) {
	// Multi-source Application: each chart-bearing item pins; git and
	// values-only ref sources don't. Nested helm maps and block-scalar
	// values inside an item must not feed the pin.
	data := []byte(`apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: stack
spec:
  sources:
    - chart: prometheus
      repoURL: https://prometheus-community.github.io/helm-charts
      targetRevision: 25.8.2
      helm:
        valueFiles:
          - $values/prometheus.yaml
        values: |
          chart: decoy
          targetRevision: 8.8.8
    - repoURL: https://github.com/org/values.git
      targetRevision: main
      ref: values
    - chart: grafana
      repoURL: oci://ghcr.io/grafana/helm-charts
      targetRevision: "7.0.0"
`)
	f, err := parseK8sManifest("apps/stack/application.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["prometheus"]; !reflect.DeepEqual(got, []string{"25.8.2"}) {
		t.Fatalf("prometheus versions = %v (packages %v)", got, f.Packages)
	}
	if got := f.PkgChannel["prometheus"]; got != "https://prometheus-community.github.io/helm-charts" {
		t.Fatalf("prometheus channel = %q", got)
	}
	// OCI repoURL: version row, no index.yaml to check → no channel.
	if got := f.Packages["grafana"]; !reflect.DeepEqual(got, []string{"7.0.0"}) {
		t.Fatalf("grafana versions = %v", got)
	}
	if got := f.PkgChannel["grafana"]; got != "" {
		t.Fatalf("grafana channel = %q, want none", got)
	}
	if len(f.Packages) != 2 {
		t.Fatalf("unexpected packages: %v", f.Packages)
	}
}

func TestParseK8sManifestArgoApplicationSet(t *testing.T) {
	// ApplicationSet template: literal chart pins count; templated
	// fields ({{ … }} parameters) are not literal pins — a templated
	// repoURL drops only the channel, a templated revision drops the
	// pin entirely.
	data := []byte(`apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: addons
spec:
  generators:
    - clusters: {}
  template:
    metadata:
      name: '{{name}}-cilium'
    spec:
      project: default
      source:
        chart: cilium
        repoURL: https://helm.cilium.io
        targetRevision: 1.15.6
      destination:
        server: '{{server}}'
---
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: templated
spec:
  template:
    spec:
      source:
        chart: '{{chart}}'
        repoURL: https://example.github.io/charts
        targetRevision: '{{rev}}'
`)
	f, err := parseK8sManifest("argocd/applicationset.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["cilium"]; !reflect.DeepEqual(got, []string{"1.15.6"}) {
		t.Fatalf("cilium versions = %v (packages %v)", got, f.Packages)
	}
	if got := f.PkgChannel["cilium"]; got != "https://helm.cilium.io" {
		t.Fatalf("cilium channel = %q", got)
	}
	if len(f.Packages) != 1 {
		t.Fatalf("templated ApplicationSet leaked packages: %v", f.Packages)
	}
}

func TestParseK8sManifestArgoRanges(t *testing.T) {
	// Range and branch-like targetRevisions track the repo — nothing is
	// pinned, no row.
	for _, rev := range []string{"*", "1.2.*", ">=1.0.0", "HEAD", "main", "~1.2.0"} {
		data := []byte(`apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: x
spec:
  source:
    chart: podinfo
    repoURL: https://stefanprodan.github.io/podinfo
    targetRevision: "` + rev + `"
`)
		f, err := parseK8sManifest("argocd/app.yaml", data)
		if err != nil {
			t.Fatal(err)
		}
		if len(f.Packages) != 0 {
			t.Fatalf("rev %q: packages = %v, want none", rev, f.Packages)
		}
	}
}
