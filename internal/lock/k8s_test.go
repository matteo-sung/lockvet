package lock

import (
	"reflect"
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
