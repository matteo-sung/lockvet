package lock

import "testing"

func TestHelmValuesNames(t *testing.T) {
	yes := []string{"values.yaml", "values.yml", "values-prod.yaml",
		"values.staging.yml", "my-app-values.yaml", "app.values.yaml",
		"my_app_values.yml"}
	no := []string{"values.json", "valuesish.yaml", "deployment.yaml",
		"pnpm-lock.yaml", "values", "chart-values.txt"}
	for _, n := range yes {
		if !isHelmValuesName(n) {
			t.Errorf("isHelmValuesName(%q) = false, want true", n)
		}
	}
	for _, n := range no {
		if isHelmValuesName(n) {
			t.Errorf("isHelmValuesName(%q) = true, want false", n)
		}
	}
}

func TestHelmValuesStructured(t *testing.T) {
	data := []byte(`replicaCount: 1
bluesky:
  pds:
    image:
      repository: ghcr.io/bluesky-social/pds
      tag: 0.4.5026
      pullPolicy: IfNotPresent
controller:
  image:
    registry: docker.io
    repository: bitnami/nginx
    tag: 1.25.3
    digest: sha256:8b2ee65f5f7dcfff8f18548d2eb23332f00f2df8ce6e6c70f2a20b1ec48d5d31
`)
	f, err := parseHelmValuesFile("values.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["ghcr.io/bluesky-social/pds"]; len(got) != 1 || got[0] != "0.4.5026" {
		t.Errorf("pds pin = %v", got)
	}
	if got := f.Packages["docker.io/bitnami/nginx"]; len(got) != 1 || got[0] != "1.25.3" {
		t.Errorf("bitnami pin = %v", got)
	}
	// The digest must land as an integrity pin.
	if pm := f.Pins["docker.io/bitnami/nginx"]["1.25.3"]; pm.Integrity == "" {
		t.Errorf("digest not recorded as pin: %+v", f.Pins)
	}
	if f.Kind != "helm-values" {
		t.Errorf("kind = %q", f.Kind)
	}
}

func TestHelmValuesScalarGates(t *testing.T) {
	data := []byte(`app:
  image: ghcr.io/example/app:v1.2.3
plain:
  image: nginx:1.27.1
untagged:
  image: nginx
asset:
  image: assets/logo.png
templated:
  image: "{{ .Values.registry }}/app:v1"
flow:
  image: {repository: x, tag: y}
`)
	f, _ := parseHelmValuesFile("values.yaml", data)
	if len(f.Packages) != 2 {
		t.Fatalf("packages = %v, want exactly the 2 tagged refs", f.Packages)
	}
	if _, ok := f.Packages["ghcr.io/example/app"]; !ok {
		t.Errorf("missing ghcr ref: %v", f.Packages)
	}
	if _, ok := f.Packages["nginx"]; !ok {
		t.Errorf("missing nginx ref: %v", f.Packages)
	}
}

func TestHelmValuesBlockScalarOpaque(t *testing.T) {
	data := []byte(`config: |
  some embedded app config
  image:
    repository: embedded/should-not-count
    tag: 9.9.9
  image: embedded/scalar:1.0.0
after:
  image:
    repository: real/app
    tag: 2.0.0
`)
	f, _ := parseHelmValuesFile("values.yaml", data)
	if len(f.Packages) != 1 {
		t.Fatalf("packages = %v, want only real/app", f.Packages)
	}
	if got := f.Packages["real/app"]; len(got) != 1 || got[0] != "2.0.0" {
		t.Errorf("real/app pin = %v", got)
	}
}

func TestHelmValuesAnchoredTag(t *testing.T) {
	// The home-ops Renovate shape: anchored tag with embedded digest.
	data := []byte(`controllers:
  main:
    containers:
      main:
        image:
          repository: ghcr.io/home-assistant/home-assistant
          tag: &img 2026.8.1@sha256:6d2a1e2d2c46bb2a8b34e1ae4bd0b1a1f9b18e5c9d0f70e26eec3dbdd54eaaaa
`)
	f, _ := parseHelmValuesFile("values.yaml", data)
	if got := f.Packages["ghcr.io/home-assistant/home-assistant"]; len(got) != 1 || got[0] != "2026.8.1" {
		t.Fatalf("packages = %v", f.Packages)
	}
	if pm := f.Pins["ghcr.io/home-assistant/home-assistant"]["2026.8.1"]; pm.Integrity == "" {
		t.Errorf("digest not recorded: %+v", f.Pins)
	}
}

func TestHelmValuesTemplatedStructuredSkipped(t *testing.T) {
	data := []byte(`image:
  repository: ghcr.io/example/app
  tag: "{{ .Chart.AppVersion }}"
other:
  image:
    repository: "{{ .Values.repo }}"
    tag: 1.0.0
`)
	f, _ := parseHelmValuesFile("values.yaml", data)
	if len(f.Packages) != 0 {
		t.Errorf("templated pins leaked: %v", f.Packages)
	}
}

func TestHelmValuesSniffStructuredOnly(t *testing.T) {
	// The kdwils/homelab shape: arbitrary filename under a GitOps dir —
	// discovered via the k8s lenient parser, structured shape only.
	data := []byte(`bluesky:
  image:
    repository: ghcr.io/bluesky-social/pds
    tag: 0.4.5026
scalarOnly:
  image: ghcr.io/example/app:v1.2.3
`)
	f, err := k8sManifestLenient("apps/bluesky/environments/homelab/homelab.yaml", data)
	if err != nil {
		t.Fatal(err)
	}
	if f.Kind != "helm-values" {
		t.Fatalf("kind = %q, want helm-values (file = %+v)", f.Kind, f)
	}
	if _, ok := f.Packages["ghcr.io/bluesky-social/pds"]; !ok {
		t.Errorf("structured pin missing: %v", f.Packages)
	}
	if _, ok := f.Packages["ghcr.io/example/app"]; ok {
		t.Errorf("scalar image must not count in sniffed files: %v", f.Packages)
	}
	// A YAML file with no image blocks stays an empty k8s file.
	ef, err := k8sManifestLenient("apps/foo/config.yaml", []byte("a:\n  b: c\n"))
	if err != nil || len(ef.Packages) != 0 {
		t.Errorf("plain YAML: %v %v", ef.Packages, err)
	}
}

func TestHelmValuesByBasenameRoute(t *testing.T) {
	p := ByBasename("charts/app/values.yaml")
	if p == nil || p.Kind != "helm-values" {
		t.Fatalf("ByBasename route = %+v", p)
	}
	if q := ByBasename("ci/smoke-values.yaml"); q == nil || q.Kind != "helm-values" {
		t.Fatalf("suffix route = %+v", q)
	}
}

func TestHelmValuesMultiDocAndEOFFlush(t *testing.T) {
	data := []byte(`image:
  repository: a/b
  tag: 1.0.0
---
image:
  repository: c/d
  tag: 2.0.0`)
	f, _ := parseHelmValuesFile("values.yaml", data)
	if len(f.Packages) != 2 {
		t.Errorf("packages = %v", f.Packages)
	}
}
