package lock

import "testing"

const tfLock = `# This file is maintained automatically by "terraform init".
# Manual edits may be lost in future updates.

provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.31.0"
  constraints = "~> 5.0"
  hashes = [
    "h1:WpZoNbLLtIYycFGqIVKBcFCu4qk8Rj+RsxTMBLzGkGw=",
    "zh:0953565eb60d0b2ac1f6e2d1a35ffd9392e57d3bc65a6500b3fb64cb52d5b02f",
  ]
}

provider "registry.terraform.io/hashicorp/random" {
  version = "3.6.0"
  hashes = [
    "h1:R5Ucn26riKIEijcsiOMBR3uOAjuOMfI1x7XvH4P6B1w=",
  ]
}

provider "registry.opentofu.org/hashicorp/null" {
  version     = "3.2.2"
  constraints = ">= 3.0.0"
}

provider "example.com/corp/internal" {
  version = "1.0.0"
}
`

func TestParseTerraformLock(t *testing.T) {
	f, err := parseTerraformLock(".terraform.lock.hcl", []byte(tfLock))
	if err != nil {
		t.Fatal(err)
	}
	if f.Ecosystem != Terraform {
		t.Fatalf("ecosystem = %q", f.Ecosystem)
	}
	want := map[string]string{
		"hashicorp/aws":                        "5.31.0",
		"hashicorp/random":                     "3.6.0",
		"registry.opentofu.org/hashicorp/null": "3.2.2",
		"example.com/corp/internal":            "1.0.0",
	}
	if len(f.Packages) != len(want) {
		t.Fatalf("got %d packages: %v", len(f.Packages), f.Packages)
	}
	for name, v := range want {
		if got := f.Packages[name]; len(got) != 1 || got[0] != v {
			t.Errorf("%s = %v, want [%s]", name, got, v)
		}
	}
	if f.RootsKnown {
		t.Error("terraform lock should not claim known roots")
	}
}

const chartLock = `dependencies:
- name: postgresql
  repository: https://charts.bitnami.com/bitnami
  version: 12.1.9
- name: common
  repository: "oci://registry-1.docker.io/bitnamicharts"
  version: 2.13.3
digest: sha256:abcdef0123456789
generated: "2024-01-05T12:00:00.000000000Z"
`

func TestParseChartLock(t *testing.T) {
	f, err := parseChartLock("Chart.lock", []byte(chartLock))
	if err != nil {
		t.Fatal(err)
	}
	if f.Ecosystem != Helm {
		t.Fatalf("ecosystem = %q", f.Ecosystem)
	}
	if len(f.Packages) != 2 {
		t.Fatalf("got %d packages: %v", len(f.Packages), f.Packages)
	}
	if got := f.Packages["postgresql"]; len(got) != 1 || got[0] != "12.1.9" {
		t.Errorf("postgresql = %v", got)
	}
	if got := f.Packages["common"]; len(got) != 1 || got[0] != "2.13.3" {
		t.Errorf("common = %v", got)
	}
	if !f.RootsKnown || len(f.Roots) != 2 {
		t.Errorf("roots = %v (known=%v), want both entries direct", f.Roots, f.RootsKnown)
	}
	if got := f.PkgChannel["postgresql"]; got != "https://charts.bitnami.com/bitnami" {
		t.Errorf("PkgChannel[postgresql] = %q", got)
	}
	if _, ok := f.PkgChannel["common"]; ok {
		t.Error("oci:// repository must not set a channel")
	}
	if f.NonRegistry["common"] {
		t.Error("oci:// repository is a real registry, not NonRegistry")
	}
}

func TestParseChartYAML(t *testing.T) {
	in := `apiVersion: v2
name: mychart
version: 1.2.3
dependencies:
  - name: postgresql
    version: 12.1.9
    repository: https://charts.bitnami.com/bitnami
    condition: postgresql.enabled
  - name: ranged
    version: ">=1.0.0"
    repository: https://charts.example.com
  - name: wildcard
    version: 1.x.x
    repository: https://charts.example.com
  - name: local-sub
    version: 0.1.0
    repository: file://../local-sub
  - name: aliased
    version: 2.0.0
    repository: "@stable"
`
	f, err := parseChartYAML("Chart.yaml", []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"postgresql": "12.1.9", "local-sub": "0.1.0", "aliased": "2.0.0"}
	if len(f.Packages) != len(want) {
		t.Fatalf("got %d packages: %v (ranges must be skipped)", len(f.Packages), f.Packages)
	}
	for name, v := range want {
		if got := f.Packages[name]; len(got) != 1 || got[0] != v {
			t.Errorf("%s = %v, want [%s]", name, got, v)
		}
	}
	if got := f.PkgChannel["postgresql"]; got != "https://charts.bitnami.com/bitnami" {
		t.Errorf("PkgChannel[postgresql] = %q", got)
	}
	if !f.NonRegistry["local-sub"] {
		t.Error("file:// subchart must be NonRegistry")
	}
	if f.NonRegistry["aliased"] {
		t.Error("@alias repository: no claims either way, not NonRegistry")
	}
	// Leaf chart: valid, empty.
	leaf, err := parseChartYAML("Chart.yaml", []byte("apiVersion: v2\nname: leaf\nversion: 0.1.0\n"))
	if err != nil || len(leaf.Packages) != 0 {
		t.Fatalf("leaf chart: %v, %v", leaf.Packages, err)
	}
}

func TestParseHelmRequirementsYAML(t *testing.T) {
	// Ansible Galaxy requirements.yml must be rejected.
	ansible := "roles:\n  - name: geerlingguy.java\n    version: 2.3.0\ncollections:\n  - name: community.general\n"
	if _, err := parseHelmRequirementsYAML("requirements.yml", []byte(ansible)); err == nil {
		t.Fatal("ansible requirements.yml must not parse as Helm")
	}
	helm := "dependencies:\n- name: redis\n  version: 10.5.7\n  repository: https://kubernetes-charts.storage.googleapis.com\n"
	f, err := parseHelmRequirementsYAML("requirements.yaml", []byte(helm))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["redis"]; len(got) != 1 || got[0] != "10.5.7" {
		t.Errorf("redis = %v", got)
	}
}

func TestExactSemver(t *testing.T) {
	yes := []string{"1.2.3", "v1.2.3", "0.1.0", "1.2.3-beta.1", "1.2.3+meta"}
	no := []string{"", "1.2", "1.x.x", "1.2.x", "*", ">=1.0.0", "~1.2.3", "^1.2.3", "1.2.3 - 2.0.0", "latest"}
	for _, v := range yes {
		if !exactSemver(v) {
			t.Errorf("exactSemver(%q) = false, want true", v)
		}
	}
	for _, v := range no {
		if exactSemver(v) {
			t.Errorf("exactSemver(%q) = true, want false", v)
		}
	}
}

func TestParseChartLockIndented(t *testing.T) {
	in := "dependencies:\n  - name: redis\n    version: 17.0.1\n    repository: https://charts.bitnami.com/bitnami\ndigest: sha256:00\n"
	f, err := parseChartLock("Chart.lock", []byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["redis"]; len(got) != 1 || got[0] != "17.0.1" {
		t.Errorf("redis = %v", got)
	}
}

func TestParseRequirementsLockDisambiguation(t *testing.T) {
	helm := "dependencies:\n- name: nginx\n  version: 1.2.3\n  repository: https://example.com\n"
	f, err := parseRequirementsLock("requirements.lock", []byte(helm))
	if err != nil {
		t.Fatal(err)
	}
	if f.Ecosystem != Helm || len(f.Packages["nginx"]) != 1 {
		t.Fatalf("helm-shaped requirements.lock parsed as %q %v", f.Ecosystem, f.Packages)
	}

	pip := "requests==2.31.0\nurllib3==2.1.0\n"
	f, err = parseRequirementsLock("requirements.lock", []byte(pip))
	if err != nil {
		t.Fatal(err)
	}
	if f.Ecosystem != PyPI {
		t.Fatalf("pip-shaped requirements.lock parsed as %q", f.Ecosystem)
	}
	if got := f.Packages["requests"]; len(got) != 1 || got[0] != "2.31.0" {
		t.Errorf("requests = %v", got)
	}
}

func TestInfraByBasename(t *testing.T) {
	for _, p := range []string{"infra/.terraform.lock.hcl", "charts/app/Chart.lock", "requirements.lock", "x/.plat-uw2-dev-kms-key.terraform.lock.hcl"} {
		if ByBasename(p) == nil {
			t.Errorf("ByBasename(%q) = nil", p)
		}
	}
}

func TestInfraNoOSV(t *testing.T) {
	if Terraform.HasOSV() || Helm.HasOSV() {
		t.Error("Terraform/Helm must not claim OSV coverage")
	}
	if !Terraform.HasSemver() || !Helm.HasSemver() {
		t.Error("Terraform/Helm are semver ecosystems")
	}
}
