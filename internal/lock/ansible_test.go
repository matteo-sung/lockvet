package lock

import "testing"

const ansibleReqs = `---
# Provisioning dependencies.
collections:
  - name: community.general
    version: "8.6.0"
  - name: ansible.posix
    version: 1.5.4
    source: https://galaxy.ansible.com
  - name: community.docker
    version: ">=3.0.0"
  - name: hetzner.hcloud
    version: "==6.9.0"
  - name: private.thing
    version: 2.0.0
    source: https://hub.example.com/api/galaxy/
  - name: https://github.com/org/coll.git
    type: git
    version: 1.2.3
  - amazon.aws
roles:
  - name: geerlingguy.docker
    version: 7.0.0
  - src: geerlingguy.java
    version: "2.2"
  - src: https://github.com/geerlingguy/ansible-role-nodejs
    name: nodejs
    version: 6.1.0
  - name: someorg.rolling
    version: master
`

func TestParseAnsibleRequirements(t *testing.T) {
	f, err := sniffRequirementsYAML("requirements.yml", []byte(ansibleReqs))
	if err != nil {
		t.Fatal(err)
	}
	if f.Ecosystem != Ansible {
		t.Fatalf("eco = %v", f.Ecosystem)
	}
	want := map[string]string{
		"community.general":               "8.6.0",
		"ansible.posix":                   "1.5.4",
		"private.thing":                   "2.0.0",
		"https://github.com/org/coll.git": "1.2.3",
		"geerlingguy.docker":              "7.0.0",
		"geerlingguy.java":                "2.2",
		"nodejs":                          "6.1.0",
		"hetzner.hcloud":                  "6.9.0",
	}
	if len(f.Packages) != len(want) {
		t.Errorf("got %d packages, want %d: %v", len(f.Packages), len(want), f.Packages)
	}
	for name, v := range want {
		if got := f.Packages[name]; len(got) != 1 || got[0] != v {
			t.Errorf("%s = %v, want [%s]", name, got, v)
		}
	}
	// Range pins, branch pins and bare entries never register.
	for _, absent := range []string{"community.docker", "amazon.aws", "someorg.rolling"} {
		if _, ok := f.Packages[absent]; ok {
			t.Errorf("%s should not be pinned", absent)
		}
	}
	// Registry honesty markers.
	for _, nr := range []string{"private.thing", "https://github.com/org/coll.git", "nodejs"} {
		if !f.NonRegistry[Sanitize(nr)] {
			t.Errorf("%s should be NonRegistry", nr)
		}
	}
	for _, reg := range []string{"community.general", "ansible.posix", "geerlingguy.docker", "geerlingguy.java"} {
		if f.NonRegistry[reg] {
			t.Errorf("%s should not be NonRegistry", reg)
		}
	}
	// Roles are marked per-package.
	for _, role := range []string{"geerlingguy.docker", "geerlingguy.java", "nodejs"} {
		if f.PkgEco[role] != AnsibleRole {
			t.Errorf("%s eco = %v, want AnsibleRole", role, f.PkgEco[role])
		}
	}
	if _, ok := f.PkgEco["community.general"]; ok {
		t.Error("collections should keep the file-level ecosystem")
	}
}

func TestParseAnsibleOldRoleList(t *testing.T) {
	const old = `---
- src: geerlingguy.apache
  version: 3.1.4
- src: https://github.com/org/ansible-role-x
  name: rolex
  version: 1.0.0
- geerlingguy.mysql
`
	f, err := sniffRequirementsYAML("requirements.yml", []byte(old))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["geerlingguy.apache"]; len(got) != 1 || got[0] != "3.1.4" {
		t.Errorf("apache = %v", got)
	}
	if got := f.Packages["rolex"]; len(got) != 1 || got[0] != "1.0.0" {
		t.Errorf("rolex = %v", got)
	}
	if !f.NonRegistry["rolex"] {
		t.Error("URL-sourced role should be NonRegistry")
	}
	if f.PkgEco["geerlingguy.apache"] != AnsibleRole {
		t.Error("old-style list entries are roles")
	}
	if _, ok := f.Packages["geerlingguy.mysql"]; ok {
		t.Error("bare entries carry no pin")
	}
}

func TestSniffRequirementsYAMLHelm(t *testing.T) {
	const helm = `dependencies:
  - name: postgresql
    version: 12.5.6
    repository: https://charts.bitnami.com/bitnami
`
	f, err := sniffRequirementsYAML("requirements.yaml", []byte(helm))
	if err != nil {
		t.Fatal(err)
	}
	if f.Ecosystem != Helm {
		t.Fatalf("eco = %v, want Helm", f.Ecosystem)
	}
	if got := f.Packages["postgresql"]; len(got) != 1 || got[0] != "12.5.6" {
		t.Errorf("postgresql = %v", got)
	}
	if _, err := sniffRequirementsYAML("requirements.yml", []byte("just: a\nrandom: file\n")); err == nil {
		t.Error("unrecognized shapes should error")
	}
}

func TestAnsibleExactVersion(t *testing.T) {
	for v, want := range map[string]bool{
		"8.6.0": true, "v3.1.2": true, "2.2": true, "1.2.3-rc1": true,
		"1.2.3.4": false, "master": false, ">=1.0.0": false, "*": false,
		"1": false, "": false, "1.x": false,
	} {
		if got := ansibleExactVersion(v); got != want {
			t.Errorf("ansibleExactVersion(%q) = %v, want %v", v, got, want)
		}
	}
}
