package lock

import (
	"encoding/json"
	"testing"
)

func TestParseDevcontainer(t *testing.T) {
	src := []byte(`{
	// A comment the VS Code templates really ship with.
	"name": "Go", /* block
	comment */
	"image": "mcr.microsoft.com/devcontainers/go:1.3-1.24-bookworm",
	"features": {
		"ghcr.io/devcontainers/features/node:1": { "version": "22" },
		"ghcr.io/devcontainers/features/docker-in-docker:2.12.4": {},
		"ghcr.io/acme/features/tool@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {},
		"ghcr.io/acme/features/untagged": {},
		"./local-feature": {},
		"https://example.com/feature.tgz": {},
		"docker-in-docker": {}, // legacy shorthand: no host, no claims
	},
	"customizations": { "vscode": { "extensions": ["golang.go",] } },
}`)
	f, err := parseDevcontainer("x/.devcontainer/devcontainer.json", src)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"mcr.microsoft.com/devcontainers/go":              "1.3-1.24-bookworm",
		"ghcr.io/devcontainers/features/node":             "1",
		"ghcr.io/devcontainers/features/docker-in-docker": "2.12.4",
		"ghcr.io/acme/features/tool":                      "sha256:aaaaaaaaaaaa",
		"ghcr.io/acme/features/untagged":                  "latest",
	}
	if len(f.Packages) != len(want) {
		t.Fatalf("got %d packages, want %d: %v", len(f.Packages), len(want), f.Packages)
	}
	for name, ver := range want {
		vs := f.Packages[name]
		if len(vs) != 1 || vs[0] != ver {
			t.Errorf("%s = %v, want [%s]", name, vs, ver)
		}
	}
	// The digest pin lands as integrity.
	if pin := f.Pins["ghcr.io/acme/features/tool"]["sha256:aaaaaaaaaaaa"]; pin.Integrity == "" {
		t.Errorf("digest pin not recorded: %+v", f.Pins["ghcr.io/acme/features/tool"])
	}
}

func TestParseDevcontainerComposeShape(t *testing.T) {
	// Compose/Dockerfile-based configs pin nothing here.
	f, err := parseDevcontainer("devcontainer.json", []byte(`{
		"dockerComposeFile": "docker-compose.yml",
		"service": "app",
		"features": {}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Packages) != 0 {
		t.Fatalf("want no packages, got %v", f.Packages)
	}
}

func TestStripJSONC(t *testing.T) {
	in := `{"a": "http://x//y /*not*/", // line
	"b": [1, 2,], /* c */ "d": "\" // \\", }`
	var v map[string]any
	if err := json.Unmarshal(stripJSONC([]byte(in)), &v); err != nil {
		t.Fatalf("strip failed: %v\n%s", err, stripJSONC([]byte(in)))
	}
	if v["a"] != "http://x//y /*not*/" || v["d"] != `" // \` {
		t.Errorf("strings mangled: %v", v)
	}
}

func TestDevcontainerByBasename(t *testing.T) {
	for _, p := range []string{
		".devcontainer/devcontainer.json",
		".devcontainer.json",
		".devcontainer/go/devcontainer.json",
	} {
		pr := ByBasename(p)
		if pr == nil || pr.Kind != "devcontainer.json" {
			t.Errorf("ByBasename(%s) = %v", p, pr)
		}
	}
}
