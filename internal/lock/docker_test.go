package lock

import (
	"reflect"
	"testing"
)

func TestParseDockerfile(t *testing.T) {
	data := []byte(`# syntax=docker/dockerfile:1
ARG GO_VERSION=1.26
ARG BASE=alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
RUN go build ./...

FROM ${BASE} AS runtime
COPY --from=build /out/app /usr/bin/app
COPY --from=ghcr.io/acme/tool:v1.2.3 /tool /usr/bin/tool
COPY --from=0 /etc/ssl /etc/ssl

FROM scratch
COPY --from=runtime /usr/bin/app /app

FROM ${UNDECLARED_IMAGE}
FROM node:22-bookworm-slim@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
FROM registry.example.com:5000/team/svc:2.0
FROM quay.io/coreos/etcd@sha256:28759af54acd6924b2191dc1a1d096e2fa2e219717a21b9d8edf89717db3631b
`)
	f, err := parseDockerfile("Dockerfile", data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"docker/dockerfile":                  {"1"},
		"golang":                             {"1.26-alpine"},
		"alpine":                             {"3.21"},
		"ghcr.io/acme/tool":                  {"v1.2.3"},
		"node":                               {"22-bookworm-slim"},
		"registry.example.com:5000/team/svc": {"2.0"},
		"quay.io/coreos/etcd":                {"sha256:28759af54acd"},
	}
	if !reflect.DeepEqual(f.Packages, want) {
		t.Fatalf("packages = %v, want %v", f.Packages, want)
	}
	if got := f.Pin("alpine", "3.21").Integrity; got != "sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d" {
		t.Fatalf("alpine pin = %q", got)
	}
	if got := f.Pin("node", "22-bookworm-slim").Integrity; got == "" {
		t.Fatal("node digest pin missing")
	}
	if got := f.Pin("quay.io/coreos/etcd", "sha256:28759af54acd").Integrity; got == "" {
		t.Fatal("digest-only pin missing")
	}
	if !f.RootsKnown || len(f.Roots) != len(want) {
		t.Fatalf("roots = %v", f.Roots)
	}
}

func TestParseDockerfileContinuationsAndCase(t *testing.T) {
	data := []byte("from \\\n  ubuntu:24.04\nFROM MyStage\nFROM busybox\n")
	f, err := parseDockerfile("app.dockerfile", data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"ubuntu": {"24.04"}, "busybox": {"latest"}}
	if !reflect.DeepEqual(f.Packages, want) {
		t.Fatalf("packages = %v", f.Packages)
	}
}

func TestParseComposeFile(t *testing.T) {
	data := []byte(`version: "3.9"
services:
  web:
    image: nginx:1.27-alpine
    ports:
      - "80:80"
  db:
    image: "postgres:16.4@sha256:aaaa567890abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  cache:
    image: redis   # default tag
  custom:
    build: .
  templated:
    image: ${REGISTRY}/app:1.0
volumes:
  data:
    driver: local
    driver_opts:
      image: not-a-service-image
`)
	f, err := parseComposeFile("docker-compose.yml", data)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"nginx":    {"1.27-alpine"},
		"postgres": {"16.4"},
		"redis":    {"latest"},
	}
	if !reflect.DeepEqual(f.Packages, want) {
		t.Fatalf("packages = %v", f.Packages)
	}
	if f.Pin("postgres", "16.4").Integrity == "" {
		t.Fatal("postgres digest pin missing")
	}
}

func TestDockerByBasename(t *testing.T) {
	for _, p := range []string{
		"Dockerfile", "sub/dir/Dockerfile", "Containerfile", "Dockerfile.alpine",
		"dev.Dockerfile", "build.dockerfile", "docker-compose.yml", "compose.yaml",
		"docker-compose.prod.yml", "deploy/compose.override.yaml",
	} {
		if ByBasename(p) == nil {
			t.Errorf("ByBasename(%q) = nil", p)
		}
	}
	for _, p := range []string{"Dockerfileish", "composer.yml", "my-compose-notes.txt"} {
		if pr := ByBasename(p); pr != nil && pr.Ecosystem == Docker {
			t.Errorf("ByBasename(%q) matched Docker", p)
		}
	}
}

func TestImageHost(t *testing.T) {
	cases := []struct{ name, host, path string }{
		{"alpine", "docker.io", "library/alpine"},
		{"grafana/grafana", "docker.io", "grafana/grafana"},
		{"ghcr.io/acme/tool", "ghcr.io", "acme/tool"},
		{"registry.example.com:5000/team/svc", "registry.example.com:5000", "team/svc"},
		{"localhost/img", "localhost", "img"},
		{"mcr.microsoft.com/dotnet/runtime", "mcr.microsoft.com", "dotnet/runtime"},
	}
	for _, c := range cases {
		h, p := ImageHost(c.name)
		if h != c.host || p != c.path {
			t.Errorf("ImageHost(%q) = %q,%q want %q,%q", c.name, h, p, c.host, c.path)
		}
	}
}

func TestParseSyntaxDirective(t *testing.T) {
	data := []byte("# syntax=docker/dockerfile:1.26@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32\nFROM golang:1.26\n# syntax=ignored/after-instruction:9\n")
	f, err := parseDockerfile("Dockerfile", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["docker/dockerfile"]; len(got) != 1 || got[0] != "1.26" {
		t.Fatalf("syntax directive = %v", got)
	}
	if f.Pin("docker/dockerfile", "1.26").Integrity == "" {
		t.Fatal("syntax digest pin missing")
	}
	if _, ok := f.Packages["ignored/after-instruction"]; ok {
		t.Fatal("directive after first instruction must be ignored")
	}
}
