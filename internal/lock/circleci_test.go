package lock

import "testing"

const circleConfig = `version: 2.1

orbs:
  node: circleci/node@5.1.0
  slack: circleci/slack@volatile
  aws: circleci/aws-cli@4
  dev-orb: my-ns/tools@dev:alpha
  templated: circleci/thing@<<pipeline.parameters.v>>
  inline:
    commands:
      greet:
        steps:
          - run: echo hi

jobs:
  build:
    docker:
      - image: cimg/node:18.16
        auth:
          username: user
      - image: cimg/postgres:14.2
    steps:
      - checkout
      - run: |
          echo "image: fake/inside-block:1.0"
      - run:
          command: |
            docker run image: also/fake:2.0
  deploy:
    machine:
      image: ubuntu-2204:2024.01.1
    steps:
      - run: make deploy
`

func TestParseCircleCI(t *testing.T) {
	f, err := parseCircleCI(".circleci/config.yml", []byte(circleConfig))
	if err != nil {
		t.Fatal(err)
	}
	wantOrb := map[string]string{
		"circleci/node":    "5.1.0",
		"circleci/slack":   "volatile",
		"circleci/aws-cli": "4",
		"my-ns/tools":      "dev:alpha",
	}
	for name, ver := range wantOrb {
		vs := f.Packages[name]
		if len(vs) != 1 || vs[0] != ver {
			t.Errorf("orb %s = %v, want [%s]", name, vs, ver)
		}
		if f.PkgEco[Sanitize(name)] != CircleCI {
			t.Errorf("orb %s eco = %q, want CircleCI", name, f.PkgEco[Sanitize(name)])
		}
	}
	if !f.NonRegistry["my-ns/tools"] {
		t.Error("dev: orb version should be NonRegistry")
	}
	if f.NonRegistry["circleci/node"] {
		t.Error("exact orb pin must not be NonRegistry")
	}
	if _, ok := f.Packages["circleci/thing"]; ok {
		t.Error("templated orb version must pin nothing")
	}
	if _, ok := f.Packages["inline"]; ok {
		t.Error("inline orb definition must pin nothing")
	}
	// Docker executor images: both entries, ecosystem Docker (file-level).
	for _, img := range []string{"cimg/node", "cimg/postgres"} {
		if _, ok := f.Packages[img]; !ok {
			t.Errorf("docker executor image %s missing: %v", img, f.Packages)
		}
	}
	// machine: images are CircleCI VM labels, not OCI refs.
	if _, ok := f.Packages["ubuntu-2204"]; ok {
		t.Error("machine image must not be treated as an OCI pull")
	}
	// Block scalars are opaque.
	for name := range f.Packages {
		if name == "fake/inside-block" || name == "also/fake" {
			t.Errorf("block-scalar content leaked as pin: %s", name)
		}
	}
}

func TestCircleCILenientGate(t *testing.T) {
	notCI := []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n")
	f, err := circleCILenient(".circleci/extra.yml", notCI)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Packages) != 0 {
		t.Errorf("non-CI YAML under .circleci/ should parse empty, got %v", f.Packages)
	}
	ci := []byte("version: 2.1\njobs:\n  build:\n    docker:\n      - image: cimg/base:2024.01\n")
	f, err = circleCILenient(".circleci/continue.yml", ci)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Packages["cimg/base"]; !ok {
		t.Errorf("CI-shaped continuation config should parse, got %v", f.Packages)
	}
}

func TestCircleCIRoute(t *testing.T) {
	for _, p := range []string{".circleci/config.yml", "sub/.circleci/config.yaml"} {
		if pr := ByBasename(p); pr == nil || pr.Kind != "circleci" {
			t.Errorf("ByBasename(%s) = %v, want circleci parser", p, pr)
		}
	}
	if pr := ByBasename("circleci/config.yml"); pr != nil && pr.Kind == "circleci" {
		t.Error("plain circleci/ dir (no dot) must not route to the CircleCI parser")
	}
	if pr := ByBasename(".circleci/config.txt"); pr != nil && pr.Kind == "circleci" {
		t.Error("non-YAML under .circleci/ must not route to the CircleCI parser")
	}
}
