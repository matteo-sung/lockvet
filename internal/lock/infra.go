package lock

import (
	"errors"
	"strings"
)

// ---- .terraform.lock.hcl (Terraform / OpenTofu) ----
//
// provider "registry.terraform.io/hashicorp/aws" {
//   version     = "5.31.0"
//   constraints = "~> 5.0"
//   hashes = [ ... ]
// }
//
// Both Terraform and OpenTofu write this file (OpenTofu pins
// registry.opentofu.org/... addresses). The default registry host is
// stripped from names for readability; any other host is kept so custom
// registries stay unambiguous. Providers have no OSV.dev ecosystem, so
// changes are explained without vulnerability claims.

func parseTerraformLock(p string, data []byte) (*File, error) {
	f := newFile(p, ".terraform.lock.hcl", Terraform)
	name, version := "", ""
	inHashes := false
	pinHash := func(item string) {
		h := strings.Trim(strings.TrimSuffix(strings.TrimSpace(item), ","), `"`)
		if name != "" && version != "" &&
			(strings.HasPrefix(h, "h1:") || strings.HasPrefix(h, "zh:")) {
			f.setPin(name, version, h, "")
		}
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if inHashes {
			if strings.HasPrefix(line, "]") {
				inHashes = false
				continue
			}
			pinHash(line)
			continue
		}
		switch {
		case strings.HasPrefix(line, "provider ") && strings.HasSuffix(line, "{"):
			name, version = "", ""
			if q := strings.IndexByte(line, '"'); q >= 0 {
				rest := line[q+1:]
				if e := strings.IndexByte(rest, '"'); e > 0 {
					name = strings.TrimPrefix(rest[:e], "registry.terraform.io/")
				}
			}
		case line == "}":
			name, version = "", ""
		case name != "" && version == "" && strings.HasPrefix(line, "version"):
			rest := strings.TrimSpace(strings.TrimPrefix(line, "version"))
			if !strings.HasPrefix(rest, "=") {
				continue // e.g. a "versions" key; real field is version = "..."
			}
			v := strings.Trim(strings.TrimSpace(rest[1:]), `"`)
			if v != "" {
				f.add(name, v)
				version = v
			}
		case name != "" && strings.HasPrefix(line, "hashes"):
			// hashes = [ ... ] — usually multi-line, tolerate inline.
			open, close := strings.IndexByte(line, '['), strings.IndexByte(line, ']')
			if open >= 0 && close > open {
				for _, item := range strings.Split(line[open+1:close], ",") {
					pinHash(item)
				}
			} else if open >= 0 {
				inHashes = true
			}
		}
	}
	return f, nil
}

// ---- Chart.lock / requirements.lock (Helm) ----
//
// dependencies:
// - name: postgresql
//   repository: https://charts.bitnami.com/bitnami
//   version: 12.1.9
// digest: sha256:...
//
// Helm v3 writes Chart.lock; Helm v2 wrote the same shape as
// requirements.lock. Every entry is a direct dependency of the chart.
// Helm charts have no OSV.dev ecosystem.

func parseChartLock(p string, data []byte) (*File, error) {
	f := newFile(p, "Chart.lock", Helm)
	inDeps := false
	name, version := "", ""
	flush := func() {
		if name != "" && version != "" {
			f.add(name, version)
			f.addRoot(name)
		}
		name, version = "", ""
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "-") {
			// top-level key: dependencies:, digest:, generated:, ...
			flush()
			inDeps = trimmed == "dependencies:"
			continue
		}
		if !inDeps {
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
		switch strings.TrimSpace(key) {
		case "name":
			name = val
		case "version":
			version = val
		}
	}
	flush()
	if len(f.Packages) == 0 && !strings.Contains(string(data), "dependencies:") {
		return nil, errNotHelm
	}
	return f, nil
}

var errNotHelm = errors.New("not a Helm lockfile")

// parseRequirementsLock disambiguates "requirements.lock": Helm v2 charts
// used that name (YAML, same shape as Chart.lock), but some Python projects
// keep pip-frozen requirements under it too. Try Helm first, fall back to
// pip requirements syntax.
func parseRequirementsLock(p string, data []byte) (*File, error) {
	if f, err := parseChartLock(p, data); err == nil {
		f.Kind = "requirements.lock"
		return f, nil
	}
	f, err := parseRequirementsTxt(p, data)
	if err == nil {
		f.Kind = "requirements.lock"
	}
	return f, err
}
