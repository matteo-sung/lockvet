package lock

import (
	"bytes"
	"encoding/json"
	"strings"
)

// parseDevcontainer reads the OCI pins out of a Dev Container
// configuration (devcontainer.json / .devcontainer.json): the base
// image named by "image", and every Feature referenced by an OCI
// registry ref in "features" (ghcr.io/devcontainers/features/go:1 and
// friends — Features are OCI artifacts, published and pulled through
// the same distribution API as images, so they get the same registry
// treatment). Codespaces and every devcontainer CLI resolve exactly
// these references, and Renovate's devcontainer manager bumps them.
//
// The file is JSONC per the spec — // and /* */ comments plus trailing
// commas are stripped before parsing (the VS Code templates ship with
// comments in them).
//
// Honestly skipped, with no claims: compose- and Dockerfile-based
// configurations (the Dockerfile/compose file itself is parsed
// separately when present), local-path Features (./feature),
// https:// tarball Features, and legacy shorthand Feature ids without
// a registry host — none of those name something a public registry
// serves under that string.
func parseDevcontainer(p string, data []byte) (*File, error) {
	f := newFile(p, "devcontainer.json", Docker)
	var doc struct {
		Image    string                     `json:"image"`
		Features map[string]json.RawMessage `json:"features"`
	}
	if err := json.Unmarshal(stripJSONC(data), &doc); err != nil {
		return nil, err
	}
	addImageRef(f, doc.Image, nil)
	for ref := range doc.Features {
		if r, ok := featureOCIRef(ref); ok {
			addImageRef(f, r, nil)
		}
	}
	rootsFromPackages(f)
	return f, nil
}

// featureOCIRef reports whether a Feature key is an OCI registry
// reference, returning it trimmed. Local paths, tarball URIs and
// host-less legacy ids are not registry refs.
func featureOCIRef(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.Contains(ref, "://") ||
		strings.HasPrefix(ref, ".") || strings.HasPrefix(ref, "/") {
		return "", false
	}
	i := strings.IndexByte(ref, '/')
	if i <= 0 || !looksLikeRegistryHost(ref[:i]) {
		return "", false
	}
	return ref, true
}

// stripJSONC removes // and /* */ comments and trailing commas from
// JSON-with-comments, respecting string literals. A leading UTF-8 BOM
// is dropped too. The result is plain JSON.
func stripJSONC(data []byte) []byte {
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	out := make([]byte, 0, len(data))
	inStr := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inStr {
			out = append(out, c)
			switch c {
			case '\\':
				if i+1 < len(data) {
					i++
					out = append(out, data[i])
				}
			case '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			if i < len(data) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			i++ // skip the '/' (loop increment skips the '*')
		case c == ',':
			// Trailing comma: a ',' whose next token is '}' or ']'.
			j := i + 1
			for j < len(data) {
				d := data[j]
				if d == ' ' || d == '\t' || d == '\r' || d == '\n' {
					j++
					continue
				}
				if d == '/' && j+1 < len(data) && data[j+1] == '/' {
					for j < len(data) && data[j] != '\n' {
						j++
					}
					continue
				}
				if d == '/' && j+1 < len(data) && data[j+1] == '*' {
					j += 2
					for j+1 < len(data) && !(data[j] == '*' && data[j+1] == '/') {
						j++
					}
					j += 2
					continue
				}
				break
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue // drop the comma
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}
