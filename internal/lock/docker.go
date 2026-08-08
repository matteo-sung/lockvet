package lock

import (
	"sort"
	"strings"
)

// parseDockerfile reads the base-image pins out of a Dockerfile (or
// Containerfile): every FROM instruction, plus external images named by
// COPY --from=. Multi-stage builds are understood — a FROM/COPY --from
// that names an earlier build stage (or a stage by index) is not an
// image. ARG defaults declared before use are substituted, so the
// Renovate-managed shape
//
//	ARG BASE=alpine:3.21
//	FROM ${BASE}
//
// resolves; a reference that still contains an unresolved variable is
// skipped rather than guessed at.
//
// The image name (registry host included, tag/digest excluded) is the
// package name; the tag is the version (an untagged reference means
// "latest", exactly as the daemon resolves it). A digest pin
// (image:tag@sha256:…) is recorded as the pinned integrity for that
// (name, tag); a digest-ONLY pin uses a short form of the digest as the
// displayed version, like other rev-pinned formats.
func parseDockerfile(p string, data []byte) (*File, error) {
	f := newFile(p, "Dockerfile", Docker)
	stages := map[string]bool{}
	args := map[string]string{}
	stageIdx := 0
	sawInstruction := false
	for _, raw := range joinContinuations(string(data)) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			// The `# syntax=docker/dockerfile:1.x` parser directive names a
			// real image BuildKit pulls to build this file — Renovate bumps
			// it like any other pin. Directives only count at the top of
			// the file, before the first instruction (Docker's own rule).
			if !sawInstruction {
				if ref, ok := parseSyntaxDirective(line); ok {
					addImageRef(f, expandArgs(ref, args), stages)
				}
			}
			continue
		}
		sawInstruction = true
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToUpper(fields[0]) {
		case "ARG":
			// ARG NAME=default — remember the default for substitution.
			for _, a := range fields[1:] {
				if eq := strings.IndexByte(a, '='); eq > 0 {
					args[a[:eq]] = strings.Trim(a[eq+1:], `"'`)
				}
			}
		case "FROM":
			rest := fields[1:]
			// Skip flags (--platform=…).
			for len(rest) > 0 && strings.HasPrefix(rest[0], "--") {
				rest = rest[1:]
			}
			if len(rest) == 0 {
				continue
			}
			ref := expandArgs(rest[0], args)
			// Record the stage name, whether or not the ref parses.
			if len(rest) >= 3 && strings.EqualFold(rest[1], "AS") {
				stages[strings.ToLower(rest[2])] = true
			}
			stages[itoa(stageIdx)] = true
			stageIdx++
			addImageRef(f, ref, stages)
		case "COPY":
			for _, a := range fields[1:] {
				if strings.HasPrefix(a, "--from=") {
					ref := expandArgs(strings.TrimPrefix(a, "--from="), args)
					addImageRef(f, ref, stages)
				}
			}
		}
	}
	rootsFromPackages(f)
	return f, nil
}

// parseComposeFile reads the images out of a Docker Compose file: every
// `image:` value under `services:`. Services built from a local
// Dockerfile (build: with no image:) have nothing to pin here; their
// Dockerfile is parsed separately. Values that still contain an
// unresolved ${VARIABLE} are skipped rather than guessed at.
func parseComposeFile(p string, data []byte) (*File, error) {
	f := newFile(p, "docker-compose.yml", Docker)
	lines := strings.Split(string(data), "\n")
	inServices := false
	for _, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " "))
		if indent == 0 {
			// A new top-level section starts (or ends) services.
			inServices = trimmed == "services:"
			continue
		}
		if !inServices {
			continue
		}
		if strings.HasPrefix(trimmed, "image:") {
			v := strings.TrimSpace(strings.TrimPrefix(trimmed, "image:"))
			v = strings.Trim(v, `"'`)
			if i := strings.Index(v, " #"); i >= 0 {
				v = strings.TrimSpace(v[:i])
			}
			addImageRef(f, v, nil)
		}
	}
	rootsFromPackages(f)
	return f, nil
}

// addImageRef parses one image reference and records it on the file.
// stages holds the build-stage names seen so far (Dockerfile only);
// references naming a stage, `scratch`, or containing unresolved
// variables are not images.
func addImageRef(f *File, ref string, stages map[string]bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.ContainsAny(ref, "$ \t") {
		return // unresolved variable or garbage
	}
	if stages[strings.ToLower(ref)] || strings.EqualFold(ref, "scratch") {
		return
	}
	name, tag, digest, ok := splitImageRef(ref)
	if !ok {
		return
	}
	version := tag
	if version == "" {
		if digest != "" {
			version = shortDigest(digest)
		} else {
			version = "latest"
		}
	}
	f.add(name, version)
	if digest != "" {
		f.setPin(name, version, digest, "")
	}
}

// splitImageRef splits an image reference into name (host + path, as
// written), tag and digest. Returns ok=false for shapes that cannot be
// an image reference.
func splitImageRef(ref string) (name, tag, digest string, ok bool) {
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		digest = ref[i+1:]
		ref = ref[:i]
		if !strings.HasPrefix(digest, "sha256:") && !strings.HasPrefix(digest, "sha512:") {
			return "", "", "", false
		}
	}
	// The tag is after the last ':' — but a ':' in the first component
	// may be a registry port (host:5000/img).
	if i := strings.LastIndexByte(ref, ':'); i >= 0 && i > strings.LastIndexByte(ref, '/') {
		name, tag = ref[:i], ref[i+1:]
	} else {
		name = ref
	}
	if name == "" || strings.HasPrefix(name, "-") || strings.ContainsAny(name, "\"'\\") {
		return "", "", "", false
	}
	// Image names are lowercase by spec; a reference with uppercase in
	// the path is a stage name or a mistake, not a pullable image (the
	// registry host itself is case-insensitive, so allow it there).
	path := name
	if i := strings.IndexByte(name, '/'); i >= 0 && looksLikeRegistryHost(name[:i]) {
		path = name[i+1:]
	}
	if path != strings.ToLower(path) {
		return "", "", "", false
	}
	return name, tag, digest, true
}

// parseSyntaxDirective recognizes the BuildKit parser directive
// `# syntax=<image-ref>` (case-insensitive key, optional whitespace
// around `=`) and returns the image reference.
func parseSyntaxDirective(line string) (string, bool) {
	if !strings.HasPrefix(line, "#") {
		return "", false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "#"))
	eq := strings.IndexByte(rest, '=')
	if eq < 0 || !strings.EqualFold(strings.TrimSpace(rest[:eq]), "syntax") {
		return "", false
	}
	ref := strings.TrimSpace(rest[eq+1:])
	if ref == "" || strings.ContainsAny(ref, " \t") {
		return "", false
	}
	return ref, true
}

// looksLikeRegistryHost reports whether the first path component of an
// image reference is a registry host (contains a dot, a port, or is
// "localhost") rather than a Docker Hub namespace.
func looksLikeRegistryHost(s string) bool {
	return strings.ContainsAny(s, ".:") || s == "localhost"
}

// ImageHost returns the registry host an image name resolves from and
// the repository path on that registry, following the daemon's rules:
// no host part means Docker Hub, and single-component Hub names live
// under library/.
func ImageHost(name string) (host, path string) {
	if i := strings.IndexByte(name, '/'); i >= 0 && looksLikeRegistryHost(name[:i]) {
		host, path = name[:i], name[i+1:]
		// Official images keep their library/ home even when the host is
		// written out: docker.io/nginx pulls library/nginx (the Hub API
		// answers a bare-path repo probe with a redirect, but every
		// deeper endpoint 404s without the prefix).
		if host == "docker.io" && !strings.Contains(path, "/") {
			path = "library/" + path
		}
		return host, path
	}
	if !strings.Contains(name, "/") {
		return "docker.io", "library/" + name
	}
	return "docker.io", name
}

// shortDigest renders a digest-only pin as a short displayable version,
// like rev-pinned formats display commit prefixes.
func shortDigest(d string) string {
	if i := strings.IndexByte(d, ':'); i >= 0 && len(d) > i+13 {
		return d[:i+13]
	}
	return d
}

// expandArgs substitutes ${NAME} and $NAME occurrences from declared
// ARG defaults. Unknown variables are left in place (the caller skips
// references that still contain '$').
func expandArgs(s string, args map[string]string) string {
	if !strings.Contains(s, "$") {
		return s
	}
	for k, v := range args {
		s = strings.ReplaceAll(s, "${"+k+"}", v)
		s = strings.ReplaceAll(s, "$"+k, v)
	}
	return s
}

// joinContinuations splits into lines, joining backslash-continued
// lines the way the Dockerfile parser does.
func joinContinuations(s string) []string {
	raw := strings.Split(s, "\n")
	out := make([]string, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		line := strings.TrimRight(raw[i], "\r")
		for strings.HasSuffix(line, "\\") && i+1 < len(raw) {
			i++
			line = line[:len(line)-1] + " " + strings.TrimSpace(strings.TrimRight(raw[i], "\r"))
		}
		out = append(out, line)
	}
	return out
}

// rootsFromPackages marks every parsed image as a direct dependency —
// base images have no transitive tree.
func rootsFromPackages(f *File) {
	for name := range f.Packages {
		f.Roots = append(f.Roots, name)
	}
	sort.Strings(f.Roots)
	f.RootsKnown = true
}

// itoa avoids importing strconv for tiny stage indexes.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
