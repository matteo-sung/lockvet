package lock

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ---- build.zig.zon (Zig) ----
//
// Zig has no lockfile and no central registry: build.zig.zon IS the pin
// file. Every dependency records a source archive URL and a content hash
// that `zig build` verifies before use:
//
//	.{
//	    .name = .zls,                       // 0.14+: enum literal; older: "zls"
//	    .version = "0.17.0-dev",
//	    .dependencies = .{
//	        .known_folders = .{
//	            .url = "https://github.com/ziglibs/known-folders/archive/207c34a1....tar.gz",
//	            .hash = "known_folders-0.0.0-Fy-PJsbKAACbDh9bBxR0...",  // 0.14+ shape
//	        },
//	        .diffz = .{
//	            .url = "git+https://github.com/ziglibs/diffz#d080c1eb...",
//	            .hash = "1220102cb2c669d82184fb1dc5380193d37d6...",     // pre-0.14 multihash
//	        },
//	        .local_thing = .{ .path = "../local" },
//	    },
//	}
//
// What lockvet reads out of it:
//
//   - a display version per dependency, best-first: the semver embedded in
//     a 0.14+ hash ("diffz-0.0.1-<digest>", unless it is the "unversioned"
//     0.0.0), a version-shaped tag from the URL (/archive/refs/tags/v1.2.tar.gz,
//     git+…#v1.2, ?ref=v1.2), the commit revision from the URL (shortened),
//     or finally a prefix of the content hash digest. Opaque rev/digest
//     "versions" are never ordered — diffx reports those bumps as
//     "changed ?" instead of pretending hex sorts mean something.
//   - the content hash as an integrity pin: same version, different hash
//     means the archive this pin expects was replaced (a moved tag, a
//     re-cut tarball, a hijacked mirror, or a hand-edited manifest).
//   - the source location as the resolution "host": for known forges the
//     owner/repo path is included, so a dependency silently re-pointed at
//     a different repository surfaces as a resolution move (mirror hosts
//     like deps.files.ghostty.org compare by hostname). A move whose hash
//     is unchanged is content-proven identical and stays quiet.
//   - forge URLs also become PkgRepo, so verified tag compare links and
//     -changelogs work for tag/semver pins, and rev...rev compare links
//     (internal/flakereg) for commit pins.
//   - .path dependencies are local source — nothing is pinned, nothing to
//     verify — and are skipped entirely, like flake follows-only nodes.
//
// There is no Zig OSV ecosystem and no registry to consult, so no
// vulnerability, age or unlisted claims are made — honesty over noise.

func parseZigZon(p string, data []byte) (*File, error) {
	root, err := zonParse(data)
	if err != nil {
		return nil, err
	}
	obj, ok := root.(zonStruct)
	if !ok {
		return nil, errors.New("build.zig.zon: top level is not a struct")
	}
	f := newFile(p, "build.zig.zon", Zig)
	deps, ok := obj.fields["dependencies"].(zonStruct)
	if !ok {
		return f, nil // no dependencies (leaf package): valid, empty
	}
	for name, v := range deps.fields {
		dep, ok := v.(zonStruct)
		if !ok {
			continue
		}
		if _, isPath := dep.fields["path"].(zonString); isPath {
			continue // local source: nothing pinned, nothing to verify
		}
		depURL, _ := dep.fields["url"].(zonString)
		hash, _ := dep.fields["hash"].(zonString)
		u, h := string(depURL), string(hash)

		hashVer := zigHashVersion(h)
		tag := zigURLTag(u)
		rev := zigURLRev(u)
		var version string
		switch {
		case rev != "":
			// The version string doubles as the integrity-pin key, so it
			// must change exactly when the pinned content changes. A
			// commit revision is that identity; the semver in the hash is
			// NOT (upstreams move revisions for months without bumping
			// their .version — keying on it would both hide routine
			// rev bumps entirely and turn them into false ‼ alarms).
			version = zigShort(rev)
		case hashVer != "" && hashVer != "0.0.0":
			// Tag or plain tarballs: the declared version is the identity
			// (re-cutting an already-released version = flag-worthy).
			// 0.0.0 is Zig's "unversioned" placeholder and identifies
			// nothing.
			version = hashVer
		case tag != "":
			version = tag
		case h != "":
			version = zigShort(zigHashDigest(h))
		default:
			continue // neither url+hash nor path: nothing usable
		}
		f.add(name, version)
		host := zigHost(u)
		if h != "" || host != "" {
			f.setPin(name, version, h, host)
		}
		if repo := zigRepoURL(u); repo != "" {
			if f.PkgRepo == nil {
				f.PkgRepo = map[string]string{}
			}
			f.PkgRepo[Sanitize(name)] = repo
		}
	}
	return f, nil
}

// zigDigestLen is the base64url length of the binary tail of a 0.14+
// package hash ("name-1.2.3-<digest>"): a 33-byte fingerprint+size+digest
// encodes to exactly 44 chars. The digest itself may contain '-', so the
// version is anchored from the right at this fixed width.
const zigDigestLen = 44

// zigHashVersion extracts the semver from a 0.14+ package hash
// ("name-1.2.3-<digest>"). Names are Zig identifiers (no dashes), so the
// version is everything between the first '-' and the digest tail;
// "N-V-<digest>" (no name/version recorded) and pre-0.14 hex multihashes
// return "".
func zigHashVersion(h string) string {
	cut := len(h) - zigDigestLen - 1
	if cut <= 0 || h[cut] != '-' || !isBase64URL(h[cut+1:]) {
		return "" // not the 0.14+ shape
	}
	rest := h[:cut] // name-1.2.3
	j := strings.IndexByte(rest, '-')
	if j < 0 {
		return ""
	}
	ver := rest[j+1:]
	if ver == "" || ver[0] < '0' || ver[0] > '9' || !strings.Contains(ver, ".") {
		return "" // "N-V" placeholder or something else entirely
	}
	return ver
}

// zigHashDigest returns the digest part of a hash: the fixed-width tail of
// a 0.14+ hash, or the hex after the "1220" multihash prefix, or the raw
// string when neither shape matches.
func zigHashDigest(h string) string {
	if cut := len(h) - zigDigestLen - 1; cut > 0 && h[cut] == '-' && isBase64URL(h[cut+1:]) {
		return h[cut+1:]
	}
	if len(h) > 4 && strings.HasPrefix(h, "1220") && isHex(h[4:]) {
		return h[4:]
	}
	return h
}

func isBase64URL(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c == '-' || c == '_' || c == '=') {
			return false
		}
	}
	return s != ""
}

// zigURLTag returns a version-shaped tag pinned in the URL:
// /archive/refs/tags/<tag>.tar.gz, git+…#<tag>, or ?ref=<tag>.
func zigURLTag(u string) string {
	if t, ok := cutRefsTags(u); ok {
		return t
	}
	for _, ref := range []string{zigFragment(u), zigQueryRef(u)} {
		if ref != "" && !isHex(ref) && zigVersionShaped(ref) {
			return ref
		}
	}
	return ""
}

func cutRefsTags(u string) (string, bool) {
	const marker = "/refs/tags/"
	i := strings.Index(u, marker)
	if i < 0 {
		return "", false
	}
	t := u[i+len(marker):]
	if j := strings.IndexAny(t, "?#"); j >= 0 {
		t = t[:j]
	}
	t = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(t,
		".tar.gz"), ".tar.xz"), ".zip")
	t = strings.TrimSuffix(t, ".tar")
	if t == "" || strings.Contains(t, "/") {
		return "", false
	}
	return t, true
}

// zigURLRev returns the commit revision pinned in the URL:
// /archive/<hex>.tar.gz or git+…#<hex>.
func zigURLRev(u string) string {
	if frag := zigFragment(u); len(frag) >= 7 && isHex(frag) {
		return frag
	}
	const marker = "/archive/"
	i := strings.Index(u, marker)
	if i < 0 {
		return ""
	}
	r := u[i+len(marker):]
	if j := strings.IndexAny(r, "?#"); j >= 0 {
		r = r[:j]
	}
	for _, suf := range []string{".tar.gz", ".tar.xz", ".zip", ".tar"} {
		r = strings.TrimSuffix(r, suf)
	}
	if len(r) >= 7 && isHex(r) {
		return r
	}
	return ""
}

func zigFragment(u string) string {
	i := strings.IndexByte(u, '#')
	if i < 0 {
		return ""
	}
	return u[i+1:]
}

func zigQueryRef(u string) string {
	i := strings.IndexByte(u, '?')
	if i < 0 {
		return ""
	}
	q := u[i+1:]
	if j := strings.IndexByte(q, '#'); j >= 0 {
		q = q[:j]
	}
	for _, kv := range strings.Split(q, "&") {
		if v, ok := strings.CutPrefix(kv, "ref="); ok {
			return v
		}
	}
	return ""
}

// zigVersionShaped reports whether s looks like a release tag rather than
// a branch name ("v0.13.1", "0.6.0", "1.2").
func zigVersionShaped(s string) bool {
	s = strings.TrimPrefix(s, "v")
	dot := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			dot = true
			continue
		}
		if c >= '0' && c <= '9' || c == '-' || c == '+' ||
			c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			continue
		}
		return false
	}
	return len(s) > 0 && s[0] >= '0' && s[0] <= '9' && dot
}

func zigShort(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// zigHost is the resolution identity for the pin: for known forges the
// owner/repo path is included so a re-point to a different repository on
// the same forge still surfaces; anything else compares by hostname.
func zigHost(rawURL string) string {
	repo := zigRepoURL(rawURL)
	if repo != "" {
		return strings.ToLower(strings.TrimPrefix(repo, "https://"))
	}
	u, err := url.Parse(strings.TrimPrefix(rawURL, "git+"))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// zigRepoURL maps a dependency URL to its browsable repository URL when
// the host is a known forge; "" otherwise (mirrors, plain tarball hosts).
func zigRepoURL(rawURL string) string {
	s := strings.TrimPrefix(rawURL, "git+")
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	switch host {
	case "github.com", "gitlab.com", "codeberg.org", "bitbucket.org", "git.sr.ht":
	default:
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return ""
	}
	owner, repo := parts[0], strings.TrimSuffix(parts[1], ".git")
	if owner == "" || repo == "" {
		return ""
	}
	return "https://" + host + "/" + owner + "/" + repo
}

// ---- minimal ZON reader ----
//
// Just enough of Zig Object Notation for build.zig.zon: anonymous structs
// (.{ .field = value, ... } and tuples .{ a, b }), string literals with
// escapes, enum literals (.foo), @"quoted" identifiers, bare scalars
// (true, 0x..., 1.2), multiline string lines (\\...), and // comments.

type zonValue interface{}

type zonStruct struct{ fields map[string]zonValue }

type zonString string

type zonScalar string

type zonReader struct {
	data []byte
	pos  int
}

var errZon = errors.New("invalid ZON")

func zonParse(data []byte) (zonValue, error) {
	r := &zonReader{data: data}
	r.skipSpace()
	v, err := r.value(0)
	if err != nil {
		return nil, err
	}
	r.skipSpace()
	if r.pos != len(r.data) {
		return nil, fmt.Errorf("build.zig.zon: trailing data at byte %d", r.pos)
	}
	return v, nil
}

func (r *zonReader) skipSpace() {
	for r.pos < len(r.data) {
		c := r.data[r.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			r.pos++
		case c == '/' && r.pos+1 < len(r.data) && r.data[r.pos+1] == '/':
			for r.pos < len(r.data) && r.data[r.pos] != '\n' {
				r.pos++
			}
		default:
			return
		}
	}
}

func (r *zonReader) peek() byte {
	if r.pos >= len(r.data) {
		return 0
	}
	return r.data[r.pos]
}

const zonMaxDepth = 100

func (r *zonReader) value(depth int) (zonValue, error) {
	if depth > zonMaxDepth {
		return nil, errZon
	}
	switch c := r.peek(); {
	case c == '.':
		// .{ struct/tuple }, .enum_literal, or .@"quoted enum"
		if r.pos+1 < len(r.data) && r.data[r.pos+1] == '{' {
			r.pos += 2
			return r.structBody(depth + 1)
		}
		r.pos++
		name, err := r.identifier()
		if err != nil {
			return nil, err
		}
		return zonScalar("." + name), nil
	case c == '"':
		s, err := r.stringLit()
		return zonString(s), err
	case c == '\\':
		return r.multiline()
	case c == 0:
		return nil, errZon
	default:
		return r.scalar()
	}
}

// structBody parses fields after ".{": either .name = value pairs or bare
// tuple elements, in any mix (real files are one or the other).
func (r *zonReader) structBody(depth int) (zonValue, error) {
	st := zonStruct{fields: map[string]zonValue{}}
	for {
		r.skipSpace()
		if r.peek() == '}' {
			r.pos++
			return st, nil
		}
		if r.peek() == '.' && r.pos+1 < len(r.data) && r.data[r.pos+1] != '{' {
			// Could be a field (.name = ...) or an enum literal element.
			save := r.pos
			r.pos++
			name, err := r.identifier()
			if err != nil {
				return nil, err
			}
			r.skipSpace()
			if r.peek() == '=' {
				r.pos++
				r.skipSpace()
				v, err := r.value(depth + 1)
				if err != nil {
					return nil, err
				}
				st.fields[name] = v
			} else {
				r.pos = save
				if _, err := r.value(depth + 1); err != nil { // tuple element
					return nil, err
				}
			}
		} else {
			if _, err := r.value(depth + 1); err != nil { // tuple element
				return nil, err
			}
		}
		r.skipSpace()
		switch r.peek() {
		case ',':
			r.pos++
		case '}':
		default:
			return nil, errZon
		}
	}
}

// identifier reads a plain identifier or @"quoted" form (already past '.').
func (r *zonReader) identifier() (string, error) {
	if r.peek() == '@' {
		r.pos++
		if r.peek() != '"' {
			return "", errZon
		}
		return r.stringLit()
	}
	start := r.pos
	for r.pos < len(r.data) {
		c := r.data[r.pos]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '_' {
			r.pos++
			continue
		}
		break
	}
	if r.pos == start {
		return "", errZon
	}
	return string(r.data[start:r.pos]), nil
}

func (r *zonReader) stringLit() (string, error) {
	if r.peek() != '"' {
		return "", errZon
	}
	r.pos++
	var b strings.Builder
	for r.pos < len(r.data) {
		c := r.data[r.pos]
		switch c {
		case '"':
			r.pos++
			return b.String(), nil
		case '\\':
			r.pos++
			if r.pos >= len(r.data) {
				return "", errZon
			}
			e := r.data[r.pos]
			r.pos++
			switch e {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case 'r':
				b.WriteByte('\r')
			case '\\', '"', '\'':
				b.WriteByte(e)
			case 'x':
				if r.pos+2 <= len(r.data) {
					r.pos += 2 // keep it simple: skip the two hex digits
				}
				b.WriteByte('?')
			case 'u':
				for r.pos < len(r.data) && r.data[r.pos] != '}' {
					r.pos++
				}
				if r.pos < len(r.data) {
					r.pos++
				}
				b.WriteByte('?')
			default:
				b.WriteByte(e)
			}
		case '\n':
			return "", errZon // ZON strings don't span lines
		default:
			b.WriteByte(c)
			r.pos++
		}
	}
	return "", errZon
}

// multiline consumes \\-prefixed string lines and returns them joined.
func (r *zonReader) multiline() (zonValue, error) {
	var b strings.Builder
	for r.peek() == '\\' && r.pos+1 < len(r.data) && r.data[r.pos+1] == '\\' {
		r.pos += 2
		start := r.pos
		for r.pos < len(r.data) && r.data[r.pos] != '\n' {
			r.pos++
		}
		b.Write(r.data[start:r.pos])
		r.skipSpace()
	}
	if b.Len() == 0 {
		return nil, errZon
	}
	return zonString(b.String()), nil
}

// scalar reads a bare token: true, false, null, numbers (0x..., 1.2, 1_000).
func (r *zonReader) scalar() (zonValue, error) {
	start := r.pos
	for r.pos < len(r.data) {
		c := r.data[r.pos]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '_' || c == '.' ||
			c == '-' || c == '+' {
			r.pos++
			continue
		}
		break
	}
	if r.pos == start {
		return nil, errZon
	}
	return zonScalar(string(r.data[start:r.pos])), nil
}
