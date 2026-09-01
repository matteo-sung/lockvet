package lock

import (
	"regexp"
	"strings"
)

// ---- rebar.lock (Erlang / rebar3) ----
//
//	{"1.2.0",
//	[{<<"certifi">>,{pkg,<<"certifi">>,<<"2.12.0">>},1},
//	 {<<"uuid">>,{pkg,<<"uuid_erl">>,<<"2.0.1">>},0},
//	 {<<"cowboy">>,
//	  {git,"https://github.com/ninenines/cowboy.git",
//	       {ref,"72d5f6c0…"}},
//	  0}]}.
//	[
//	{pkg_hash,[
//	 {<<"certifi">>, <<"2D1CCA2E…">>}]},
//	{pkg_hash_ext,[
//	 {<<"certifi">>, <<"26D1DCC8…">>}]}].
//
// Only {pkg,…} entries carry a hex.pm version; {git,…}/{path,…} entries
// pin a commit, not a release, and are skipped (mix.lock precedent —
// hex.pm knows nothing about them). The outer key is the OTP application
// name; the Hex PACKAGE name is the second element of the pkg tuple —
// they differ for renamed forks ({<<"uuid">>,{pkg,<<"uuid_erl">>,…}}),
// and the package name is what hex.pm and OSV know, so that is the name
// lockvet reports. The trailing integer is the dependency level: level 0
// entries are the project's direct dependencies. pkg_hash (inner, sha256
// of the tarball contents) and pkg_hash_ext (outer, sha256 of the
// tarball — format "1.2.0"+) are keyed by the application name and become
// integrity pins: hex.pm tarballs are immutable per version, so a
// same-version checksum change means the artifact moved.

var rebarPkgRe = regexp.MustCompile(
	`\{<<"([^"]+)">>,\s*\{pkg,\s*<<"([^"]+)">>,\s*<<"([^"]+)">>[^{}]*\},\s*(\d+)\}`)

// The hash value is captured loosely and labeled sha256 (both rebar3
// checksum fields are sha256 by spec) so malformed-width swaps compare
// within the algorithm instead of dropping out of the hash set.
var rebarHashRe = regexp.MustCompile(`\{<<"([^"]+)">>,\s*<<"([^"]+)">>\}`)

func parseRebarLock(p string, data []byte) (*File, error) {
	f := newFile(p, "rebar.lock", Hex)
	s := string(data)

	// Hash attr blocks sit after the main entry list; scope each regex
	// sweep to its own block so app-name/hash pairs never cross over.
	inner := map[string]string{}
	outer := map[string]string{}
	hashBlock := func(marker string, into map[string]string) {
		i := strings.Index(s, marker)
		if i < 0 {
			return
		}
		rest := s[i+len(marker):]
		if end := strings.Index(rest, "]}"); end >= 0 {
			rest = rest[:end]
		}
		for _, m := range rebarHashRe.FindAllStringSubmatch(rest, -1) {
			into[m[1]] = "sha256:" + strings.ToLower(m[2])
		}
	}
	hashBlock("{pkg_hash,", inner)
	hashBlock("{pkg_hash_ext,", outer)

	// Entries only up to the first attr block, so hash pairs (which the
	// entry regex cannot match anyway) stay out of scope on principle.
	entries := s
	if i := strings.Index(s, "{pkg_hash"); i >= 0 {
		entries = s[:i]
	}
	for _, m := range rebarPkgRe.FindAllStringSubmatch(entries, -1) {
		app, pkg, version, level := m[1], m[2], m[3], m[4]
		f.add(pkg, version)
		hashes := inner[app]
		if h := outer[app]; h != "" {
			hashes = strings.TrimSpace(hashes + " " + h)
		}
		f.setPin(pkg, version, hashes, "")
		if level == "0" {
			f.addRoot(pkg)
		}
	}
	return f, nil
}
