package render

import (
	"strings"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// registryLink returns the public registry page for the version a change
// introduces (or, for removals, the version it removes), so markdown
// output can make package names clickable. It returns "" when the
// ecosystem has no linkable registry or when the name/version contains
// characters that could break a markdown link (pnpm peer-suffixes like
// "1.2.3(react@18.0.0)", git refs, and other oddities simply don't link).
func registryLink(c diffx.Change) string {
	if !urlSafe(c.Name) {
		return ""
	}
	v := ""
	if c.Kind == diffx.Removed {
		if len(c.Old) == 1 {
			v = c.Old[0]
		}
	} else if len(c.New) == 1 {
		v = c.New[0]
	}
	if !urlSafe(v) {
		v = "" // fall back to the package page without a version anchor
	}
	name := c.Name
	switch c.Ecosystem {
	case "npm":
		if v == "" {
			return "https://www.npmjs.com/package/" + name
		}
		return "https://www.npmjs.com/package/" + name + "/v/" + v
	case "crates.io":
		if v == "" {
			return "https://crates.io/crates/" + name
		}
		return "https://crates.io/crates/" + name + "/" + v
	case "PyPI":
		if v == "" {
			return "https://pypi.org/project/" + name + "/"
		}
		return "https://pypi.org/project/" + name + "/" + v + "/"
	case "Go":
		if v == "" {
			return "https://pkg.go.dev/" + name
		}
		// lockvet strips the "v" prefix when parsing Go versions.
		return "https://pkg.go.dev/" + name + "@v" + v
	case "Packagist":
		if v == "" {
			return "https://packagist.org/packages/" + name
		}
		return "https://packagist.org/packages/" + name + "#" + v
	case "RubyGems":
		if v == "" {
			return "https://rubygems.org/gems/" + name
		}
		return "https://rubygems.org/gems/" + name + "/versions/" + v
	case "Hex":
		if v == "" {
			return "https://hex.pm/packages/" + name
		}
		return "https://hex.pm/packages/" + name + "/" + v
	case "Pub":
		if v == "" {
			return "https://pub.dev/packages/" + name
		}
		return "https://pub.dev/packages/" + name + "/versions/" + v
	case "Maven":
		group, artifact, ok := strings.Cut(name, ":")
		if !ok || group == "" || artifact == "" {
			return ""
		}
		u := "https://central.sonatype.com/artifact/" + group + "/" + artifact
		if v != "" {
			u += "/" + v
		}
		return u
	case "NuGet":
		if v == "" {
			return "https://www.nuget.org/packages/" + name
		}
		return "https://www.nuget.org/packages/" + name + "/" + v
	case "CocoaPods":
		return "https://cocoapods.org/pods/" + name
	case "SwiftURL":
		// Swift package names are already "host/org/repo".
		return "https://" + name
	}
	return "" // Nix and anything unknown: no stable registry page
}

// urlSafe reports whether s can be embedded verbatim in a markdown link
// target. The allowlist covers real package names and versions (npm
// scopes, Go module paths, Maven coordinates, semver build metadata)
// while rejecting spaces, parens, brackets, quotes and backticks that
// would break the link or the surrounding markdown.
func urlSafe(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune(".-_+/@:~!", r):
		default:
			return false
		}
	}
	return true
}
