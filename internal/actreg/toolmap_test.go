package actreg

import (
	"os"
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/taglink"
	"github.com/matteo-sung/lockvet/internal/vers"
)

func TestToolStyleRoundtrip(t *testing.T) {
	cases := []struct {
		style   toolStyle
		version string
		tag     string
	}{
		{toolStyle{"go", ".", ""}, "1.23.4", "go1.23.4"},
		{toolStyle{"v", "_", ""}, "3.3.4", "v3_3_4"},
		{toolStyle{"OTP-", ".", ""}, "27.1.2", "OTP-27.1.2"},
		{toolStyle{"jq-", ".", ""}, "1.7.1", "jq-1.7.1"},
		{toolStyle{"kustomize/v", ".", ""}, "5.4.3", "kustomize/v5.4.3"},
		{toolStyle{"swift-", ".", "-RELEASE"}, "5.10.1", "swift-5.10.1-RELEASE"},
		{toolStyle{"REL_", "_", ""}, "16.3", "REL_16_3"},
		{toolStyle{"php-", ".", ""}, "8.3.10", "php-8.3.10"},
		{toolStyle{"bun-v", ".", ""}, "1.1.20", "bun-v1.1.20"},
		{toolStyle{"@yarnpkg/cli/", ".", ""}, "4.9.2", "@yarnpkg/cli/4.9.2"},
	}
	for _, c := range cases {
		if got := c.style.tag(c.version); got != c.tag {
			t.Errorf("style %v tag(%s) = %s, want %s", c.style, c.version, got, c.tag)
		}
		if got := c.style.version(c.tag); got != c.version {
			t.Errorf("style %v version(%s) = %s, want %s", c.style, c.tag, got, c.version)
		}
	}
}

func TestToolResolveOffline(t *testing.T) {
	tags := map[string]string{
		"v22.4.0": "a1", "v22.5.1": "a2", "v20.15.0": "a3",
	}
	if got := toolResolve("node", "22", tags); got != "v22.5.1" {
		t.Errorf("fuzzy 22 = %q, want v22.5.1", got)
	}
	rubyTags := map[string]string{"v3_3_4": "b1", "v3_4_0_preview1": "b2"}
	if got := toolResolve("ruby", "3.3.4", rubyTags); got != "v3_3_4" {
		t.Errorf("ruby 3.3.4 = %q", got)
	}
	if got := toolResolve("ruby", "3.3", rubyTags); got != "v3_3_4" {
		t.Errorf("ruby fuzzy 3.3 = %q, want v3_3_4", got)
	}
	if got := toolResolve("ruby", "3.4", rubyTags); got != "" {
		t.Errorf("ruby fuzzy 3.4 must not resolve to a preview, got %q", got)
	}
	if got := toolResolve("nope-such-tool", "1.2.3", tags); got != "" {
		t.Errorf("unmapped tool resolved: %q", got)
	}
}

func TestToolExactShaped(t *testing.T) {
	for v, want := range map[string]bool{
		"1.2.3": true, "22.4": true, "v1.2.3": true,
		"22": false, "3.13t": false, "27.0-rc3": false,
		"temurin-21.0.2+13": false, "1.22.x": false, "": false,
	} {
		if got := toolExactShaped(v); got != want {
			t.Errorf("toolExactShaped(%q) = %v, want %v", v, got, want)
		}
	}
}

// TestToolMapLive validates EVERY curated map entry against the repo's
// real tags: the newest stable release must reverse-map through a style
// and roundtrip via toolResolve, and a fabricated version must not
// resolve. Network-gated: LOCKVET_LIVE=1 go test -run ToolMapLive.
func TestToolMapLive(t *testing.T) {
	if os.Getenv("LOCKVET_LIVE") == "" {
		t.Skip("set LOCKVET_LIVE=1 for live tag validation")
	}
	seen := map[string]bool{}
	for tool, ti := range toolRepos {
		if seen[ti.repo+"|"+styleKey(ti.styles)] {
			continue
		}
		seen[ti.repo+"|"+styleKey(ti.styles)] = true
		tags, _, err := taglink.Refs("https://github.com/" + ti.repo)
		if err != nil || len(tags) == 0 {
			t.Errorf("%s (%s): no refs (%v)", tool, ti.repo, err)
			continue
		}
		styles := append(append([]toolStyle{}, ti.styles...), defaultStyles...)
		best := ""
		for tag := range tags {
			for _, s := range styles {
				sv := strings.TrimPrefix(s.version(tag), "v")
				if sv == "" || !stableNumeric(sv) || !strings.Contains(sv, ".") {
					continue
				}
				if best == "" || vers.Compare(best, sv) < 0 {
					best = sv
				}
			}
		}
		if best == "" {
			t.Errorf("%s (%s): no stable version reverse-maps from %d tags", tool, ti.repo, len(tags))
			continue
		}
		if got := toolResolve(tool, best, tags); got == "" {
			t.Errorf("%s (%s): newest stable %s does not roundtrip", tool, ti.repo, best)
		} else {
			t.Logf("%s (%s): %s -> %s [%d tags]", tool, ti.repo, best, got, len(tags))
		}
		if got := toolResolve(tool, "99.99.99", tags); got != "" {
			t.Errorf("%s: fabricated 99.99.99 resolved to %q", tool, got)
		}
	}
}

func styleKey(ss []toolStyle) string {
	parts := make([]string, len(ss))
	for i, s := range ss {
		parts[i] = s.prefix + "|" + s.sep + "|" + s.suffix
	}
	return strings.Join(parts, ";")
}
