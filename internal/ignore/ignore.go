// Package ignore reads .lockvetignore files: acknowledged findings that
// should stop tripping -fail-on gates without turning the gate off.
//
// One rule per line. Blank lines and #-comments are skipped; a trailing
// "# reason" on a rule line is encouraged. Rules:
//
//	GHSA-xxxx-xxxx-xxxx              ignore one advisory wherever it appears
//	lodash                           ignore every finding for a package
//	lodash@4.17.21                   … only while a specific version is incoming
//	fresh:aws-sdk-go-v2              ignore one finding kind for a package
//	major:react@19.*                 accept a specific major bump
//	GHSA-xxxx-xxxx-xxxx until=2026-12-31   temporary, expires loudly
//
// Kinds: vuln, fresh, deprecated, unlisted, typosquat, scripts, provenance, integrity, registry, license,
// major, downgrade. Package names and advisory IDs match case-insensitively
// and accept * and ? globs. Suppressed findings stay in the JSON output
// (ignored / ignored_vulns) and appear as a dim marker in reports, but no
// longer count toward the summary or -fail-on.
package ignore

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// DefaultName is the filename discovered automatically.
const DefaultName = ".lockvetignore"

var kinds = map[string]string{
	"vuln": "vuln", "vulns": "vuln",
	"fresh":      "fresh",
	"deprecated": "deprecated",
	"unlisted":   "unlisted",
	"typosquat":  "typosquat", "typosquats": "typosquat",
	"scripts": "scripts", "install-scripts": "scripts",
	"provenance": "provenance",
	"integrity":  "integrity", "registry": "registry", "resolution": "registry",
	"license": "license", "licenses": "license",
	"major":     "major",
	"downgrade": "downgrade", "downgrades": "downgrade",
}

// Rule is one parsed .lockvetignore line.
type Rule struct {
	Raw     string // the line as written (comment stripped)
	Line    int
	Kind    string         // "" = all kinds; otherwise a canonical kind
	pattern *regexp.Regexp // package name or advisory ID
	version *regexp.Regexp // nil = any version
	Until   time.Time      // zero = never expires
}

func (r Rule) expired(now time.Time) bool {
	return !r.Until.IsZero() && !now.Before(r.Until.Add(24*time.Hour))
}

// Set is a parsed ignore file.
type Set struct {
	Path  string
	Rules []Rule
}

// Resolve loads the ignore rules for a run: nil when disabled, the
// explicit file when given (an error if it doesn't exist), otherwise
// dir/.lockvetignore when present.
func Resolve(explicit string, disable bool, dir string) (*Set, error) {
	if disable {
		return nil, nil
	}
	path := explicit
	if path == "" {
		if dir == "" {
			dir = "."
		}
		path = filepath.Join(dir, DefaultName)
		if _, err := os.Stat(path); err != nil {
			return nil, nil // no ignore file — the usual case
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read ignore file: %v", err)
	}
	return Parse(path, string(data))
}

// Parse parses ignore-file content. Errors carry path:line.
func Parse(path, content string) (*Set, error) {
	s := &Set{Path: path}
	for i, line := range strings.Split(content, "\n") {
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		r := Rule{Raw: strings.TrimSpace(line), Line: i + 1}
		pat := fields[0]
		for _, f := range fields[1:] {
			val, ok := strings.CutPrefix(f, "until=")
			if !ok {
				return nil, fmt.Errorf("%s:%d: unrecognized %q (only `until=YYYY-MM-DD` may follow the pattern; use # for comments)", path, i+1, f)
			}
			t, err := time.Parse("2006-01-02", val)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: bad date %q (want until=YYYY-MM-DD)", path, i+1, val)
			}
			r.Until = t
		}
		if k, spec, ok := strings.Cut(pat, ":"); ok && kinds[strings.ToLower(k)] != "" {
			r.Kind = kinds[strings.ToLower(k)]
			pat = spec
			if pat == "" {
				return nil, fmt.Errorf("%s:%d: %q needs a package after the colon (e.g. %s:lodash)", path, i+1, r.Raw, k)
			}
		}
		name, version := pat, ""
		if idx := strings.LastIndex(pat, "@"); idx > 0 { // >0 keeps @scope/pkg intact
			name, version = pat[:idx], pat[idx+1:]
		}
		r.pattern = compileGlob(name)
		if version != "" {
			r.version = compileGlob(version)
		}
		s.Rules = append(s.Rules, r)
	}
	return s, nil
}

// compileGlob turns a case-insensitive glob (* and ?) into a regexp.
func compileGlob(p string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?i)^")
	for _, r := range p {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

func (r Rule) matchesPkg(c *diffx.Change) bool {
	if !r.pattern.MatchString(c.Name) {
		return false
	}
	if r.version == nil {
		return true
	}
	for _, v := range c.New {
		if r.version.MatchString(v) {
			return true
		}
	}
	return false
}

// matchesVuln: a bare (kind-less, version-less) rule can also name an
// advisory ID directly, whatever package it appears on.
func (r Rule) matchesVuln(id string) bool {
	return r.Kind == "" && r.version == nil && r.pattern.MatchString(id)
}

// Apply suppresses matching findings in place. It returns the number of
// findings suppressed and warnings for expired rules (which no longer
// apply — remove or extend them).
func (s *Set) Apply(diffs []diffx.FileDiff, now time.Time) (int, []string) {
	if s == nil || len(s.Rules) == 0 {
		return 0, nil
	}
	var warnings []string
	active := make([]Rule, 0, len(s.Rules))
	for _, r := range s.Rules {
		if r.expired(now) {
			warnings = append(warnings, fmt.Sprintf("%s:%d: ignore rule %q expired %s — the finding counts again; remove the line or extend the date",
				s.Path, r.Line, r.Raw, r.Until.Format("2006-01-02")))
			continue
		}
		active = append(active, r)
	}
	total := 0
	for fi := range diffs {
		for ci := range diffs[fi].Changes {
			total += applyChange(&diffs[fi].Changes[ci], active)
		}
	}
	return total, warnings
}

func applyChange(c *diffx.Change, rules []Rule) int {
	n := 0
	mark := func(kind string) {
		if !c.HasIgnored(kind) {
			c.Ignored = append(c.Ignored, kind)
			n++
		}
	}
	for _, r := range rules {
		pkg := r.matchesPkg(c)

		// Advisories: by package (kind vuln or bare) or by advisory ID.
		if pkg && (r.Kind == "" || r.Kind == "vuln") || r.Kind == "" {
			var kept []diffx.Vuln
			for _, v := range c.IntroducedVulns {
				byPkg := pkg && (r.Kind == "" || r.Kind == "vuln")
				if byPkg || r.matchesVuln(v.ID) {
					c.IgnoredVulns = append(c.IgnoredVulns, v)
					n++
				} else {
					kept = append(kept, v)
				}
			}
			c.IntroducedVulns = kept
		}
		if !pkg {
			continue
		}
		all := r.Kind == ""
		if (all || r.Kind == "fresh") && c.Fresh {
			c.Fresh = false
			mark("fresh")
		}
		if (all || r.Kind == "deprecated") && c.Deprecated {
			c.Deprecated = false
			mark("deprecated")
		}
		if (all || r.Kind == "unlisted") && c.Unlisted {
			c.Unlisted = false
			mark("unlisted")
		}
		if (all || r.Kind == "typosquat") && c.TyposquatOf != "" {
			c.TyposquatOf = ""
			mark("typosquat")
		}
		if (all || r.Kind == "scripts") && c.ScriptsAdded {
			c.ScriptsAdded = false
			mark("scripts")
		}
		if (all || r.Kind == "provenance") && c.ProvenanceDropped {
			c.ProvenanceDropped = false
			mark("provenance")
		}
		if (all || r.Kind == "integrity") && c.IntegrityChanged {
			c.IntegrityChanged = false
			mark("integrity")
		}
		if (all || r.Kind == "registry") && c.RegistryMoved {
			c.RegistryMoved = false
			mark("registry")
		}
		if (all || r.Kind == "license") && c.LicenseChanged {
			c.LicenseChanged = false
			mark("license")
		}
		bump := c.Kind == diffx.Upgraded || c.Kind == diffx.Downgraded || c.Kind == diffx.Changed
		if (all || r.Kind == "major") && bump && c.Level == vers.Major {
			mark("major")
		}
		if (all || r.Kind == "downgrade") && c.Kind == diffx.Downgraded {
			mark("downgrade")
		}
	}
	return n
}
