package render

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// SARIF writes the diff as a SARIF 2.1.0 log suitable for GitHub Code
// Scanning (and any other SARIF consumer). Findings:
//
//   - a vulnerability introduced by an incoming version  → error/warning
//   - a known vulnerability the change still doesn't fix → note
//   - an incoming version its own registry marks deprecated → warning
//
// contents, when non-nil, returns the new-side bytes of a lockfile path so
// results can point at the exact line that names the package; without it
// (or when the package isn't found) results point at line 1.
func SARIF(w io.Writer, diffs []diffx.FileDiff, toolVersion string, contents func(path string) []byte) error {
	return sarif(w, diffs, toolVersion, contents, false)
}

// SARIFAudit is SARIF for `lockvet audit`, where every package is reported
// against the current pin rather than a change ("is pinned at", not "was
// added at").
func SARIFAudit(w io.Writer, diffs []diffx.FileDiff, toolVersion string, contents func(path string) []byte) error {
	return sarif(w, diffs, toolVersion, contents, true)
}

func sarif(w io.Writer, diffs []diffx.FileDiff, toolVersion string, contents func(path string) []byte, audit bool) error {
	type rule struct {
		ID   string `json:"id"`
		Name string `json:"name,omitempty"`
		//nolint:staticcheck
		ShortDescription map[string]string `json:"shortDescription,omitempty"`
		FullDescription  map[string]string `json:"fullDescription,omitempty"`
		HelpURI          string            `json:"helpUri,omitempty"`
		Help             map[string]string `json:"help,omitempty"`
		Properties       map[string]any    `json:"properties,omitempty"`
	}
	type artifactLocation struct {
		URI string `json:"uri"`
	}
	type region struct {
		StartLine int `json:"startLine"`
	}
	type physicalLocation struct {
		ArtifactLocation artifactLocation `json:"artifactLocation"`
		Region           region           `json:"region"`
	}
	type location struct {
		PhysicalLocation physicalLocation `json:"physicalLocation"`
	}
	type result struct {
		RuleID              string            `json:"ruleId"`
		RuleIndex           int               `json:"ruleIndex"`
		Level               string            `json:"level"`
		Message             map[string]string `json:"message"`
		Locations           []location        `json:"locations"`
		PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	}

	var (
		rules     []rule
		ruleIndex = map[string]int{}
		results   []result
	)
	addRule := func(r rule) int {
		if i, ok := ruleIndex[r.ID]; ok {
			return i
		}
		ruleIndex[r.ID] = len(rules)
		rules = append(rules, r)
		return len(rules) - 1
	}
	vulnRule := func(v diffx.Vuln) int {
		short := v.ID
		if v.Summary != "" {
			short = v.ID + ": " + v.Summary
		}
		r := rule{
			ID:               v.ID,
			ShortDescription: map[string]string{"text": short},
			HelpURI:          v.URL,
			Properties: map[string]any{
				"tags": []string{"security", "vulnerability"},
			},
		}
		if v.Summary != "" {
			r.FullDescription = map[string]string{"text": v.Summary}
			r.Help = map[string]string{"text": v.Summary}
		}
		if s := securitySeverity(v.Severity); s != "" {
			r.Properties["security-severity"] = s
		}
		return addRule(r)
	}

	locate := func(path string, c diffx.Change) []location {
		line := 1
		if contents != nil {
			if data := contents(path); data != nil {
				line = lineOf(data, c.Name, c.New)
			}
		}
		return []location{{PhysicalLocation: physicalLocation{
			ArtifactLocation: artifactLocation{URI: path},
			Region:           region{StartLine: line},
		}}}
	}

	for _, fd := range diffs {
		for _, c := range fd.Changes {
			what := describeChange(c, audit)
			via := ""
			if len(c.Via) > 0 {
				via = " Pulled in via " + strings.Join(c.Via, " › ") + "."
			}
			locs := locate(fd.Path, c)

			for _, v := range c.IntroducedVulns {
				idx := vulnRule(v)
				msg := fmt.Sprintf("%s, which is affected by %s%s.%s%s%s",
					what, v.ID, sevParen(v.Severity), summaryClause(v), fixClause(v), via)
				results = append(results, result{
					RuleID: v.ID, RuleIndex: idx,
					Level:     vulnLevel(v.Severity),
					Message:   map[string]string{"text": msg},
					Locations: locs,
					PartialFingerprints: map[string]string{
						"lockvetFinding": fingerprint(fd.Path, c.Name, v.ID),
					},
				})
			}
			for _, v := range c.ExistingVulns {
				idx := vulnRule(v)
				msg := fmt.Sprintf("%s, which is still affected by %s%s (the old version was too — this change does not fix it).%s%s%s",
					what, v.ID, sevParen(v.Severity), summaryClause(v), fixClause(v), via)
				results = append(results, result{
					RuleID: v.ID, RuleIndex: idx,
					Level:     "note",
					Message:   map[string]string{"text": msg},
					Locations: locs,
					PartialFingerprints: map[string]string{
						"lockvetFinding": fingerprint(fd.Path, c.Name, v.ID),
					},
				})
			}
			if c.Unlisted {
				idx := addRule(rule{
					ID:               "unlisted-version",
					ShortDescription: map[string]string{"text": "Incoming version is missing from the registry index"},
					HelpURI:          "https://github.com/matteo-sung/lockvet#versions-missing-from-the-registry",
					Properties:       map[string]any{"tags": []string{"security", "supply-chain"}},
				})
				results = append(results, result{
					RuleID: "unlisted-version", RuleIndex: idx,
					Level:     "warning",
					Message:   map[string]string{"text": unlistedText(c, what, via)},
					Locations: locs,
					PartialFingerprints: map[string]string{
						"lockvetFinding": fingerprint(fd.Path, c.Name, "unlisted"),
					},
				})
			}
			if c.TyposquatOf != "" {
				idx := addRule(rule{
					ID:               "typosquat-suspect",
					ShortDescription: map[string]string{"text": "New dependency's name is one edit away from a popular package"},
					HelpURI:          "https://github.com/matteo-sung/lockvet#typosquat-suspects",
					Properties:       map[string]any{"tags": []string{"security", "supply-chain"}},
				})
				results = append(results, result{
					RuleID: "typosquat-suspect", RuleIndex: idx,
					Level:     "warning",
					Message:   map[string]string{"text": fmt.Sprintf("%s: the name is at most one edit away from the popular package '%s' on the same registry, and the release is young or of unknown age — the shape of a typosquatting attack. Make sure this is the package you meant.%s", what, c.TyposquatOf, via)},
					Locations: locs,
					PartialFingerprints: map[string]string{
						"lockvetFinding": fingerprint(fd.Path, c.Name, "typosquat"),
					},
				})
			}
			if c.IntegrityChanged {
				idx := addRule(rule{
					ID:               "integrity-changed",
					ShortDescription: map[string]string{"text": "Pinned version's content hash changed without a version change"},
					HelpURI:          "https://github.com/matteo-sung/lockvet#integrity--resolution-changes",
					Properties:       map[string]any{"tags": []string{"security", "supply-chain"}},
				})
				results = append(results, result{
					RuleID: "integrity-changed", RuleIndex: idx,
					Level:     "error",
					Message:   map[string]string{"text": integrityMessage(c, what, via)},
					Locations: locs,
					PartialFingerprints: map[string]string{
						"lockvetFinding": fingerprint(fd.Path, c.Name, "integrity"),
					},
				})
			}
			if c.TagMismatch {
				idx := addRule(rule{
					ID:               "tag-mismatch",
					ShortDescription: map[string]string{"text": "Pinned commit does not match the upstream release tag"},
					HelpURI:          "https://github.com/matteo-sung/lockvet#integrity--resolution-changes",
					Properties:       map[string]any{"tags": []string{"security", "supply-chain"}},
				})
				text := fmt.Sprintf("%s, but the pinned commit is not what the upstream repository's release tag points at today (%s). Released tags are supposed to be immutable — either the tag has been re-pointed since this was resolved, or the lockfile was edited to fetch a different commit while displaying an innocent version. Verify the commit before trusting it.%s", what, strings.Join(c.TagMismatches, "; "), via)
				if c.Ecosystem == "Docker" {
					text = fmt.Sprintf("%s, but the pinned digest is not what the registry serves for this tag today (%s). Image tags do move — the tag may simply have been rebuilt since this pin was made (re-pin to refresh) — but a pin that never came from this registry looks the same. Verify before trusting.%s", what, strings.Join(c.TagMismatches, "; "), via)
				}
				results = append(results, result{
					RuleID: "tag-mismatch", RuleIndex: idx,
					Level:     "error",
					Message:   map[string]string{"text": text},
					Locations: locs,
					PartialFingerprints: map[string]string{
						"lockvetFinding": fingerprint(fd.Path, c.Name, "tag-mismatch"),
					},
				})
			}
			if c.RegistryMoved {
				idx := addRule(rule{
					ID:               "registry-moved",
					ShortDescription: map[string]string{"text": "Resolution moved from a private host to the public registry"},
					HelpURI:          "https://github.com/matteo-sung/lockvet#integrity--resolution-changes",
					Properties:       map[string]any{"tags": []string{"security", "supply-chain"}},
				})
				results = append(results, result{
					RuleID: "registry-moved", RuleIndex: idx,
					Level:     "warning",
					Message:   map[string]string{"text": movedMessage(c, what, via)},
					Locations: locs,
					PartialFingerprints: map[string]string{
						"lockvetFinding": fingerprint(fd.Path, c.Name, "registry"),
					},
				})
			}
			if c.ScriptsAdded {
				idx := addRule(rule{
					ID:               "install-scripts-added",
					ShortDescription: map[string]string{"text": "Bump adds install scripts where the old version ran none"},
					HelpURI:          "https://github.com/matteo-sung/lockvet#install-scripts-added-by-a-bump",
					Properties:       map[string]any{"tags": []string{"security", "supply-chain"}},
				})
				results = append(results, result{
					RuleID: "install-scripts-added", RuleIndex: idx,
					Level:     "warning",
					Message:   map[string]string{"text": fmt.Sprintf("%s: version %s runs install scripts (preinstall/install/postinstall) while the outgoing version ran none. Gaining execution-on-install in an ordinary-looking bump is how several real npm supply-chain attacks shipped their payload; review the release before trusting it.%s", what, strings.Join(c.ScriptedVersions, ", "), via)},
					Locations: locs,
					PartialFingerprints: map[string]string{
						"lockvetFinding": fingerprint(fd.Path, c.Name, "scripts"),
					},
				})
			}
			if c.ProvenanceDropped {
				idx := addRule(rule{
					ID:               "provenance-dropped",
					ShortDescription: map[string]string{"text": "Bump drops sigstore provenance where every previous version attested"},
					HelpURI:          "https://github.com/matteo-sung/lockvet#provenance-dropped-by-a-bump",
					Properties:       map[string]any{"tags": []string{"security", "supply-chain"}},
				})
				results = append(results, result{
					RuleID: "provenance-dropped", RuleIndex: idx,
					Level:     "warning",
					Message:   map[string]string{"text": fmt.Sprintf("%s: version %s carries no sigstore provenance attestation while every previous version of the package was published with one. Legitimate CI keeps attesting its releases; a stolen publish token can publish but cannot make the project's pipeline attest. Verify the release before trusting it.%s", what, strings.Join(c.UnattestedVersions, ", "), via)},
					Locations: locs,
					PartialFingerprints: map[string]string{
						"lockvetFinding": fingerprint(fd.Path, c.Name, "provenance"),
					},
				})
			}
			if c.Deprecated {
				idx := addRule(rule{
					ID:               "deprecated-package",
					ShortDescription: map[string]string{"text": "Incoming version is marked deprecated by its registry"},
					HelpURI:          "https://github.com/matteo-sung/lockvet#deprecations-and-license-changes",
					Properties:       map[string]any{"tags": []string{"maintainability"}},
				})
				reason := ""
				if c.DeprecatedReason != "" {
					reason = " Registry says: " + strings.TrimRight(c.DeprecatedReason, ".") + "."
				}
				results = append(results, result{
					RuleID: "deprecated-package", RuleIndex: idx,
					Level:     "warning",
					Message:   map[string]string{"text": fmt.Sprintf("%s, which its registry marks as deprecated.%s%s", what, reason, via)},
					Locations: locs,
					PartialFingerprints: map[string]string{
						"lockvetFinding": fingerprint(fd.Path, c.Name, "deprecated"),
					},
				})
			}
			if c.LicenseChanged {
				idx := addRule(rule{
					ID:               "license-change",
					ShortDescription: map[string]string{"text": "Incoming version is published under a different license"},
					HelpURI:          "https://github.com/matteo-sung/lockvet#deprecations-and-license-changes",
					Properties:       map[string]any{"tags": []string{"legal", "license"}},
				})
				results = append(results, result{
					RuleID: "license-change", RuleIndex: idx,
					Level:     "warning",
					Message:   map[string]string{"text": fmt.Sprintf("%s, which changes its license from %s to %s.%s", what, c.OldLicense, c.NewLicense, via)},
					Locations: locs,
					PartialFingerprints: map[string]string{
						"lockvetFinding": fingerprint(fd.Path, c.Name, "license-change"),
					},
				})
			}
		}
	}

	if results == nil {
		results = []result{}
	}
	if rules == nil {
		rules = []rule{}
	}
	log := map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{"driver": map[string]any{
				"name":           "lockvet",
				"informationUri": "https://github.com/matteo-sung/lockvet",
				"version":        strings.TrimPrefix(toolVersion, "v"),
				"rules":          rules,
			}},
			"results": results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// describeChange says what happened to the package in plain words:
// "lodash was upgraded to 4.17.19", "left-pad was added at 1.3.0", …
func describeChange(c diffx.Change, audit bool) string {
	to := strings.Join(c.New, ", ")
	if audit {
		return fmt.Sprintf("%s is pinned at %s", c.Name, to)
	}
	switch c.Kind {
	case diffx.Added:
		return fmt.Sprintf("%s was added at %s", c.Name, to)
	case diffx.Removed:
		return fmt.Sprintf("%s was removed (was %s)", c.Name, strings.Join(c.Old, ", "))
	case diffx.Downgraded:
		return fmt.Sprintf("%s was downgraded to %s", c.Name, to)
	case diffx.Repinned:
		return fmt.Sprintf("%s stays at %s", c.Name, to)
	case diffx.Changed:
		return fmt.Sprintf("%s changed to %s", c.Name, to)
	default:
		return fmt.Sprintf("%s was upgraded to %s", c.Name, to)
	}
}

// unlistedText phrases the unlisted finding for the ecosystem: workflow
// pins are checked against the action repository's tags, everything else
// against its registry index.
func unlistedText(c diffx.Change, what, via string) string {
	if c.Ecosystem == "GitHub Actions" {
		return fmt.Sprintf("%s, but pinned ref %s matches no tag in the action's repository. Release tags are how actions ship; the March-2025 tj-actions/changed-files attack pinned users to exactly such commits. Verify where the commit comes from.%s", what, strings.Join(c.UnlistedVersions, ", "), via)
	}
	if c.Ecosystem == "pre-commit" {
		return fmt.Sprintf("%s, but pinned rev %s matches no tag in the hook repository. pre-commit clones and runs this rev on every commit on every contributor's machine. Verify where it comes from.%s", what, strings.Join(c.UnlistedVersions, ", "), via)
	}
	if c.Ecosystem == "Docker" {
		return fmt.Sprintf("%s, but the image registry does not serve %s for this image. A deleted tag, the wrong repository, or a fabricated digest pin looks exactly like this. Verify before trusting.%s", what, strings.Join(c.UnlistedVersions, ", "), via)
	}
	return fmt.Sprintf("%s, but version %s is missing from the registry index even though other versions of the package are listed. Unpublished or deleted releases look exactly like this (registries pull malicious versions); a release published minutes ago may also not be indexed yet. Verify before trusting.%s", what, strings.Join(c.UnlistedVersions, ", "), via)
}

func fixClause(v diffx.Vuln) string {
	if v.FixedIn == "" {
		return ""
	}
	return " Fixed in " + v.FixedIn + "."
}

func summaryClause(v diffx.Vuln) string {
	if v.Summary == "" {
		return ""
	}
	return " " + strings.TrimRight(v.Summary, ".") + "."
}

func sevParen(s string) string {
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

// vulnLevel maps OSV database severity words onto SARIF levels.
func vulnLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	default:
		return "warning"
	}
}

// securitySeverity maps severity words onto the numeric CVSS-like scale
// GitHub Code Scanning uses to bucket security alerts (as a string).
func securitySeverity(severity string) string {
	switch severity {
	case "critical":
		return "9.5"
	case "high":
		return "8.0"
	case "moderate", "medium":
		return "5.5"
	case "low":
		return "2.5"
	}
	return ""
}

// fingerprint identifies a finding stably across uploads so GitHub can
// track an alert even when the line number moves.
func fingerprint(path, pkg, id string) string {
	return path + ":" + pkg + ":" + id
}

// lineOf finds the 1-based line in data that most plausibly declares the
// package: the first line containing the name where one of the incoming
// versions appears on the same or one of the next three lines (npm, pnpm
// and friends put the version on a following line), else the first line
// containing the name, else 1.
func lineOf(data []byte, name string, versions []string) int {
	lines := bytes.Split(data, []byte("\n"))
	contains := func(ln []byte, ss []string) bool {
		for _, s := range ss {
			if s != "" && bytes.Contains(ln, []byte(s)) {
				return true
			}
		}
		return false
	}
	windowed, nameOnly := 0, 0
	for i, ln := range lines {
		if !bytes.Contains(ln, []byte(name)) {
			continue
		}
		if contains(ln, versions) {
			return i + 1 // name and version on one line: unambiguous
		}
		if windowed == 0 {
			for j := i + 1; j < len(lines) && j <= i+3; j++ {
				if contains(lines[j], versions) {
					windowed = i + 1
					break
				}
			}
		}
		if nameOnly == 0 {
			nameOnly = i + 1
		}
	}
	if windowed != 0 {
		return windowed
	}
	if nameOnly != 0 {
		return nameOnly
	}
	return 1
}

// integrityMessage words the integrity-changed finding for the ecosystem:
// registry artifacts are immutable by contract, git revisions by definition.
func integrityMessage(c diffx.Change, what, via string) string {
	if c.Ecosystem == "Nix" {
		return fmt.Sprintf("%s, but the lockfile now records a different narHash for %s. A git revision's content never changes, so the tree this pin expects was replaced (upstream rewritten, a hijacked mirror, or a hand-edited lockfile). Find out why before merging.%s", what, strings.Join(c.IntegrityVersions, ", "), via)
	}
	if c.Ecosystem == "Zig" {
		return fmt.Sprintf("%s, but build.zig.zon now records a different hash for %s. Zig verifies this hash against the fetched archive, so the source this pin expects was replaced (a moved tag, a re-cut tarball, a hijacked mirror, or a hand-edited manifest). Find out why before merging.%s", what, strings.Join(c.IntegrityVersions, ", "), via)
	}
	return fmt.Sprintf("%s, but the lockfile now records a different content hash for version %s. Registries never change a published artifact, so outside a registry migration the tarball this pin expects was replaced (registry-side tampering, a hijacked mirror, or a hand-edited lockfile). Find out why before merging.%s", what, strings.Join(c.IntegrityVersions, ", "), via)
}

// movedMessage words the resolution-moved finding for the ecosystem.
func movedMessage(c diffx.Change, what, via string) string {
	if c.Ecosystem == "Nix" {
		return fmt.Sprintf("%s and now fetches from %s instead of %s. A flake input that changes repository without you editing flake.nix means someone re-pointed your dependency; make sure the move was intentional.%s", what, c.NewHost, c.OldHost, via)
	}
	if c.Ecosystem == "Zig" {
		return fmt.Sprintf("%s and now fetches from %s instead of %s. A dependency that changes source without you editing build.zig.zon means someone re-pointed it; make sure the move was intentional.%s", what, c.NewHost, c.OldHost, via)
	}
	return fmt.Sprintf("%s and now resolves from %s instead of %s. A package that silently moves from a private host to the public registry is the shape of a dependency-confusion attack; make sure the public package is really yours.%s", what, c.NewHost, c.OldHost, via)
}
