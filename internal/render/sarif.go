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
			what := describeChange(c)
			via := ""
			if len(c.Via) > 0 {
				via = " Pulled in via " + strings.Join(c.Via, " › ") + "."
			}
			locs := locate(fd.Path, c)

			for _, v := range c.IntroducedVulns {
				idx := vulnRule(v)
				msg := fmt.Sprintf("%s, which is affected by %s%s.%s%s",
					what, v.ID, sevParen(v.Severity), summaryClause(v), via)
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
				msg := fmt.Sprintf("%s, which is still affected by %s%s (the old version was too — this change does not fix it).%s%s",
					what, v.ID, sevParen(v.Severity), summaryClause(v), via)
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
			if c.Deprecated {
				idx := addRule(rule{
					ID:               "deprecated-package",
					ShortDescription: map[string]string{"text": "Incoming version is marked deprecated by its registry"},
					HelpURI:          "https://github.com/matteo-sung/lockvet#deprecations",
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
func describeChange(c diffx.Change) string {
	to := strings.Join(c.New, ", ")
	switch c.Kind {
	case diffx.Added:
		return fmt.Sprintf("%s was added at %s", c.Name, to)
	case diffx.Removed:
		return fmt.Sprintf("%s was removed (was %s)", c.Name, strings.Join(c.Old, ", "))
	case diffx.Downgraded:
		return fmt.Sprintf("%s was downgraded to %s", c.Name, to)
	case diffx.Changed:
		return fmt.Sprintf("%s changed to %s", c.Name, to)
	default:
		return fmt.Sprintf("%s was upgraded to %s", c.Name, to)
	}
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
