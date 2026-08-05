package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

const sarifLockfile = `{
  "packages": {
    "node_modules/lodash": {
      "version": "4.17.19"
    },
    "node_modules/request": {
      "version": "2.88.2"
    }
  }
}`

func sarifDiffs() []diffx.FileDiff {
	return []diffx.FileDiff{{
		Path: "package-lock.json", Kind: "package-lock.json", Ecosystem: "npm",
		Changes: []diffx.Change{
			{
				Name: "lodash", Ecosystem: "npm", Kind: diffx.Upgraded,
				Old: []string{"4.17.15"}, New: []string{"4.17.19"},
				IntroducedVulns: []diffx.Vuln{{
					ID: "GHSA-35jh-r3h4-6jhm", Severity: "high",
					Summary: "Command injection in lodash",
					URL:     "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm",
				}},
				ExistingVulns: []diffx.Vuln{{
					ID: "GHSA-29mw-wpgm-hmr9", Severity: "moderate",
					Summary: "ReDoS in lodash",
					URL:     "https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9",
				}},
				Via:        []string{"express", "body-parser"},
				OldLicense: "MIT", NewLicense: "non-standard", LicenseChanged: true,
			},
			{
				Name: "request", Ecosystem: "npm", Kind: diffx.Added,
				New: []string{"2.88.2"}, Deprecated: true,
				DeprecatedReason: "request has been deprecated",
			},
			{
				Name: "event-stream", Ecosystem: "npm", Kind: diffx.Upgraded,
				Old: []string{"3.3.4"}, New: []string{"3.3.6"},
				Unlisted: true, UnlistedVersions: []string{"3.3.6"},
			},
		},
	}}
}

func TestSARIF(t *testing.T) {
	var buf bytes.Buffer
	err := SARIF(&buf, sarifDiffs(), "v0.1.12",
		func(p string) []byte { return []byte(sarifLockfile) })
	if err != nil {
		t.Fatal(err)
	}

	var log struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name    string `json:"name"`
					Version string `json:"version"`
					Rules   []struct {
						ID         string         `json:"id"`
						HelpURI    string         `json:"helpUri"`
						Properties map[string]any `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("want one 2.1.0 run, got version %q, %d runs", log.Version, len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "lockvet" || run.Tool.Driver.Version != "0.1.12" {
		t.Errorf("driver = %s %s, want lockvet 0.1.12 (no v prefix)",
			run.Tool.Driver.Name, run.Tool.Driver.Version)
	}
	if len(run.Results) != 5 {
		t.Fatalf("want 5 results (introduced, unresolved, deprecated, license, unlisted), got %d", len(run.Results))
	}

	byRule := map[string]int{}
	for i, r := range run.Results {
		byRule[r.RuleID] = i
	}

	intro := run.Results[byRule["GHSA-35jh-r3h4-6jhm"]]
	if intro.Level != "error" {
		t.Errorf("high-severity introduced vuln level = %q, want error", intro.Level)
	}
	if got := intro.Locations[0].PhysicalLocation.Region.StartLine; got != 3 {
		t.Errorf("introduced vuln startLine = %d, want 3 (the node_modules/lodash line)", got)
	}
	if uri := intro.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "package-lock.json" {
		t.Errorf("uri = %q", uri)
	}
	for _, want := range []string{"lodash was upgraded to 4.17.19", "GHSA-35jh-r3h4-6jhm", "(high)", "via express › body-parser"} {
		if !strings.Contains(intro.Message.Text, want) {
			t.Errorf("introduced message %q missing %q", intro.Message.Text, want)
		}
	}

	unres := run.Results[byRule["GHSA-29mw-wpgm-hmr9"]]
	if unres.Level != "note" {
		t.Errorf("unresolved vuln level = %q, want note", unres.Level)
	}
	if !strings.Contains(unres.Message.Text, "does not fix it") {
		t.Errorf("unresolved message %q should say the change does not fix it", unres.Message.Text)
	}

	dep := run.Results[byRule["deprecated-package"]]
	if dep.Level != "warning" {
		t.Errorf("deprecated level = %q, want warning", dep.Level)
	}
	for _, want := range []string{"request was added at 2.88.2", "request has been deprecated"} {
		if !strings.Contains(dep.Message.Text, want) {
			t.Errorf("deprecated message %q missing %q", dep.Message.Text, want)
		}
	}
	if got := dep.Locations[0].PhysicalLocation.Region.StartLine; got != 6 {
		t.Errorf("deprecated startLine = %d, want 6 (the node_modules/request line)", got)
	}

	unl := run.Results[byRule["unlisted-version"]]
	if unl.Level != "warning" {
		t.Errorf("unlisted level = %q, want warning", unl.Level)
	}
	for _, want := range []string{"event-stream was upgraded to 3.3.6", "version 3.3.6 is unknown to deps.dev", "other versions of the package are listed"} {
		if !strings.Contains(unl.Message.Text, want) {
			t.Errorf("unlisted message %q missing %q", unl.Message.Text, want)
		}
	}

	lic := run.Results[byRule["license-change"]]
	if lic.Level != "warning" {
		t.Errorf("license-change level = %q, want warning", lic.Level)
	}
	for _, want := range []string{"lodash was upgraded to 4.17.19", "from MIT to non-standard"} {
		if !strings.Contains(lic.Message.Text, want) {
			t.Errorf("license message %q missing %q", lic.Message.Text, want)
		}
	}
	if got := lic.Locations[0].PhysicalLocation.Region.StartLine; got != 3 {
		t.Errorf("license startLine = %d, want 3 (the node_modules/lodash line)", got)
	}

	// Rules: dedup + security-severity mapping.
	sawSec := false
	for _, r := range run.Tool.Driver.Rules {
		if r.ID == "GHSA-35jh-r3h4-6jhm" {
			if r.Properties["security-severity"] != "8.0" {
				t.Errorf("high → security-severity %v, want 8.0", r.Properties["security-severity"])
			}
			if r.HelpURI == "" {
				t.Error("vuln rule missing helpUri")
			}
			sawSec = true
		}
	}
	if !sawSec {
		t.Error("no rule for the introduced vuln")
	}
	if len(run.Tool.Driver.Rules) != 5 {
		t.Errorf("want 5 rules, got %d", len(run.Tool.Driver.Rules))
	}

	// RuleIndex must point at the right rule.
	for _, res := range run.Results {
		if run.Tool.Driver.Rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("ruleIndex %d points at %q, want %q",
				res.RuleIndex, run.Tool.Driver.Rules[res.RuleIndex].ID, res.RuleID)
		}
	}
}

func TestSARIFEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := SARIF(&buf, nil, "dev", nil); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []any `json:"results"`
			Tool    struct {
				Driver struct {
					Rules []any `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	// GitHub rejects runs where results/rules are null instead of [].
	if log.Runs[0].Results == nil || log.Runs[0].Tool.Driver.Rules == nil {
		t.Error("results and rules must be [] (not null) when empty")
	}
}

func TestLineOf(t *testing.T) {
	data := []byte("a\nfoo:\n  version: 1.2.3\nbar 9.9.9\nfoo 1.0.0\n")
	if got := lineOf(data, "foo", []string{"1.2.3"}); got != 2 {
		t.Errorf("windowed match = %d, want 2", got)
	}
	if got := lineOf(data, "foo", []string{"1.0.0"}); got != 5 {
		t.Errorf("same-line later match = %d, want 5", got)
	}
	if got := lineOf(data, "foo", []string{"7.7.7"}); got != 2 {
		t.Errorf("name-only fallback = %d, want 2", got)
	}
	if got := lineOf(data, "nope", nil); got != 1 {
		t.Errorf("absent name = %d, want 1", got)
	}
}
