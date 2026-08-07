package osv

import (
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

func rangeDetail(name string, events ...map[string]string) vulnDetail {
	var d vulnDetail
	var e affectedEntry
	e.Package.Name = name
	e.Package.Ecosystem = "GitHub Actions"
	e.Ranges = append(e.Ranges, struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	}{Type: "ECOSYSTEM", Events: events})
	d.affected = append(d.affected, e)
	return d
}

func TestInEvents(t *testing.T) {
	events := []map[string]string{{"introduced": "0"}, {"fixed": "41"}, {"introduced": "42"}, {"fixed": "43"}}
	cases := map[string]bool{
		"40.9.9": true,
		"41":     false,
		"41.5":   false,
		"42.0.1": true,
		"43":     false,
		"50":     false,
	}
	for v, want := range cases {
		if got := inEvents(events, v); got != want {
			t.Errorf("inEvents(%s) = %v, want %v", v, got, want)
		}
	}
	la := []map[string]string{{"introduced": "1"}, {"last_affected": "2.5"}}
	if !inEvents(la, "2.5") || inEvents(la, "2.6") || inEvents(la, "0.9") {
		t.Errorf("last_affected evaluation wrong")
	}
}

func TestActionAffected(t *testing.T) {
	// The tj-actions shape: everything before 46.0.1 is affected.
	det := rangeDetail("tj-actions/changed-files", map[string]string{"introduced": "0"}, map[string]string{"fixed": "46.0.1"})

	c := &diffx.Change{Name: "tj-actions/changed-files", Ecosystem: "GitHub Actions"}
	if !actionAffected(det, c.Name, c, "45.0.7") {
		t.Errorf("concrete pin 45.0.7 should be affected")
	}
	if !actionAffected(det, c.Name, c, "v45") {
		t.Errorf("floating v45 (whole major below the fix) should be affected")
	}
	if actionAffected(det, c.Name, c, "46.0.1") {
		t.Errorf("fixed version flagged")
	}
	if actionAffected(det, c.Name, c, "main") || actionAffected(det, c.Name, c, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef") {
		t.Errorf("branch/SHA refs cannot be evaluated and must stay quiet")
	}

	// A SHA resolved to a release evaluates as that release.
	c.ResolvedRefs = map[string]string{"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef": "v45.0.7"}
	if !actionAffected(det, c.Name, c, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef") {
		t.Errorf("resolved SHA should evaluate as v45.0.7")
	}

	// Fix within the major: an unresolved floating tag must NOT flag.
	det2 := rangeDetail("actions/checkout", map[string]string{"introduced": "0"}, map[string]string{"fixed": "4.4.1"})
	c2 := &diffx.Change{Name: "actions/checkout", Ecosystem: "GitHub Actions"}
	if actionAffected(det2, c2.Name, c2, "v4") {
		t.Errorf("floating v4 with fix inside the major is unknowable — must not flag")
	}
	// But resolved past the fix it stays quiet, resolved before it flags.
	c2.ResolvedRefs = map[string]string{"v4": "v4.4.2"}
	if actionAffected(det2, c2.Name, c2, "v4") {
		t.Errorf("v4 resolved to 4.4.2 (fixed) flagged")
	}
	c2.ResolvedRefs["v4"] = "v4.2.1"
	if !actionAffected(det2, c2.Name, c2, "v4") {
		t.Errorf("v4 resolved to 4.2.1 (affected) missed")
	}

	// Explicit versions list.
	var d3 vulnDetail
	var e affectedEntry
	e.Package.Name = "some/action"
	e.Package.Ecosystem = "GitHub Actions"
	e.Versions = []string{"1.2.3"}
	d3.affected = append(d3.affected, e)
	c3 := &diffx.Change{Name: "some/action", Ecosystem: "GitHub Actions"}
	if !actionAffected(d3, c3.Name, c3, "v1.2.3") || actionAffected(d3, c3.Name, c3, "v1.2.4") {
		t.Errorf("explicit version list evaluation wrong")
	}
}

func TestCapOpenRange(t *testing.T) {
	// The GHSA-vqf5-2xx6-9wfm shape: a fixed 3.x range plus an open 2.x
	// range whose "< 3.0.0" bound the OSV export dropped.
	var d vulnDetail
	var e1 affectedEntry
	e1.Package.Name = "github/codeql-action"
	e1.Package.Ecosystem = "GitHub Actions"
	e1.Ranges = append(e1.Ranges, struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	}{Type: "ECOSYSTEM", Events: []map[string]string{{"introduced": "3.26.11"}, {"fixed": "3.28.3"}}})
	var e2 affectedEntry
	e2.Package.Name = "github/codeql-action"
	e2.Package.Ecosystem = "GitHub Actions"
	e2.Ranges = append(e2.Ranges, struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	}{Type: "ECOSYSTEM", Events: []map[string]string{{"introduced": "2.26.11"}}})
	d.affected = []affectedEntry{e1, e2}

	c := &diffx.Change{Name: "github/codeql-action", Ecosystem: "GitHub Actions"}
	if actionAffected(d, c.Name, c, "4.37.6") {
		t.Errorf("4.x must not be flagged by the capped 2.x range")
	}
	if !actionAffected(d, c.Name, c, "2.27.0") {
		t.Errorf("2.27.0 inside the open 2.x range should flag")
	}
	if !actionAffected(d, c.Name, c, "3.27.0") {
		t.Errorf("3.27.0 inside the fixed range should flag")
	}
	if actionAffected(d, c.Name, c, "3.28.3") {
		t.Errorf("patched 3.28.3 flagged")
	}

	// A truly unpatched advisory (no fix anywhere) stays open-ended.
	var d2 vulnDetail
	d2.affected = []affectedEntry{e2}
	if !actionAffected(d2, c.Name, c, "4.37.6") {
		t.Errorf("advisory without any fix must stay open-ended")
	}
}
