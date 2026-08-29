package osv

import (
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// stubBackend answers batch queries from a fixed (name@version → IDs)
// table, so Annotate's partitioning is testable without a network or a
// local zip database.
type stubBackend struct {
	vulns map[string][]string // "name@version" → advisory IDs
}

func (s stubBackend) batch(qs []query) ([]batchResult, error) {
	out := make([]batchResult, len(qs))
	for i, q := range qs {
		for _, id := range s.vulns[q.Package.Name+"@"+q.Version] {
			out[i].Vulns = append(out[i].Vulns, struct {
				ID string `json:"id"`
			}{ID: id})
		}
	}
	return out, nil
}

func (s stubBackend) details(ids []string) map[string]vulnDetail {
	out := map[string]vulnDetail{}
	for _, id := range ids {
		out[id] = vulnDetail{summary: "stub advisory", severity: "critical"}
	}
	return out
}

// A removed package's advisories land in RemovedVulns (informational),
// never in FixedVulns: dropping a dependency is not a fix. An upgrade
// away from the affected version still counts as fixed.
func TestAnnotateRemovedPackageVulns(t *testing.T) {
	orig := db
	db = stubBackend{vulns: map[string][]string{
		"pyyaml@5.3.1":   {"GHSA-8q59-q68h-6hv4"},
		"lodash@4.17.11": {"GHSA-jf85-cpcp-j695"},
	}}
	t.Cleanup(func() { db = orig })

	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		{Name: "pyyaml", Ecosystem: "PyPI", Kind: diffx.Removed, Old: []string{"5.3.1"}},
		{Name: "lodash", Ecosystem: "npm", Kind: diffx.Upgraded, Old: []string{"4.17.11"}, New: []string{"4.17.21"}},
	}}}
	if err := Annotate(diffs); err != nil {
		t.Fatal(err)
	}

	rm := diffs[0].Changes[0]
	if len(rm.FixedVulns) != 0 {
		t.Errorf("removal claimed fixes: %+v", rm.FixedVulns)
	}
	if len(rm.RemovedVulns) != 1 || rm.RemovedVulns[0].ID != "GHSA-8q59-q68h-6hv4" {
		t.Errorf("removal note missing: %+v", rm.RemovedVulns)
	}
	if rm.RemovedVulns[0].Severity != "critical" {
		t.Errorf("severity not carried: %+v", rm.RemovedVulns[0])
	}

	up := diffs[0].Changes[1]
	if len(up.FixedVulns) != 1 || up.FixedVulns[0].ID != "GHSA-jf85-cpcp-j695" {
		t.Errorf("upgrade fix lost: %+v", up.FixedVulns)
	}
	if len(up.RemovedVulns) != 0 {
		t.Errorf("upgrade gained removal note: %+v", up.RemovedVulns)
	}
}
