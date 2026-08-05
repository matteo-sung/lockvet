package tfreg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// fakeRegistries serves Terraform v2 provider documents under
// /v2/providers/ and OpenTofu index documents under
// /registry/docs/providers/. Missing names 404.
func fakeRegistries(t *testing.T, tf, otf map[string]string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if name, ok := strings.CutPrefix(r.URL.Path, "/v2/providers/"); ok {
			if doc, ok := tf[name]; ok {
				fmt.Fprint(w, doc)
				return
			}
		}
		if rest, ok := strings.CutPrefix(r.URL.Path, "/v1/providers/"); ok {
			if doc, ok := tf["v1:"+rest]; ok {
				fmt.Fprint(w, doc)
				return
			}
		}
		if rest, ok := strings.CutPrefix(r.URL.Path, "/registry/docs/providers/"); ok {
			name := strings.TrimSuffix(rest, "/index.json")
			if doc, ok := otf[name]; ok {
				fmt.Fprint(w, doc)
				return
			}
		}
		http.NotFound(w, r)
	}))
	oldTF, oldOTF := TerraformBaseURL, OpenTofuBaseURL
	TerraformBaseURL, OpenTofuBaseURL = srv.URL, srv.URL
	return func() { TerraformBaseURL, OpenTofuBaseURL = oldTF, oldOTF; srv.Close() }
}

func bump(name, from, to string) diffx.FileDiff {
	return diffx.FileDiff{Path: ".terraform.lock.hcl", Changes: []diffx.Change{{
		Name: name, Ecosystem: "Terraform", Kind: diffx.Changed,
		Old: []string{from}, New: []string{to},
	}}}
}

func ts(age time.Duration) string {
	return time.Now().UTC().Add(-age).Format(time.RFC3339)
}

func tfDoc(attrs string, versions ...[2]string) string {
	var inc []string
	for _, v := range versions {
		inc = append(inc, fmt.Sprintf(
			`{"type":"provider-versions","attributes":{"version":%q,"published-at":%q}}`,
			v[0], v[1]))
	}
	return fmt.Sprintf(`{"data":{"type":"providers","attributes":{%s}},"included":[%s]}`,
		attrs, strings.Join(inc, ","))
}

func TestTerraformAgesFreshSourceAndClean(t *testing.T) {
	defer fakeRegistries(t, map[string]string{
		"hashicorp/aws": tfDoc(`"source":"https://github.com/hashicorp/terraform-provider-aws"`,
			[2]string{"6.0.0", ts(400 * 24 * time.Hour)},
			[2]string{"6.1.0", ts(3 * 24 * time.Hour)}),
	}, nil)()
	diffs := []diffx.FileDiff{bump("hashicorp/aws", "6.0.0", "6.1.0")}
	checked, err := Annotate(diffs, 7)
	if err != nil || !checked {
		t.Fatalf("Annotate: checked=%v err=%v", checked, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 3 || !c.Fresh {
		t.Errorf("age/fresh = %d/%v, want 3/true", c.AgeDays, c.Fresh)
	}
	if c.SourceRepo != "https://github.com/hashicorp/terraform-provider-aws" {
		t.Errorf("SourceRepo = %q", c.SourceRepo)
	}
	if c.Unlisted || c.Deprecated {
		t.Errorf("healthy bump flagged: unlisted=%v deprecated=%v", c.Unlisted, c.Deprecated)
	}
}

func TestArchivedDescriptionAndWarning(t *testing.T) {
	defer fakeRegistries(t, map[string]string{
		"hashicorp/template": tfDoc(
			`"description":"This provider has been archived. Please use the templatefile function instead. See documentation for more details.","source":"https://github.com/hashicorp/terraform-provider-template"`,
			[2]string{"2.2.0", "2020-10-08T16:16:33Z"},
			[2]string{"2.1.2", "2019-05-02T00:00:00Z"}),
		"acme/old": tfDoc(`"warning":"Deprecated  in favor of acme/new."`,
			[2]string{"1.0.0", "2020-01-01T00:00:00Z"},
			[2]string{"1.1.0", "2021-01-01T00:00:00Z"}),
		"acme/hidden": tfDoc(`"unlisted":true`,
			[2]string{"0.9.0", "2020-01-01T00:00:00Z"},
			[2]string{"1.0.0", "2021-01-01T00:00:00Z"}),
	}, nil)()
	diffs := []diffx.FileDiff{
		bump("hashicorp/template", "2.1.2", "2.2.0"),
		bump("acme/old", "1.0.0", "1.1.0"),
		bump("acme/hidden", "0.9.0", "1.0.0"),
	}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	want := "This provider has been archived. Please use the templatefile function instead"
	if !c.Deprecated || c.DeprecatedReason != want {
		t.Errorf("archived: Deprecated=%v reason=%q", c.Deprecated, c.DeprecatedReason)
	}
	c = diffs[1].Changes[0]
	if !c.Deprecated || c.DeprecatedReason != "Deprecated in favor of acme/new." {
		t.Errorf("warning: Deprecated=%v reason=%q", c.Deprecated, c.DeprecatedReason)
	}
	c = diffs[2].Changes[0]
	if !c.Deprecated || c.DeprecatedReason != "provider delisted from registry.terraform.io" {
		t.Errorf("delisted: Deprecated=%v reason=%q", c.Deprecated, c.DeprecatedReason)
	}
}

func TestRemovalNeverDeprecated(t *testing.T) {
	defer fakeRegistries(t, map[string]string{
		"acme/old": tfDoc(`"warning":"deprecated"`, [2]string{"1.0.0", "2020-01-01T00:00:00Z"}),
	}, nil)()
	diffs := []diffx.FileDiff{{Path: ".terraform.lock.hcl", Changes: []diffx.Change{{
		Name: "acme/old", Ecosystem: "Terraform", Kind: diffx.Removed, Old: []string{"1.0.0"},
	}}}}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Deprecated {
		t.Errorf("removal flagged deprecated")
	}
}

func TestUnlistedOnlyWhenProviderKnown(t *testing.T) {
	defer fakeRegistries(t, map[string]string{
		"hashicorp/null": tfDoc(``, [2]string{"3.2.0", "2022-10-25T14:50:52Z"}),
	}, nil)()
	diffs := []diffx.FileDiff{
		bump("hashicorp/null", "3.2.0", "9.9.9"),
		bump("acme/nowhere", "1.0.0", "1.0.1"),
	}
	checked, err := Annotate(diffs, 7)
	if err != nil || !checked {
		t.Fatalf("checked=%v err=%v", checked, err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "9.9.9" {
		t.Errorf("unlisted = %v %v", c.Unlisted, c.UnlistedVersions)
	}
	if diffs[1].Changes[0].Unlisted {
		t.Errorf("provider unknown to the registry must never be flagged")
	}
}

func TestCappedListFallsBackToPerVersionCheck(t *testing.T) {
	// registry.terraform.io caps its version lists at 500 entries; a
	// listed version outside the cap must not be flagged (and gets its
	// age from the per-version endpoint), while a version the registry
	// 404s for stays flagged. AWS provider 5.71.0 is the real-world
	// case: tagged upstream, pulled from the registry.
	defer fakeRegistries(t, map[string]string{
		"hashicorp/aws": tfDoc(``, [2]string{"6.22.1", "2026-01-01T00:00:00Z"}),
		"v1:hashicorp/aws/5.70.0": fmt.Sprintf(`{"version":"5.70.0","published_at":%q}`,
			ts(3*24*time.Hour)),
		// 5.71.0 has no v1 doc → the fake registry answers 404.
	}, nil)()
	diffs := []diffx.FileDiff{
		bump("hashicorp/aws", "5.69.0", "5.70.0"),
		bump("hashicorp/aws", "5.69.0", "5.71.0"),
	}
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if c.Unlisted {
		t.Errorf("listed-but-outside-cap version flagged unlisted")
	}
	if c.AgeDays != 3 || !c.Fresh {
		t.Errorf("per-version age not applied: age/fresh = %d/%v", c.AgeDays, c.Fresh)
	}
	c = diffs[1].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "5.71.0" {
		t.Errorf("registry-404 version not flagged: %v %v", c.Unlisted, c.UnlistedVersions)
	}
}

func TestOpenTofuHostFullTreatment(t *testing.T) {
	defer fakeRegistries(t, nil, map[string]string{
		"hashicorp/null": fmt.Sprintf(
			`{"addr":{"display":"hashicorp/terraform-provider-null"},"versions":[{"id":"v3.3.0","published":%q},{"id":"v3.2.0","published":%q}],"is_blocked":false}`,
			ts(2*24*time.Hour), ts(500*24*time.Hour)),
		"acme/badware": `{"addr":{"display":"acme/terraform-provider-badware"},"versions":[{"id":"v1.0.0","published":"2024-01-01T00:00:00Z"},{"id":"v1.1.0","published":"2024-02-01T00:00:00Z"}],"is_blocked":true,"blocked_reason":"malware"}`,
	})()
	diffs := []diffx.FileDiff{
		bump("registry.opentofu.org/hashicorp/null", "3.2.0", "3.3.0"),
		bump("registry.opentofu.org/acme/badware", "1.0.0", "1.1.0"),
	}
	checked, err := Annotate(diffs, 7)
	if err != nil || !checked {
		t.Fatalf("checked=%v err=%v", checked, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 2 || !c.Fresh {
		t.Errorf("opentofu age/fresh = %d/%v", c.AgeDays, c.Fresh)
	}
	if c.SourceRepo != "https://github.com/hashicorp/terraform-provider-null" {
		t.Errorf("opentofu SourceRepo = %q", c.SourceRepo)
	}
	c = diffs[1].Changes[0]
	if !c.Deprecated || c.DeprecatedReason != "provider blocked in the OpenTofu registry: malware" {
		t.Errorf("blocked: Deprecated=%v reason=%q", c.Deprecated, c.DeprecatedReason)
	}
}

func TestWasmFallbackAgesOnly(t *testing.T) {
	defer fakeRegistries(t, nil, map[string]string{
		"hashicorp/aws": fmt.Sprintf(
			`{"addr":{"display":"hashicorp/terraform-provider-aws"},"versions":[{"id":"v6.1.0","published":%q}],"is_blocked":true,"blocked_reason":"x"}`,
			ts(3*24*time.Hour)),
	})()
	UseTerraformRegistry = false
	defer func() { UseTerraformRegistry = true }()
	diffs := []diffx.FileDiff{bump("hashicorp/aws", "6.0.0", "6.1.0")}
	checked, err := Annotate(diffs, 7)
	if err != nil || !checked {
		t.Fatalf("checked=%v err=%v", checked, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 3 || !c.Fresh {
		t.Errorf("fallback age/fresh = %d/%v", c.AgeDays, c.Fresh)
	}
	if c.SourceRepo != "https://github.com/hashicorp/terraform-provider-aws" {
		t.Errorf("fallback SourceRepo = %q", c.SourceRepo)
	}
	// The mirror can lag: 6.0.0 is absent from the fake list, and the
	// provider is "blocked" — the fallback must claim neither.
	if c.Unlisted || c.Deprecated {
		t.Errorf("mirror fallback made claims: unlisted=%v deprecated=%v", c.Unlisted, c.Deprecated)
	}
}

func TestCustomHostsAndOtherEcosystemsSkipped(t *testing.T) {
	defer fakeRegistries(t, map[string]string{}, map[string]string{})()
	diffs := []diffx.FileDiff{
		bump("tf.example.com/acme/x", "1.0.0", "1.0.1"),
		{Path: "package-lock.json", Changes: []diffx.Change{{
			Name: "left-pad", Ecosystem: "npm", Kind: diffx.Changed,
			Old: []string{"1.0.0"}, New: []string{"1.3.0"},
		}}},
	}
	checked, err := Annotate(diffs, 7)
	if err != nil {
		t.Fatal(err)
	}
	if checked {
		t.Errorf("nothing eligible, yet checked=true")
	}
}

func TestRoute(t *testing.T) {
	cases := []struct {
		name     string
		ok       bool
		opentofu bool
	}{
		{"hashicorp/aws", true, false},
		{"registry.opentofu.org/hashicorp/null", true, true},
		{"tf.example.com/acme/x", false, false},
		{"registry.opentofu.org/x", false, false},
		{"justone", false, false},
	}
	for _, c := range cases {
		got, ok := route(c.name)
		if ok != c.ok || (ok && got.opentofu != c.opentofu) {
			t.Errorf("route(%q) = %+v, %v", c.name, got, ok)
		}
	}
}
