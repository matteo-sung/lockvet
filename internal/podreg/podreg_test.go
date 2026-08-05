package podreg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// fakeRegistry serves both the CDN (shard index + podspecs) and the
// trunk API from one httptest server. shards maps "d_a_2" → index body;
// specs maps "Name/Version" → podspec JSON; trunk maps pod name → trunk
// document.
func fakeRegistry(t *testing.T, shards, specs, trunk map[string]string) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if rest, ok := strings.CutPrefix(p, "/all_pods_versions_"); ok {
			key := strings.TrimSuffix(rest, ".txt")
			if body, ok := shards[key]; ok {
				fmt.Fprint(w, body)
				return
			}
		}
		if rest, ok := strings.CutPrefix(p, "/Specs/"); ok {
			parts := strings.Split(rest, "/") // a b c Name Version Name.podspec.json
			if len(parts) == 6 {
				if body, ok := specs[parts[3]+"/"+parts[4]]; ok {
					fmt.Fprint(w, body)
					return
				}
			}
		}
		if name, ok := strings.CutPrefix(p, "/api/v1/pods/"); ok {
			if body, ok := trunk[name]; ok {
				fmt.Fprint(w, body)
				return
			}
		}
		http.NotFound(w, r)
	}))
	oldCDN, oldTrunk, oldUse := CDNURL, TrunkURL, UseTrunk
	CDNURL, TrunkURL, UseTrunk = srv.URL, srv.URL, true
	return func() { CDNURL, TrunkURL, UseTrunk = oldCDN, oldTrunk, oldUse; srv.Close() }
}

func bump(name, from, to string) []diffx.FileDiff {
	return []diffx.FileDiff{{Path: "Podfile.lock", Changes: []diffx.Change{{
		Name: name, Ecosystem: "CocoaPods", Kind: diffx.Changed,
		Old: []string{from}, New: []string{to},
	}}}}
}

func trunkTS(age time.Duration) string {
	return time.Now().UTC().Add(-age).Format("2006-01-02 15:04:05") + " UTC"
}

// Alamofire shards to d/a/2 (md5).
const alamoShard = "d_a_2"

func TestAgesFreshLicenseAndSource(t *testing.T) {
	defer fakeRegistry(t,
		map[string]string{alamoShard: "Alamofire/5.9.0/5.9.1\nOther/1.0.0\n"},
		map[string]string{
			"Alamofire/5.9.1": `{"license":"Apache-2.0","source":{"git":"https://github.com/Alamofire/Alamofire.git","tag":"5.9.1"}}`,
			"Alamofire/5.9.0": `{"license":{"type":"MIT","file":"LICENSE"},"source":{"git":"https://github.com/Alamofire/Alamofire.git"}}`,
		},
		map[string]string{"Alamofire": fmt.Sprintf(
			`{"versions":[{"name":"5.9.0","created_at":%q},{"name":"5.9.1","created_at":%q}]}`,
			trunkTS(400*24*time.Hour), trunkTS(3*24*time.Hour))},
	)()
	diffs := bump("Alamofire", "5.9.0", "5.9.1")
	checked, err := Annotate(diffs, 7)
	if err != nil || !checked {
		t.Fatalf("Annotate: checked=%v err=%v", checked, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 3 || !c.Fresh {
		t.Errorf("age/fresh = %d/%v, want 3/true", c.AgeDays, c.Fresh)
	}
	if !c.LicenseChanged || c.OldLicense != "MIT" || c.NewLicense != "Apache-2.0" {
		t.Errorf("license = %q→%q changed=%v", c.OldLicense, c.NewLicense, c.LicenseChanged)
	}
	if c.SourceRepo != "https://github.com/Alamofire/Alamofire" {
		t.Errorf("SourceRepo = %q", c.SourceRepo)
	}
	if c.Unlisted || c.Deprecated {
		t.Errorf("healthy bump flagged: unlisted=%v deprecated=%v", c.Unlisted, c.Deprecated)
	}
}

func TestDeprecatedInFavorOf(t *testing.T) {
	defer fakeRegistry(t,
		map[string]string{alamoShard: "Alamofire/1.0.0/2.0.0\n"},
		map[string]string{
			"Alamofire/2.0.0": `{"deprecated_in_favor_of":"BetterPod","license":"MIT"}`,
			"Alamofire/1.0.0": `{"license":"MIT"}`,
		},
		map[string]string{},
	)()
	diffs := bump("Alamofire", "1.0.0", "2.0.0")
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated || !strings.Contains(c.DeprecatedReason, "BetterPod") {
		t.Errorf("deprecated=%v reason=%q", c.Deprecated, c.DeprecatedReason)
	}
	if c.LicenseChanged {
		t.Error("same license flagged as change")
	}
}

func TestUnlistedVersionAndUnknownPod(t *testing.T) {
	defer fakeRegistry(t,
		map[string]string{alamoShard: "Alamofire/5.9.0/5.9.1\n"},
		map[string]string{},
		map[string]string{},
	)()
	diffs := bump("Alamofire", "5.9.0", "9.9.9")
	if _, err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "9.9.9" {
		t.Errorf("unlisted=%v versions=%v", c.Unlisted, c.UnlistedVersions)
	}

	// A pod the index has never heard of is not flagged at all.
	diffs = bump("TotallyUnknownPod", "1.0.0", "2.0.0")
	checked, err := Annotate(diffs, 7)
	if err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; c.Unlisted {
		t.Errorf("unknown pod flagged unlisted (checked=%v)", checked)
	}
}

func TestNonRegistryAndOtherEcosystemsSkipped(t *testing.T) {
	// No server registered at all: any network use would fail loudly.
	oldCDN := CDNURL
	CDNURL = "http://127.0.0.1:1"
	defer func() { CDNURL = oldCDN }()
	diffs := []diffx.FileDiff{{Path: "Podfile.lock", Changes: []diffx.Change{
		{Name: "LocalPod", Ecosystem: "CocoaPods", Kind: diffx.Changed,
			Old: []string{"1.0.0"}, New: []string{"2.0.0"}, NonRegistry: true},
		{Name: "left-pad", Ecosystem: "npm", Kind: diffx.Changed,
			Old: []string{"1.0.0"}, New: []string{"1.3.0"}},
	}}}
	checked, err := Annotate(diffs, 7)
	if err != nil || checked {
		t.Fatalf("checked=%v err=%v, want false/nil (nothing eligible)", checked, err)
	}
}

func TestWasmPathNoTrunk(t *testing.T) {
	defer fakeRegistry(t,
		map[string]string{alamoShard: "Alamofire/5.9.0/5.9.1\n"},
		map[string]string{
			"Alamofire/5.9.1": `{"license":"MIT","source":{"git":"https://github.com/Alamofire/Alamofire.git"}}`,
			"Alamofire/5.9.0": `{"license":"MIT"}`,
		},
		map[string]string{},
	)()
	UseTrunk = false
	diffs := bump("Alamofire", "5.9.0", "5.9.1")
	checked, err := Annotate(diffs, 7)
	if err != nil || !checked {
		t.Fatalf("checked=%v err=%v", checked, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 0 || c.PublishedAt != "" {
		t.Errorf("browser path should carry no ages, got %d/%q", c.AgeDays, c.PublishedAt)
	}
	if c.SourceRepo != "https://github.com/Alamofire/Alamofire" {
		t.Errorf("SourceRepo = %q", c.SourceRepo)
	}
}

func TestShardHelper(t *testing.T) {
	if s := shard("Alamofire"); s != [3]string{"d", "a", "2"} {
		t.Errorf("shard(Alamofire) = %v", s)
	}
}
