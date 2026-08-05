package gemreg

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

// fakeRubyGems serves compact-index /info documents and attestation
// answers. attestations maps full_name (gem-version) → true (bundle) /
// false (empty array); missing keys 404.
func fakeRubyGems(t *testing.T, infos map[string]string, attestations map[string]bool, hits *int64) func() {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if name, ok := strings.CutPrefix(r.URL.Path, "/info/"); ok {
			if doc, ok := infos[name]; ok {
				fmt.Fprint(w, doc)
				return
			}
			http.NotFound(w, r)
			return
		}
		if full, ok := strings.CutPrefix(r.URL.Path, "/attestations/"); ok {
			full = strings.TrimSuffix(full, ".json")
			if hits != nil {
				atomic.AddInt64(hits, 1)
			}
			if att, ok := attestations[full]; ok {
				if att {
					fmt.Fprint(w, `[{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}]`)
				} else {
					fmt.Fprint(w, `[]`)
				}
				return
			}
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	oldIdx, oldAPI := IndexURL, APIURL
	IndexURL, APIURL = srv.URL, srv.URL
	return func() { IndexURL, APIURL = oldIdx, oldAPI; srv.Close() }
}

func line(version string, age time.Duration) string {
	return fmt.Sprintf("%s |checksum:abc,created_at:%s\n",
		version, time.Now().UTC().Add(-age).Format(time.RFC3339))
}

func bump(name, from, to string) diffx.FileDiff {
	return diffx.FileDiff{Path: "Gemfile.lock", Changes: []diffx.Change{{
		Name: name, Ecosystem: "RubyGems", Kind: diffx.Changed,
		Old: []string{from}, New: []string{to},
	}}}
}

const day = 24 * time.Hour

func TestProvenanceDropFlagged(t *testing.T) {
	defer fakeRubyGems(t, map[string]string{
		"pkg": "---\n" + line("1.0.0", 400*day) + line("1.1.0", 300*day) +
			line("1.2.0", 200*day) + line("2.0.0", 2*day),
	}, map[string]bool{
		"pkg-1.0.0": true, "pkg-1.1.0": true, "pkg-1.2.0": true, "pkg-2.0.0": false,
	}, nil)()
	diffs := []diffx.FileDiff{bump("pkg", "1.2.0", "2.0.0")}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.ProvenanceDropped || len(c.UnattestedVersions) != 1 || c.UnattestedVersions[0] != "2.0.0" {
		t.Fatalf("want provenance drop on 2.0.0, got %+v", c)
	}
	if !c.Fresh || c.AgeDays != 2 {
		t.Fatalf("want age backfill (fresh, 2d), got fresh=%v age=%d", c.Fresh, c.AgeDays)
	}
}

func TestNoFlagWhenOutgoingUnattested(t *testing.T) {
	var hits int64
	defer fakeRubyGems(t, map[string]string{
		"pkg": "---\n" + line("1.0.0", 400*day) + line("1.1.0", 300*day) +
			line("1.2.0", 200*day) + line("2.0.0", 2*day),
	}, map[string]bool{
		"pkg-1.0.0": true, "pkg-1.1.0": true, "pkg-1.2.0": false, "pkg-2.0.0": false,
	}, &hits)()
	diffs := []diffx.FileDiff{bump("pkg", "1.2.0", "2.0.0")}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].ProvenanceDropped {
		t.Fatal("outgoing unattested must not flag")
	}
	if hits != 1 {
		t.Fatalf("want exactly 1 attestation lookup (early exit), got %d", hits)
	}
}

func TestNoFlagWhenIncomingOld(t *testing.T) {
	var hits int64
	defer fakeRubyGems(t, map[string]string{
		"pkg": "---\n" + line("1.0.0", 400*day) + line("1.1.0", 300*day) +
			line("1.2.0", 200*day) + line("2.0.0", 100*day),
	}, map[string]bool{
		"pkg-1.0.0": true, "pkg-1.1.0": true, "pkg-1.2.0": true, "pkg-2.0.0": false,
	}, &hits)()
	diffs := []diffx.FileDiff{bump("pkg", "1.2.0", "2.0.0")}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].ProvenanceDropped {
		t.Fatal("100-day-old incoming must not flag (age gate)")
	}
	if hits != 0 {
		t.Fatalf("age gate must spend no lookups, got %d", hits)
	}
}

func TestNoFlagWithoutEstablishedPractice(t *testing.T) {
	// Only one stable release below the incoming version: window < 2.
	defer fakeRubyGems(t, map[string]string{
		"pkg": "---\n" + line("1.2.0", 200*day) + line("2.0.0", 2*day),
	}, map[string]bool{
		"pkg-1.2.0": true, "pkg-2.0.0": false,
	}, nil)()
	diffs := []diffx.FileDiff{bump("pkg", "1.2.0", "2.0.0")}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].ProvenanceDropped {
		t.Fatal("single-release history must not flag")
	}
}

func TestWindowSkipsPrereleasesAndPlatforms(t *testing.T) {
	// Practice window must anchor on 1.1.0/1.2.0, not the rc or the
	// platform build (whose attestation state is unknown → would bail).
	defer fakeRubyGems(t, map[string]string{
		"pkg": "---\n" + line("1.1.0", 300*day) + line("1.2.0", 200*day) +
			line("2.0.0.rc1", 30*day) + line("1.2.0-x86_64-linux", 200*day) +
			line("2.0.0", 2*day),
	}, map[string]bool{
		"pkg-1.1.0": true, "pkg-1.2.0": true, "pkg-2.0.0": false,
	}, nil)()
	diffs := []diffx.FileDiff{bump("pkg", "1.2.0", "2.0.0")}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if !diffs[0].Changes[0].ProvenanceDropped {
		t.Fatal("want flag; prerelease/platform entries must not join the window")
	}
}

func TestPlatformGemFullName(t *testing.T) {
	// Platform pins hit the attestation endpoint with the platform in
	// the full_name, exactly as Gemfile.lock spells the version.
	defer fakeRubyGems(t, map[string]string{
		"native": "---\n" + line("1.0.0", 400*day) + line("1.1.0", 300*day) +
			line("1.1.0-x86_64-linux", 300*day) + line("1.2.0", 2*day) +
			line("1.2.0-x86_64-linux", 2*day),
	}, map[string]bool{
		"native-1.0.0": true, "native-1.1.0": true, "native-1.1.0-x86_64-linux": true,
		"native-1.2.0": true, "native-1.2.0-x86_64-linux": false,
	}, nil)()
	diffs := []diffx.FileDiff{bump("native", "1.1.0-x86_64-linux", "1.2.0-x86_64-linux")}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.ProvenanceDropped || len(c.UnattestedVersions) != 1 || c.UnattestedVersions[0] != "1.2.0-x86_64-linux" {
		t.Fatalf("want platform full_name flagged, got %+v", c)
	}
}

func TestUnlistedVerification(t *testing.T) {
	defer fakeRubyGems(t, map[string]string{
		"pkg": "---\n" + line("1.0.0", 400*day) + line("1.1.0", 10*day),
	}, nil, nil)()
	diffs := []diffx.FileDiff{{Path: "Gemfile.lock", Changes: []diffx.Change{
		{Name: "pkg", Ecosystem: "RubyGems", Kind: diffx.Changed,
			Old: []string{"1.0.0"}, New: []string{"1.1.0"},
			Unlisted: true, UnlistedVersions: []string{"1.1.0"}},
		{Name: "pkg", Ecosystem: "RubyGems", Kind: diffx.Changed,
			Old: []string{"1.0.0"}, New: []string{"6.6.6"},
			Unlisted: true, UnlistedVersions: []string{"6.6.6"}},
		{Name: "gone", Ecosystem: "RubyGems", Kind: diffx.Changed,
			Old: []string{"1.0.0"}, New: []string{"2.0.0"},
			Unlisted: true, UnlistedVersions: []string{"2.0.0"}},
	}}}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	cs := diffs[0].Changes
	if cs[0].Unlisted {
		t.Fatal("1.1.0 is in the index: flag must clear")
	}
	if !cs[1].Unlisted {
		t.Fatal("6.6.6 is not in the index: flag must stay")
	}
	if !cs[2].Unlisted {
		t.Fatal("whole gem missing from the registry: flag must stay")
	}
}

func TestAgeBackfillOnlyWhenNewer(t *testing.T) {
	defer fakeRubyGems(t, map[string]string{
		"pkg": "---\n" + line("1.0.0", 400*day) + line("1.1.0", 3*day),
	}, nil, nil)()
	already := time.Now().UTC().Add(-1 * day).Format(time.RFC3339)
	diffs := []diffx.FileDiff{{Path: "Gemfile.lock", Changes: []diffx.Change{
		{Name: "pkg", Ecosystem: "RubyGems", Kind: diffx.Changed,
			Old: []string{"1.0.0"}, New: []string{"1.1.0"},
			PublishedAt: already, AgeDays: 1, Fresh: true},
	}}}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].PublishedAt != already {
		t.Fatal("deps.dev's newer time must not be overwritten by an older index time")
	}
}

func TestNonRubyAndNonRegistrySkipped(t *testing.T) {
	var infoHits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&infoHits, 1)
		http.NotFound(w, r)
	}))
	defer srv.Close()
	oldIdx := IndexURL
	IndexURL = srv.URL
	defer func() { IndexURL = oldIdx }()
	diffs := []diffx.FileDiff{{Path: "Gemfile.lock", Changes: []diffx.Change{
		{Name: "npmpkg", Ecosystem: "npm", Kind: diffx.Changed, Old: []string{"1"}, New: []string{"2"}},
		{Name: "fork", Ecosystem: "RubyGems", Kind: diffx.Changed, Old: []string{"1"}, New: []string{"2"}, NonRegistry: true},
	}}}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if infoHits != 0 {
		t.Fatalf("nothing to vet: want 0 index fetches, got %d", infoHits)
	}
}

func TestDecodeInfo(t *testing.T) {
	g := decodeInfo(&http.Response{Body: io.NopCloser(strings.NewReader(
		"---\n" +
			"1.0.0 dep:>= 0|checksum:aa,created_at:2024-01-02T03:04:05Z\n" +
			"1.1.0 |checksum:bb,ruby:>= 3.0,created_at:2025-06-07T08:09:10Z\n" +
			"2.0.0.rc1 |checksum:cc\n"))})
	if g == nil || len(g.order) != 3 {
		t.Fatalf("want 3 entries, got %+v", g)
	}
	if g.created["1.0.0"] != "2024-01-02T03:04:05Z" || g.created["1.1.0"] != "2025-06-07T08:09:10Z" {
		t.Fatalf("created_at parse wrong: %+v", g.created)
	}
	if g.created["2.0.0.rc1"] != "" {
		t.Fatal("missing created_at must stay empty")
	}
}
