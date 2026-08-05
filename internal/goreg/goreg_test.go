package goreg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

const compressMod = `module github.com/klauspost/compress

go 1.22

retract (
	// https://github.com/klauspost/compress/issues/1114
	v1.18.1

	// https://github.com/klauspost/compress/pull/503
	v1.14.3
	v1.14.2
)
`

const protobufMod = `// Deprecated: Use the "google.golang.org/protobuf" module instead.
module github.com/golang/protobuf

go 1.17
`

const renamedMod = `module github.com/quic-go/quic-go

go 1.25
`

const rangeMod = `module example.com/ranged

retract [v1.0.0, v1.1.9] // all builds broken

retract v2.0.0+incompatible
`

func fakeProxy(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mods := map[string]string{
		"github.com/klauspost/compress":     compressMod,
		"github.com/golang/protobuf":        protobufMod,
		"github.com/lucas-clemente/quic-go": renamedMod,
		"example.com/ranged":                rangeMod,
	}
	latest := map[string]string{
		"github.com/klauspost/compress":     "v1.19.1",
		"github.com/golang/protobuf":        "v1.5.4",
		"github.com/lucas-clemente/quic-go": "v0.61.0",
		"example.com/ranged":                "v3.0.0",
	}
	infos := map[string]string{
		"github.com/klauspost/compress@v1.19.1": "2026-08-01T00:00:00Z",
		"github.com/klauspost/compress@v1.18.1": "2025-01-01T00:00:00Z",
		"example.com/fresh@v1.0.1":              "2026-08-04T00:00:00Z",
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		for name, v := range latest {
			if path == "/"+escape(name)+"/@latest" {
				fmt.Fprintf(w, `{"Version":%q,"Time":"2026-01-01T00:00:00Z"}`, v)
				return
			}
			if path == "/"+escape(name)+"/@v/"+escape(v)+".mod" {
				fmt.Fprint(w, mods[name])
				return
			}
		}
		if path == "/example.com/fresh/@latest" {
			fmt.Fprint(w, `{"Version":"v1.0.1","Time":"2026-08-04T00:00:00Z"}`)
			return
		}
		if path == "/example.com/fresh/@v/v1.0.1.mod" {
			fmt.Fprint(w, "module example.com/fresh\n")
			return
		}
		for key, ts := range infos {
			name, v, _ := cut(key)
			if path == "/"+escape(name)+"/@v/"+escape(v)+".info" {
				fmt.Fprintf(w, `{"Version":%q,"Time":%q}`, v, ts)
				return
			}
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func cut(key string) (name, version string, ok bool) {
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == '@' {
			return key[:i], key[i+1:], true
		}
	}
	return key, "", false
}

func withProxy(t *testing.T, srv *httptest.Server) {
	t.Helper()
	old := ProxyURL
	ProxyURL = srv.URL
	t.Cleanup(func() { ProxyURL = old })
	oldNow := Now
	Now = func() time.Time { return time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { Now = oldNow })
}

func oneChange(c diffx.Change) []diffx.FileDiff {
	return []diffx.FileDiff{{Path: "go.mod", Changes: []diffx.Change{c}}}
}

func TestRetractedVersionFlagged(t *testing.T) {
	withProxy(t, fakeProxy(t))
	diffs := oneChange(diffx.Change{
		Name: "github.com/klauspost/compress", Ecosystem: "Go",
		Old: []string{"1.18.0"}, New: []string{"1.18.1"},
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated {
		t.Fatalf("want retracted v1.18.1 flagged, got %+v", c)
	}
	if want := "retracted: https://github.com/klauspost/compress/issues/1114"; c.DeprecatedReason != want {
		t.Errorf("reason = %q, want %q", c.DeprecatedReason, want)
	}
}

func TestGroupCommentAppliesToAllItems(t *testing.T) {
	m := parseMod(compressMod)
	if len(m.retractions) != 3 {
		t.Fatalf("want 3 retractions, got %+v", m.retractions)
	}
	want := "https://github.com/klauspost/compress/pull/503"
	if m.retractions[1].rationale != want || m.retractions[2].rationale != want {
		t.Errorf("group comment not shared: %+v", m.retractions[1:])
	}
}

func TestModuleDeprecated(t *testing.T) {
	withProxy(t, fakeProxy(t))
	diffs := oneChange(diffx.Change{
		Name: "github.com/golang/protobuf", Ecosystem: "Go",
		Old: []string{"1.5.3"}, New: []string{"1.5.4"},
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated || c.DeprecatedReason != `module deprecated: Use the "google.golang.org/protobuf" module instead.` {
		t.Errorf("got %+v", c)
	}
}

func TestDepsDevReasonKept(t *testing.T) {
	withProxy(t, fakeProxy(t))
	diffs := oneChange(diffx.Change{
		Name: "github.com/golang/protobuf", Ecosystem: "Go",
		Old: []string{"1.5.3"}, New: []string{"1.5.4"},
		Deprecated: true, DeprecatedReason: "Module deprecated: from deps.dev",
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if got := diffs[0].Changes[0].DeprecatedReason; got != "Module deprecated: from deps.dev" {
		t.Errorf("deps.dev reason clobbered: %q", got)
	}
}

func TestRenamedRepoNotApplied(t *testing.T) {
	withProxy(t, fakeProxy(t))
	diffs := oneChange(diffx.Change{
		Name: "github.com/lucas-clemente/quic-go", Ecosystem: "Go",
		Old: []string{"0.31.0"}, New: []string{"0.31.1"},
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Deprecated {
		t.Error("renamed repo's go.mod must not deprecate the old path")
	}
}

func TestRetractRangeAndIncompatible(t *testing.T) {
	m := parseMod(rangeMod)
	if len(m.retractions) != 2 {
		t.Fatalf("got %+v", m.retractions)
	}
	for v, want := range map[string]bool{
		"1.0.0": true, "1.1.9": true, "1.0.5": true, "1.2.0": false,
		"2.0.0+incompatible": true, "2.0.1+incompatible": false,
	} {
		got := inRange(v, m.retractions[0]) || inRange(v, m.retractions[1])
		if got != want {
			t.Errorf("inRange(%s) = %v, want %v", v, got, want)
		}
	}
	if m.retractions[0].rationale != "all builds broken" {
		t.Errorf("inline rationale lost: %+v", m.retractions[0])
	}
}

func TestAgeBackfillFromInfo(t *testing.T) {
	withProxy(t, fakeProxy(t))
	diffs := oneChange(diffx.Change{
		Name: "example.com/fresh", Ecosystem: "Go",
		Old: []string{"1.0.0"}, New: []string{"1.0.1"},
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if c.PublishedAt != "2026-08-04T00:00:00Z" || !c.Fresh || c.AgeDays != 1 {
		t.Errorf("age backfill: %+v", c)
	}
}

func TestPseudoAgeNeedsNoRequest(t *testing.T) {
	// No server: pseudo timestamps must resolve locally.
	old := ProxyURL
	ProxyURL = "http://127.0.0.1:0"
	defer func() { ProxyURL = old }()
	oldNow := Now
	Now = func() time.Time { return time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC) }
	defer func() { Now = oldNow }()
	diffs := oneChange(diffx.Change{
		Name: "example.com/pseudo", Ecosystem: "Go",
		Old: []string{"0.0.0-20240101120000-abcdef123456"},
		New: []string{"0.0.0-20260804120000-abcdef123456"},
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if c.PublishedAt != "2026-08-04T12:00:00Z" || !c.Fresh {
		t.Errorf("pseudo age: %+v", c)
	}
}

func TestUnlistedVerification(t *testing.T) {
	withProxy(t, fakeProxy(t))
	diffs := oneChange(diffx.Change{
		Name: "github.com/klauspost/compress", Ecosystem: "Go",
		Old: []string{"1.18.0"}, New: []string{"1.18.1", "9.9.9"},
		Unlisted: true, UnlistedVersions: []string{"v1.18.1", "v9.9.9"},
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 || c.UnlistedVersions[0] != "v9.9.9" {
		t.Errorf("unlisted verify: %+v", c)
	}
}

func TestUnknownModuleStaysQuiet(t *testing.T) {
	withProxy(t, fakeProxy(t))
	diffs := oneChange(diffx.Change{
		Name: "corp.internal/private", Ecosystem: "Go",
		Old: []string{"1.0.0"}, New: []string{"1.0.1"},
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if c.Deprecated || c.Unlisted || c.PublishedAt != "" {
		t.Errorf("private module must stay quiet: %+v", c)
	}
}

func TestGoproxyEnvRespected(t *testing.T) {
	t.Setenv("GOPROXY", "off")
	diffs := oneChange(diffx.Change{
		Name: "github.com/klauspost/compress", Ecosystem: "Go",
		Old: []string{"1.18.0"}, New: []string{"1.18.1"},
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Deprecated {
		t.Error("GOPROXY=off must disable the check")
	}

	srv := fakeProxy(t)
	t.Setenv("GOPROXY", srv.URL+",direct")
	oldNow := Now
	Now = func() time.Time { return time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC) }
	defer func() { Now = oldNow }()
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if !diffs[0].Changes[0].Deprecated {
		t.Error("single-URL GOPROXY list head must be used")
	}
}

func TestEscape(t *testing.T) {
	if got := escape("github.com/BurntSushi/toml"); got != "github.com/!burnt!sushi/toml" {
		t.Errorf("escape = %q", got)
	}
}

func TestNonGoAndNonRegistrySkipped(t *testing.T) {
	t.Setenv("GOPROXY", "") // ensure default path; no server needed — must not be hit
	old := ProxyURL
	ProxyURL = "http://127.0.0.1:0"
	defer func() { ProxyURL = old }()
	diffs := []diffx.FileDiff{{Path: "go.mod", Changes: []diffx.Change{
		{Name: "left-pad", Ecosystem: "npm", Old: []string{"1.0.0"}, New: []string{"1.3.0"}},
		{Name: "corp/x", Ecosystem: "Go", NonRegistry: true, New: []string{"1.0.0"}},
	}}}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
}

func TestDepsDevRetractTextKept(t *testing.T) {
	withProxy(t, fakeProxy(t))
	diffs := oneChange(diffx.Change{
		Name: "github.com/klauspost/compress", Ecosystem: "Go",
		Old: []string{"1.18.0"}, New: []string{"1.18.1"},
		Deprecated: true, DeprecatedReason: "Version retracted: https://github.com/klauspost/compress/issues/1114",
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if got := diffs[0].Changes[0].DeprecatedReason; got != "Version retracted: https://github.com/klauspost/compress/issues/1114" {
		t.Errorf("deps.dev retract text churned: %q", got)
	}
}
