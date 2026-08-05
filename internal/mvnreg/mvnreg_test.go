package mvnreg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

func fixedNow(t *testing.T) time.Time {
	t.Helper()
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	old := Now
	Now = func() time.Time { return now }
	t.Cleanup(func() { Now = old })
	return now
}

// fakeRepo serves POMs from a map of "group/artifact/version" → body,
// stamping Last-Modified when a time is registered.
func fakeRepo(t *testing.T, poms map[string]string, times map[string]time.Time, hits *int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt64(hits, 1)
		}
		p := strings.TrimPrefix(r.URL.Path, "/")
		parts := strings.Split(p, "/")
		if len(parts) < 4 || !strings.HasSuffix(parts[len(parts)-1], ".pom") {
			http.NotFound(w, r)
			return
		}
		version := parts[len(parts)-2]
		artifact := parts[len(parts)-3]
		group := strings.Join(parts[:len(parts)-3], ".")
		key := group + "/" + artifact + "/" + version
		body, ok := poms[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if ts, ok := times[key]; ok {
			w.Header().Set("Last-Modified", ts.UTC().Format(http.TimeFormat))
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func setHosts(t *testing.T, central, google string) {
	t.Helper()
	oc, og := CentralURL, GoogleURL
	CentralURL, GoogleURL = central, google
	t.Cleanup(func() { CentralURL, GoogleURL = oc, og })
}

const plainPOM = `<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion></project>`

const relocPOM = `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <distributionManagement>
    <relocation>
      <groupId>com.mysql</groupId>
      <artifactId>mysql-connector-j</artifactId>
      <message>MySQL Connector/J artifacts moved to reverse-DNS compliant Maven 2+ coordinates.</message>
    </relocation>
  </distributionManagement>
</project>`

func oneDiff(changes ...diffx.Change) []diffx.FileDiff {
	return []diffx.FileDiff{{Path: "gradle.lockfile", Changes: changes}}
}

func TestRelocationLandsInDeprecationLane(t *testing.T) {
	fixedNow(t)
	central := fakeRepo(t, map[string]string{
		"mysql/mysql-connector-java/8.0.33": relocPOM,
	}, nil, nil)
	setHosts(t, central.URL, central.URL+"/nope")

	diffs := oneDiff(diffx.Change{
		Name: "mysql:mysql-connector-java", Ecosystem: "Maven",
		Old: []string{"8.0.32"}, New: []string{"8.0.33"},
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated {
		t.Fatal("relocation stub not flagged deprecated")
	}
	want := "relocated to com.mysql:mysql-connector-j — MySQL Connector/J artifacts moved to reverse-DNS compliant Maven 2+ coordinates."
	if c.DeprecatedReason != want {
		t.Fatalf("reason = %q, want %q", c.DeprecatedReason, want)
	}
}

func TestRelocationKeepsRicherReason(t *testing.T) {
	fixedNow(t)
	central := fakeRepo(t, map[string]string{
		"mysql/mysql-connector-java/8.0.33": relocPOM,
	}, nil, nil)
	setHosts(t, central.URL, central.URL+"/nope")

	diffs := oneDiff(diffx.Change{
		Name: "mysql:mysql-connector-java", Ecosystem: "Maven",
		New: []string{"8.0.33"}, Deprecated: true, DeprecatedReason: "existing reason",
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if got := diffs[0].Changes[0].DeprecatedReason; got != "existing reason" {
		t.Fatalf("reason overwritten: %q", got)
	}
}

func TestSelfRelocationIgnored(t *testing.T) {
	fixedNow(t)
	// A relocation that resolves to the same coordinates (version-only
	// relocation) is not a deprecation.
	pom := `<project><distributionManagement><relocation><version>9.0.0</version></relocation></distributionManagement></project>`
	central := fakeRepo(t, map[string]string{"g/a/1.0.0": pom}, nil, nil)
	setHosts(t, central.URL, central.URL+"/nope")

	diffs := oneDiff(diffx.Change{Name: "g:a", Ecosystem: "Maven", New: []string{"1.0.0"}})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if diffs[0].Changes[0].Deprecated {
		t.Fatal("self-relocation flagged")
	}
}

func TestUnlistedClearedWhenServed(t *testing.T) {
	fixedNow(t)
	central := fakeRepo(t, map[string]string{"g/a/1.2.3": plainPOM}, nil, nil)
	setHosts(t, central.URL, central.URL+"/nope")

	diffs := oneDiff(diffx.Change{
		Name: "g:a", Ecosystem: "Maven", New: []string{"1.2.3"},
		Unlisted: true, UnlistedVersions: []string{"1.2.3"},
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if c.Unlisted || len(c.UnlistedVersions) != 0 {
		t.Fatalf("lagging unlisted flag not cleared: %+v", c)
	}
}

func TestUnlistedKeptOnDoubleMiss(t *testing.T) {
	fixedNow(t)
	central := fakeRepo(t, nil, nil, nil)
	google := fakeRepo(t, nil, nil, nil)
	setHosts(t, central.URL, google.URL)

	diffs := oneDiff(diffx.Change{
		Name: "g:a", Ecosystem: "Maven", New: []string{"9.9.9"},
		Unlisted: true, UnlistedVersions: []string{"9.9.9"},
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || len(c.UnlistedVersions) != 1 {
		t.Fatalf("registry-verified unlisted flag lost: %+v", c)
	}
}

func TestAgeBackfillFromLastModified(t *testing.T) {
	now := fixedNow(t)
	central := fakeRepo(t, map[string]string{"g/a/2.0.0": plainPOM},
		map[string]time.Time{"g/a/2.0.0": now.Add(-3 * 24 * time.Hour)}, nil)
	setHosts(t, central.URL, central.URL+"/nope")

	diffs := oneDiff(diffx.Change{Name: "g:a", Ecosystem: "Maven", New: []string{"2.0.0"}})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 3 || !c.Fresh || c.PublishedAt == "" {
		t.Fatalf("age backfill wrong: %+v", c)
	}
}

func TestDepsDevAgeNotOverwritten(t *testing.T) {
	now := fixedNow(t)
	central := fakeRepo(t, map[string]string{"g/a/2.0.0": plainPOM},
		map[string]time.Time{"g/a/2.0.0": now.Add(-100 * 24 * time.Hour)}, nil)
	setHosts(t, central.URL, central.URL+"/nope")

	diffs := oneDiff(diffx.Change{
		Name: "g:a", Ecosystem: "Maven", New: []string{"2.0.0"},
		PublishedAt: "2026-08-01T00:00:00Z", AgeDays: 4,
	})
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; c.AgeDays != 4 {
		t.Fatalf("deps.dev age overwritten: %+v", c)
	}
}

func TestGoogleFallbackAndHostMemo(t *testing.T) {
	fixedNow(t)
	var centralHits, googleHits int64
	central := fakeRepo(t, nil, nil, &centralHits)
	google := fakeRepo(t, map[string]string{
		"androidx.core/core/1.13.0": plainPOM,
		"androidx.core/core/1.16.0": plainPOM,
	}, nil, &googleHits)
	setHosts(t, central.URL, google.URL)

	diffs := oneDiff(
		diffx.Change{Name: "androidx.core:core", Ecosystem: "Maven", New: []string{"1.13.0"}},
		diffx.Change{Name: "androidx.core:core", Ecosystem: "Maven", New: []string{"1.16.0"}},
	)
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	// androidx guesses Google first: Central should never be touched.
	if centralHits != 0 {
		t.Fatalf("central hit %d times for an androidx artifact", centralHits)
	}
	if googleHits != 2 {
		t.Fatalf("google hits = %d, want 2", googleHits)
	}
}

func TestDedupAcrossFiles(t *testing.T) {
	fixedNow(t)
	var hits int64
	central := fakeRepo(t, map[string]string{"g/a/1.0.0": plainPOM}, nil, &hits)
	setHosts(t, central.URL, central.URL+"/nope")

	diffs := []diffx.FileDiff{
		{Path: "a/gradle.lockfile", Changes: []diffx.Change{{Name: "g:a", Ecosystem: "Maven", New: []string{"1.0.0"}}}},
		{Path: "b/gradle.lockfile", Changes: []diffx.Change{{Name: "g:a", Ecosystem: "Maven", New: []string{"1.0.0"}}}},
	}
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if hits != 1 {
		t.Fatalf("same version fetched %d times, want 1", hits)
	}
}

func TestSkipsNonRegistryBadCoordsAndDynamicVersions(t *testing.T) {
	fixedNow(t)
	var hits int64
	central := fakeRepo(t, nil, nil, &hits)
	setHosts(t, central.URL, central.URL)

	diffs := oneDiff(
		diffx.Change{Name: "g:a", Ecosystem: "Maven", New: []string{"1.0.0"}, NonRegistry: true},
		diffx.Change{Name: "no-colon", Ecosystem: "Maven", New: []string{"1.0.0"}},
		diffx.Change{Name: "g:a:classifier", Ecosystem: "Maven", New: []string{"1.0.0"}},
		diffx.Change{Name: "g:a", Ecosystem: "Maven", New: []string{"1.+"}},
		diffx.Change{Name: "g:a", Ecosystem: "Maven", New: []string{"../../etc"}},
		diffx.Change{Name: "g:a", Ecosystem: "npm", New: []string{"1.0.0"}},
	)
	if err := Annotate(diffs, 7); err != nil {
		t.Fatal(err)
	}
	if hits != 0 {
		t.Fatalf("skippable changes caused %d requests", hits)
	}
}

func TestErrorWhenNothingSucceeds(t *testing.T) {
	fixedNow(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	setHosts(t, srv.URL, srv.URL)

	diffs := oneDiff(diffx.Change{Name: "g:a", Ecosystem: "Maven", New: []string{"1.0.0"}})
	if err := Annotate(diffs, 7); err == nil {
		t.Fatal("expected error when every request fails")
	}
}
