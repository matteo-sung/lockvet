package gradlereg

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

const (
	binSum = "31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26"
	allSum = "2ab88d6de2c23e6adae7363ae6e29cbdd2a709e992929b48b6530fd0c7133bd6"
)

func fakeIndex(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/versions/all", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `[
		 {"version":"8.10.2","buildTime":"20240923212839+0000","snapshot":false,"broken":false,"current":false,
		  "downloadUrl":"%[1]s/distributions/gradle-8.10.2-bin.zip",
		  "checksumUrl":"%[1]s/distributions/gradle-8.10.2-bin.zip.sha256",
		  "checksum":"%[2]s"},
		 {"version":"9.0.0","buildTime":"20260701120000+0000","snapshot":false,"broken":false,"current":true,
		  "downloadUrl":"%[1]s/distributions/gradle-9.0.0-bin.zip",
		  "checksumUrl":"%[1]s/distributions/gradle-9.0.0-bin.zip.sha256",
		  "checksum":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		 {"version":"1.0-milestone-4","buildTime":"20110210120000+0000","snapshot":false,"broken":true,"current":false,
		  "downloadUrl":"%[1]s/distributions/gradle-1.0-milestone-4-bin.zip",
		  "checksumUrl":"%[1]s/distributions/gradle-1.0-milestone-4-bin.zip.sha256",
		  "checksum":""}
		]`, base, binSum)
	})
	mux.HandleFunc("/distributions/gradle-8.10.2-all.zip.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, allSum)
	})
	mux.HandleFunc("/distributions/gradle-8.10.2-bin.zip.sha256", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, binSum)
	})
	server := httptest.NewServer(mux) // anything else 404s
	base = server.URL
	t.Cleanup(server.Close)
	return server
}

func withFake(t *testing.T) {
	t.Helper()
	old := BaseURL
	BaseURL = fakeIndex(t).URL
	ResetForTesting()
	t.Cleanup(func() { BaseURL = old; ResetForTesting() })
}

func change(pins map[string]string, newVers ...string) []diffx.FileDiff {
	return []diffx.FileDiff{{Path: "gradle/wrapper/gradle-wrapper.properties", Changes: []diffx.Change{
		{Name: "gradle", Ecosystem: "Gradle", Kind: diffx.Added, New: newVers, NewPins: pins},
	}}}
}

func TestAgesAndSourceRepo(t *testing.T) {
	withFake(t)
	oldNow := Now
	Now = func() time.Time { return time.Date(2024, 10, 3, 21, 28, 39, 0, time.UTC) }
	defer func() { Now = oldNow }()
	diffs := change(nil, "8.10.2")
	ok, err := Annotate(diffs, 30)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	c := diffs[0].Changes[0]
	if c.AgeDays != 10 || !c.Fresh {
		t.Fatalf("age=%d fresh=%v", c.AgeDays, c.Fresh)
	}
	if c.SourceRepo != "https://github.com/gradle/gradle" {
		t.Fatalf("source repo %q", c.SourceRepo)
	}
	if c.Unlisted || c.TagMismatch || c.Deprecated {
		t.Fatalf("unexpected flags: %+v", c)
	}
}

func TestBrokenRelease(t *testing.T) {
	withFake(t)
	diffs := change(nil, "1.0-milestone-4")
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Deprecated || !strings.Contains(c.DeprecatedReason, "broken") {
		t.Fatalf("want broken deprecation, got %+v", c)
	}
}

func TestUnlistedReproven(t *testing.T) {
	withFake(t)
	diffs := change(nil, "9.9.9")
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.Unlisted || c.UnlistedVersions[0] != "9.9.9" {
		t.Fatalf("want unlisted, got %+v", c)
	}
}

func TestSnapshotExemptFromUnlisted(t *testing.T) {
	withFake(t)
	diffs := change(nil, "9.8.0-20260809003445+0000")
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	if c := diffs[0].Changes[0]; c.Unlisted {
		t.Fatalf("snapshot flagged unlisted: %+v", c)
	}
}

func TestChecksumVerifiedBinAndAll(t *testing.T) {
	for _, sum := range []string{binSum, allSum} {
		withFake(t)
		diffs := change(map[string]string{"8.10.2": "sha256:" + sum}, "8.10.2")
		if _, err := Annotate(diffs, 0); err != nil {
			t.Fatal(err)
		}
		c := diffs[0].Changes[0]
		if !c.DigestVerified || c.TagMismatch {
			t.Fatalf("sum %s: want verified, got %+v", sum[:8], c)
		}
	}
}

func TestChecksumMismatch(t *testing.T) {
	withFake(t)
	bad := strings.Repeat("de", 32)
	diffs := change(map[string]string{"8.10.2": "sha256:" + bad}, "8.10.2")
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if !c.TagMismatch || c.DigestVerified {
		t.Fatalf("want mismatch, got %+v", c)
	}
	if !strings.Contains(c.TagMismatches[0], "distributionSha256Sum dededededede") {
		t.Fatalf("message: %v", c.TagMismatches)
	}
}

func TestChecksumUnprovable(t *testing.T) {
	// The 9.0.0 entry's published checksums can't be fetched (404) and
	// the inline checksum doesn't match: the live re-proof fails → the
	// inline evidence alone must not produce a claim… actually the
	// inline checksum IS official evidence, but the mismatch is only
	// claimed when the live re-proof also fails to clear it. Here the
	// live fetch 404s entirely → no claim either way.
	withFake(t)
	diffs := change(map[string]string{"9.0.0": "sha256:" + strings.Repeat("ab", 32)}, "9.0.0")
	if _, err := Annotate(diffs, 0); err != nil {
		t.Fatal(err)
	}
	c := diffs[0].Changes[0]
	if c.TagMismatch || c.DigestVerified {
		t.Fatalf("want no claim, got %+v", c)
	}
}

func TestNonRegistrySkipped(t *testing.T) {
	withFake(t)
	diffs := change(nil, "8.10.2")
	diffs[0].Changes[0].NonRegistry = true
	ok, err := Annotate(diffs, 0)
	if err != nil || ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestLatest(t *testing.T) {
	withFake(t)
	v, err := Latest("gradle")
	if err != nil || v != "9.0.0" {
		t.Fatalf("v=%q err=%v", v, err)
	}
	if _, err := Latest("something-else"); err == nil {
		t.Fatal("want error for unknown name")
	}
}
