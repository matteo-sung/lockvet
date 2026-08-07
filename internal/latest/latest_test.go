package latest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matteo-sung/lockvet/internal/gemreg"
	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/mvnreg"
	"github.com/matteo-sung/lockvet/internal/npmreg"
	"github.com/matteo-sung/lockvet/internal/phpreg"
)

func TestNPMLatest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chalk":
			w.Write([]byte(`{"dist-tags":{"latest":"5.6.2"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := npmreg.RegistryURL
	npmreg.RegistryURL = srv.URL
	defer func() { npmreg.RegistryURL = old }()

	v, err := Resolve(lock.NPM, "chalk")
	if err != nil || v != "5.6.2" {
		t.Fatalf("Resolve(npm, chalk) = %q, %v; want 5.6.2", v, err)
	}
	if _, err := Resolve(lock.NPM, "no-such-pkg"); err == nil {
		t.Fatal("Resolve(npm, no-such-pkg): want not-found error")
	}
}

func TestPackagistLatestSkipsDevBranches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/p2/monolog/monolog.json" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"packages":{"monolog/monolog":[
			{"version":"dev-main"},{"version":"3.10.0"},{"version":"3.9.0"}]}}`))
	}))
	defer srv.Close()
	old := phpreg.RepoURL
	phpreg.RepoURL = srv.URL
	defer func() { phpreg.RepoURL = old }()

	v, err := Resolve(lock.Packagist, "monolog/monolog")
	if err != nil || v != "3.10.0" {
		t.Fatalf("Resolve(packagist) = %q, %v; want 3.10.0", v, err)
	}
}

func TestNuGetLatestPicksHighestStable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/newtonsoft.json/index.json" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"versions":["12.0.1","13.0.4","14.0.0-beta1"]}`))
	}))
	defer srv.Close()
	old := NuGetFlatURL
	NuGetFlatURL = srv.URL
	defer func() { NuGetFlatURL = old }()

	v, err := Resolve(lock.NuGet, "Newtonsoft.Json")
	if err != nil || v != "13.0.4" {
		t.Fatalf("Resolve(nuget) = %q, %v; want 13.0.4", v, err)
	}
}

func TestMavenLatestGoogleFallback(t *testing.T) {
	central := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer central.Close()
	google := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/androidx/core/core/maven-metadata.xml" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`<metadata><versioning><release>1.13.1</release></versioning></metadata>`))
	}))
	defer google.Close()
	oldC, oldG := mvnreg.CentralURL, mvnreg.GoogleURL
	mvnreg.CentralURL, mvnreg.GoogleURL = central.URL, google.URL
	defer func() { mvnreg.CentralURL, mvnreg.GoogleURL = oldC, oldG }()

	v, err := Resolve(lock.Maven, "androidx.core:core")
	if err != nil || v != "1.13.1" {
		t.Fatalf("Resolve(maven androidx) = %q, %v; want 1.13.1", v, err)
	}
	if _, err := Resolve(lock.Maven, "com.example:gone"); err == nil {
		t.Fatal("Resolve(maven, gone): want not-found error")
	}
}

func TestGemLatestUnknownMeansNoStable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"version":"unknown"}`))
	}))
	defer srv.Close()
	old := gemreg.APIURL
	gemreg.APIURL = srv.URL
	defer func() { gemreg.APIURL = old }()

	if _, err := Resolve(lock.RubyGems, "prerelease-only"); err == nil {
		t.Fatal("want no-releases error for rubygems 'unknown' answer")
	}
}

func TestUnsupportedEcosystem(t *testing.T) {
	if Supported(lock.Julia) {
		t.Fatal("Julia should not have a latest resolver")
	}
	if _, err := Resolve(lock.Julia, "DataFrames"); err == nil {
		t.Fatal("Resolve(Julia): want unsupported error")
	}
	if !Supported(lock.NPM) || !Supported(lock.Terraform) || !Supported(lock.CRAN) {
		t.Fatal("npm, terraform and cran should be supported")
	}
}

func TestPickHighest(t *testing.T) {
	if v := pickHighest([]string{"1.2.3", "1.10.0", "2.0.0-rc1"}); v != "1.10.0" {
		t.Fatalf("pickHighest = %q, want 1.10.0", v)
	}
	if v := pickHighest([]string{"1.0.0-beta", "1.0.0-alpha"}); v != "1.0.0-beta" {
		t.Fatalf("pickHighest all-prerelease = %q, want 1.0.0-beta", v)
	}
	if v := pickHighest(nil); v != "" {
		t.Fatalf("pickHighest(nil) = %q, want empty", v)
	}
}
