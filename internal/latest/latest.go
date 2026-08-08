// Package latest resolves "the latest version" of a package straight from
// its registry, for `lockvet pkg <ecosystem>:<name>` when no version is
// given. Each lookup asks the same registry the corresponding metadata
// layer already talks to (same base-URL variables, so tests fake one
// place), prefers the registry's own notion of "latest stable" where the
// API offers one, and otherwise picks the highest non-prerelease version
// lockvet's comparator can order.
package latest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/matteo-sung/lockvet/internal/actreg"
	"github.com/matteo-sung/lockvet/internal/bzlreg"
	"github.com/matteo-sung/lockvet/internal/cargoreg"
	"github.com/matteo-sung/lockvet/internal/condareg"
	"github.com/matteo-sung/lockvet/internal/cranreg"
	"github.com/matteo-sung/lockvet/internal/gemreg"
	"github.com/matteo-sung/lockvet/internal/goreg"
	"github.com/matteo-sung/lockvet/internal/hcache"
	"github.com/matteo-sung/lockvet/internal/hexreg"
	"github.com/matteo-sung/lockvet/internal/hkgreg"
	"github.com/matteo-sung/lockvet/internal/jsrreg"
	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/mvnreg"
	"github.com/matteo-sung/lockvet/internal/npmreg"
	"github.com/matteo-sung/lockvet/internal/phpreg"
	"github.com/matteo-sung/lockvet/internal/podreg"
	"github.com/matteo-sung/lockvet/internal/pubreg"
	"github.com/matteo-sung/lockvet/internal/taglink"
	"github.com/matteo-sung/lockvet/internal/tfreg"
	"github.com/matteo-sung/lockvet/internal/vers"
)

var client = hcache.Client(20 * time.Second)

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

// Extra base URLs for registries whose metadata layer reads a different
// endpoint than the latest-version lookup wants; vars so tests can fake.
var (
	// PyPIURL serves /pypi/{name}/json (info.version = latest stable).
	PyPIURL = "https://pypi.org"
	// NuGetFlatURL is the v3 flat container: /{id}/index.json lists all
	// versions ascending (the endpoint `dotnet add package` resolves from).
	NuGetFlatURL = "https://api.nuget.org/v3-flatcontainer"
)

// Supported reports whether Resolve can look up a latest version for eco.
func Supported(eco lock.Ecosystem) bool {
	_, ok := resolvers[eco]
	return ok
}

// Resolve returns the latest (stable, where the registry distinguishes)
// version of name in eco. A package that does not exist is an error.
// JSR packages arrive the way deno.lock records them: npm ecosystem,
// name prefixed "jsr:".
func Resolve(eco lock.Ecosystem, name string) (string, error) {
	if eco == lock.NPM && strings.HasPrefix(name, jsrreg.Prefix) {
		return jsrLatest(strings.TrimPrefix(name, jsrreg.Prefix))
	}
	fn, ok := resolvers[eco]
	if !ok {
		return "", fmt.Errorf("no latest-version lookup for %s yet — say which version to vet, e.g. %s:%s@<version>", eco, specPrefix(eco), name)
	}
	v, err := fn(name)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", fmt.Errorf("%s: no releases found for %s", eco, name)
	}
	return v, nil
}

var resolvers = map[lock.Ecosystem]func(string) (string, error){
	lock.NPM:       npmLatest,
	lock.PyPI:      pypiLatest,
	lock.CratesIO:  cratesLatest,
	lock.RubyGems:  gemLatest,
	lock.Packagist: packagistLatest,
	lock.Go:        goreg.Latest,
	lock.Hex:       hexLatest,
	lock.Pub:       pubLatest,
	lock.NuGet:     nugetLatest,
	lock.Maven:     mavenLatest,
	lock.CocoaPods: podLatest,
	lock.Terraform: tfLatest,
	lock.CRAN:      cranreg.Latest,
	lock.Conda:     condaLatest,
	lock.Hackage:   hkgreg.Latest,
	lock.Bazel:     bzlreg.Latest,

	// GitHub Actions releases are the action repository's tags; the same
	// anonymous smart-HTTP advertisement actreg resolves pins with
	// answers "latest" (highest stable version-shaped tag).
	lock.GitHubActions: actionsLatest,

	// SwiftPM has no registry: releases ARE the package repository's
	// semver tags, read from the same smart-HTTP advertisement.
	lock.SwiftURL: swiftLatest,
}

// condaLatest resolves [channel/]name against anaconda.org;
// the channel defaults to conda-forge.
func condaLatest(name string) (string, error) {
	channel := "conda-forge"
	if ch, rest, ok := strings.Cut(name, "/"); ok && ch != "" && rest != "" {
		channel, name = ch, rest
	}
	return condareg.Latest(channel, name)
}

func actionsLatest(name string) (string, error) {
	if strings.Count(name, "/") != 1 {
		return "", fmt.Errorf("want owner/repo for a GitHub Action, got %q", name)
	}
	tags, err := taglink.Tags("https://github.com/" + name)
	if err != nil {
		return "", notFound("GitHub", name)
	}
	best := ""
	for t := range tags {
		if !actreg.VersionLike(t) || strings.ContainsAny(t, "-+") {
			continue // skip pre-releases; floating majors compare fine
		}
		if best == "" || vers.Compare(strings.TrimPrefix(best, "v"), strings.TrimPrefix(t, "v")) < 0 {
			best = t
		}
	}
	if best == "" {
		return "", fmt.Errorf("no version-shaped tags in https://github.com/%s", name)
	}
	return best, nil
}

func swiftLatest(name string) (string, error) {
	first, rest, ok := strings.Cut(name, "/")
	if !ok || !strings.Contains(first, ".") || !strings.Contains(rest, "/") {
		return "", fmt.Errorf("want host/owner/repo for a Swift package, got %q", name)
	}
	tags, err := taglink.Tags("https://" + name)
	if err != nil {
		return "", notFound("the repository host", name)
	}
	best := ""
	for t := range tags {
		v := strings.TrimPrefix(t, "v")
		if !actreg.VersionLike(v) || strings.ContainsAny(v, "-+") {
			continue // SwiftPM resolves stable semver tags
		}
		if best == "" || vers.Compare(best, v) < 0 {
			best = v
		}
	}
	if best == "" {
		return "", fmt.Errorf("no version-shaped tags in https://%s", name)
	}
	return best, nil
}

// specPrefix is the canonical spec prefix shown in error hints.
func specPrefix(eco lock.Ecosystem) string {
	switch eco {
	case lock.CratesIO:
		return "cargo"
	case lock.Packagist:
		return "composer"
	case lock.CocoaPods:
		return "pod"
	case lock.Conan:
		return "conan"
	case lock.SwiftURL:
		return "swift"
	case lock.Bazel:
		return "bazel"
	}
	return strings.ToLower(string(eco))
}

func get(rawURL string, accept string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, 0, err
	}
	return body, resp.StatusCode, nil
}

func getJSON(rawURL, accept string, dst any) (int, error) {
	body, status, err := get(rawURL, accept)
	if err != nil {
		return 0, err
	}
	if status != http.StatusOK {
		return status, nil
	}
	return status, json.Unmarshal(body, dst)
}

func notFound(eco, name string) error {
	return fmt.Errorf("%s: package %s not found — check the name (typo here beats typo in your manifest)", eco, name)
}

func unexpected(eco string, status int) error {
	return fmt.Errorf("%s registry answered HTTP %d", eco, status)
}

func npmLatest(name string) (string, error) {
	var doc struct {
		DistTags map[string]string `json:"dist-tags"`
	}
	status, err := getJSON(npmreg.RegistryURL+"/"+url.PathEscape(name),
		"application/vnd.npm.install-v1+json", &doc)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", notFound("npm", name)
	}
	if status != http.StatusOK {
		return "", unexpected("npm", status)
	}
	return doc.DistTags["latest"], nil
}

func pypiLatest(name string) (string, error) {
	var doc struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	status, err := getJSON(PyPIURL+"/pypi/"+url.PathEscape(name)+"/json", "", &doc)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", notFound("PyPI", name)
	}
	if status != http.StatusOK {
		return "", unexpected("PyPI", status)
	}
	return doc.Info.Version, nil
}

func cratesLatest(name string) (string, error) {
	var doc struct {
		Crate struct {
			MaxStable string `json:"max_stable_version"`
			Newest    string `json:"newest_version"`
		} `json:"crate"`
	}
	status, err := getJSON(cargoreg.APIURL+"/crates/"+url.PathEscape(name), "", &doc)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", notFound("crates.io", name)
	}
	if status != http.StatusOK {
		return "", unexpected("crates.io", status)
	}
	if doc.Crate.MaxStable != "" {
		return doc.Crate.MaxStable, nil
	}
	return doc.Crate.Newest, nil
}

func gemLatest(name string) (string, error) {
	var doc struct {
		Version string `json:"version"`
	}
	status, err := getJSON(gemreg.APIURL+"/versions/"+url.PathEscape(name)+"/latest.json", "", &doc)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", notFound("RubyGems", name)
	}
	if status != http.StatusOK {
		return "", unexpected("RubyGems", status)
	}
	if doc.Version == "unknown" { // rubygems.org returns "unknown" for prerelease-only gems
		return "", nil
	}
	return doc.Version, nil
}

func packagistLatest(name string) (string, error) {
	if phpreg.UseAPI {
		// Browser build: repo.packagist.org (p2) sends no CORS headers,
		// but the packagist.org package endpoint does. Its versions map
		// is unordered — the newest non-dev release by publish time wins.
		var doc struct {
			Package struct {
				Versions map[string]struct {
					Version string `json:"version"`
					Time    string `json:"time"`
				} `json:"versions"`
			} `json:"package"`
		}
		status, err := getJSON(phpreg.APIURL+"/packages/"+name+".json", "", &doc)
		if err != nil {
			return "", err
		}
		if status == http.StatusNotFound {
			return "", notFound("Packagist", name)
		}
		if status != http.StatusOK {
			return "", unexpected("Packagist", status)
		}
		best, bestTime := "", ""
		for key, v := range doc.Package.Versions {
			version := v.Version
			if version == "" {
				version = key
			}
			if version == "" || strings.HasPrefix(version, "dev-") || strings.HasSuffix(version, "-dev") {
				continue
			}
			if bestTime == "" || v.Time > bestTime {
				best, bestTime = strings.TrimPrefix(version, "v"), v.Time
			}
		}
		if best == "" {
			return "", nil
		}
		return best, nil
	}
	var doc struct {
		Packages map[string][]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	status, err := getJSON(phpreg.RepoURL+"/p2/"+name+".json", "", &doc)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", notFound("Packagist", name)
	}
	if status != http.StatusOK {
		return "", unexpected("Packagist", status)
	}
	// p2 release files list tagged versions newest-first; skip dev branches.
	for _, v := range doc.Packages[strings.ToLower(name)] {
		if v.Version != "" && !strings.HasPrefix(v.Version, "dev-") {
			return v.Version, nil
		}
	}
	return "", nil
}

func hexLatest(name string) (string, error) {
	var doc struct {
		LatestStable string `json:"latest_stable_version"`
		Latest       string `json:"latest_version"`
	}
	status, err := getJSON(hexreg.BaseURL+"/api/packages/"+url.PathEscape(name), "", &doc)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", notFound("Hex", name)
	}
	if status != http.StatusOK {
		return "", unexpected("hex.pm", status)
	}
	if doc.LatestStable != "" {
		return doc.LatestStable, nil
	}
	return doc.Latest, nil
}

func pubLatest(name string) (string, error) {
	var doc struct {
		Latest struct {
			Version string `json:"version"`
		} `json:"latest"`
	}
	status, err := getJSON(pubreg.BaseURL+"/api/packages/"+url.PathEscape(name), "", &doc)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", notFound("pub.dev", name)
	}
	if status != http.StatusOK {
		return "", unexpected("pub.dev", status)
	}
	return doc.Latest.Version, nil
}

func jsrLatest(name string) (string, error) {
	n := strings.TrimPrefix(name, "@")
	scope, pkg, ok := strings.Cut(n, "/")
	if !ok {
		return "", fmt.Errorf("JSR package names look like @scope/name (got %s)", name)
	}
	var doc struct {
		Latest string `json:"latest"`
	}
	status, err := getJSON(jsrreg.BaseURL+"/@"+scope+"/"+pkg+"/meta.json", "", &doc)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", notFound("JSR", name)
	}
	if status != http.StatusOK {
		return "", unexpected("jsr.io", status)
	}
	return doc.Latest, nil
}

func nugetLatest(name string) (string, error) {
	var doc struct {
		Versions []string `json:"versions"`
	}
	status, err := getJSON(NuGetFlatURL+"/"+strings.ToLower(name)+"/index.json", "", &doc)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", notFound("NuGet", name)
	}
	if status != http.StatusOK {
		return "", unexpected("NuGet", status)
	}
	return pickHighest(doc.Versions), nil
}

func mavenLatest(name string) (string, error) {
	group, artifact, ok := strings.Cut(name, ":")
	if !ok {
		return "", fmt.Errorf("Maven package names look like group:artifact (got %s)", name)
	}
	path := "/" + strings.ReplaceAll(group, ".", "/") + "/" + artifact + "/maven-metadata.xml"
	for _, base := range orderedMavenBases(group, artifact) {
		body, status, err := get(base+path, "")
		if err != nil {
			return "", err
		}
		if status == http.StatusNotFound {
			continue
		}
		if status != http.StatusOK {
			return "", unexpected("Maven", status)
		}
		var doc struct {
			Versioning struct {
				Release  string   `xml:"release"`
				Latest   string   `xml:"latest"`
				Versions []string `xml:"versions>version"`
			} `xml:"versioning"`
		}
		if err := mvnreg.DecodeXML(body, &doc); err != nil {
			return "", err
		}
		if doc.Versioning.Release != "" {
			return doc.Versioning.Release, nil
		}
		if doc.Versioning.Latest != "" {
			return doc.Versioning.Latest, nil
		}
		return pickHighest(doc.Versioning.Versions), nil
	}
	return "", notFound("Maven", name)
}

// orderedMavenBases mirrors mvnreg's heuristics: androidx/com.android/
// com.google.android groups live on Google's Maven repository, and
// Gradle plugin markers (id:id.gradle.plugin) on the Plugin Portal.
func orderedMavenBases(group, artifact string) []string {
	if strings.HasSuffix(artifact, ".gradle.plugin") {
		return []string{mvnreg.PluginPortalURL, mvnreg.CentralURL}
	}
	if strings.HasPrefix(group, "androidx.") || strings.HasPrefix(group, "com.android") ||
		strings.HasPrefix(group, "com.google.android") {
		return []string{mvnreg.GoogleURL, mvnreg.CentralURL}
	}
	return []string{mvnreg.CentralURL, mvnreg.GoogleURL}
}

func podLatest(name string) (string, error) {
	versions, status, err := podreg.ShardVersions(name)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", unexpected("CocoaPods", status)
	}
	if len(versions) == 0 {
		return "", notFound("CocoaPods", name)
	}
	return pickHighest(versions), nil
}

func tfLatest(name string) (string, error) {
	if strings.Count(name, "/") != 1 {
		return "", fmt.Errorf("Terraform providers look like namespace/name (got %s)", name)
	}
	var doc struct {
		Versions []struct {
			Version string `json:"version"`
		} `json:"versions"`
	}
	status, err := getJSON(tfreg.TerraformBaseURL+"/v1/providers/"+name+"/versions", "", &doc)
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", notFound("Terraform registry", name)
	}
	if status != http.StatusOK {
		return "", unexpected("Terraform registry", status)
	}
	var vs []string
	for _, v := range doc.Versions {
		vs = append(vs, v.Version)
	}
	return pickHighest(vs), nil
}

// pickHighest returns the highest stable version in vs (highest overall
// when every version looks like a prerelease).
func pickHighest(vs []string) string {
	best, bestAny := "", ""
	for _, v := range vs {
		if v == "" {
			continue
		}
		if bestAny == "" || vers.Compare(v, bestAny) > 0 {
			bestAny = v
		}
		if prereleaseLooking(v) {
			continue
		}
		if best == "" || vers.Compare(v, best) > 0 {
			best = v
		}
	}
	if best != "" {
		return best
	}
	return bestAny
}

// prereleaseLooking: anything beyond digits, dots and a leading v smells
// like a prerelease or platform-specific build (1.2.3-beta.1, 1.0.0-rc1).
func prereleaseLooking(v string) bool {
	v = strings.TrimPrefix(v, "v")
	for _, r := range v {
		if !unicode.IsDigit(r) && r != '.' {
			return true
		}
	}
	return false
}
