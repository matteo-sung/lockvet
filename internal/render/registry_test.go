package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

func up(eco, name string, from, to string) diffx.Change {
	return diffx.Change{Ecosystem: eco, Name: name, Kind: diffx.Upgraded, Old: []string{from}, New: []string{to}}
}

func TestRegistryLink(t *testing.T) {
	cases := []struct {
		c    diffx.Change
		want string
	}{
		{up("npm", "lodash", "4.17.20", "4.17.21"), "https://www.npmjs.com/package/lodash/v/4.17.21"},
		{up("npm", "@babel/core", "7.0.0", "7.1.0"), "https://www.npmjs.com/package/@babel/core/v/7.1.0"},
		{up("crates.io", "serde", "1.0.0", "1.0.1"), "https://crates.io/crates/serde/1.0.1"},
		{up("PyPI", "requests", "2.31.0", "2.32.0"), "https://pypi.org/project/requests/2.32.0/"},
		{up("Go", "github.com/spf13/cobra", "1.8.0", "1.8.1"), "https://pkg.go.dev/github.com/spf13/cobra@v1.8.1"},
		{up("Packagist", "symfony/console", "6.0.0", "7.0.0"), "https://packagist.org/packages/symfony/console#7.0.0"},
		{up("RubyGems", "rails", "7.1.0", "7.1.1"), "https://rubygems.org/gems/rails/versions/7.1.1"},
		{up("Hex", "phoenix", "1.7.0", "1.7.1"), "https://hex.pm/packages/phoenix/1.7.1"},
		{up("Pub", "http", "1.1.0", "1.2.0"), "https://pub.dev/packages/http/versions/1.2.0"},
		{up("Maven", "com.google.guava:guava", "32.0.0-jre", "33.0.0-jre"), "https://central.sonatype.com/artifact/com.google.guava/guava/33.0.0-jre"},
		{up("NuGet", "Newtonsoft.Json", "13.0.2", "13.0.3"), "https://www.nuget.org/packages/Newtonsoft.Json/13.0.3"},
		{up("Terraform", "hashicorp/aws", "5.30.0", "5.31.0"), "https://registry.terraform.io/providers/hashicorp/aws/5.31.0"},
		{up("Terraform", "registry.opentofu.org/hashicorp/null", "3.2.1", "3.2.2"), "https://search.opentofu.org/provider/hashicorp/null/v3.2.2"},
		{up("Terraform", "example.com/corp/internal", "1.0.0", "1.1.0"), ""},
		{up("Helm", "postgresql", "12.1.8", "12.1.9"), ""},
		{up("CocoaPods", "Alamofire", "5.8.0", "5.9.0"), "https://cocoapods.org/pods/Alamofire"},
		{up("SwiftURL", "github.com/apple/swift-nio", "2.60.0", "2.61.0"), "https://github.com/apple/swift-nio"},
		{up("CRAN", "dplyr", "1.1.3", "1.1.4"), "https://cran.r-project.org/package=dplyr"},
		{up("Bioconductor", "BiocGenerics", "0.46.0", "0.48.0"), "https://bioconductor.org/packages/BiocGenerics/"},

		// no registry page
		{up("Nix", "nixpkgs", "20240101.abcd1234", "20240201.ef567890"), ""},
		// bad Maven coordinate
		{up("Maven", "guava", "1.0", "2.0"), ""},
		// unsafe name: never link
		{up("npm", "evil name)", "1.0.0", "1.0.1"), ""},
		// unsafe version (pnpm peer suffix): fall back to package page
		{up("npm", "react-dom", "18.0.0(react@18.0.0)", "18.2.0(react@18.2.0)"), "https://www.npmjs.com/package/react-dom"},
	}
	for _, tc := range cases {
		if got := registryLink(tc.c); got != tc.want {
			t.Errorf("registryLink(%s %q) = %q, want %q", tc.c.Ecosystem, tc.c.Name, got, tc.want)
		}
	}

	// removed package links to the version being removed
	rm := diffx.Change{Ecosystem: "crates.io", Name: "serde", Kind: diffx.Removed, Old: []string{"1.0.0"}}
	if got, want := registryLink(rm), "https://crates.io/crates/serde/1.0.0"; got != want {
		t.Errorf("removed: got %q, want %q", got, want)
	}
	// multi-version set: fall back to the package page
	multi := diffx.Change{Ecosystem: "npm", Name: "glob", Kind: diffx.Changed, Old: []string{"7.2.3"}, New: []string{"7.2.3", "10.3.10"}}
	if got, want := registryLink(multi), "https://www.npmjs.com/package/glob"; got != want {
		t.Errorf("multi: got %q, want %q", got, want)
	}
}

func TestMarkdownLinksPackages(t *testing.T) {
	diffs := []diffx.FileDiff{{
		Path: "Cargo.lock", Ecosystem: "crates.io",
		Changes: []diffx.Change{up("crates.io", "serde", "1.0.0", "1.0.1")},
	}}
	var buf bytes.Buffer
	Markdown(&buf, diffs, diffx.Summary{Total: 1, Patch: 1}, false, false, 7)
	if !strings.Contains(buf.String(), "[`serde`](https://crates.io/crates/serde/1.0.1)") {
		t.Errorf("markdown missing registry link:\n%s", buf.String())
	}
}
