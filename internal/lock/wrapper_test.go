package lock

import "testing"

func TestGradleWrapperProps(t *testing.T) {
	data := []byte(`distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionSha256Sum=31C55713E40233A8303827CEB42CA48A47267A0AD4BAB9177123121E71524C26
distributionUrl=https\://services.gradle.org/distributions/gradle-8.10.2-bin.zip
networkTimeout=10000
zipStoreBase=GRADLE_USER_HOME
`)
	f, err := parseGradleWrapperProps("gradle/wrapper/gradle-wrapper.properties", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["gradle"]; len(got) != 1 || got[0] != "8.10.2" {
		t.Fatalf("packages: %v", f.Packages)
	}
	if f.Ecosystem != GradleDist {
		t.Fatalf("eco %q", f.Ecosystem)
	}
	if f.NonRegistry["gradle"] {
		t.Fatal("official host marked NonRegistry")
	}
	pin := f.Pin("gradle", "8.10.2")
	if pin.Integrity != "sha256:31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26" {
		t.Fatalf("integrity %q", pin.Integrity)
	}
	if pin.Host != "services.gradle.org" {
		t.Fatalf("host %q", pin.Host)
	}
	if !f.RootsKnown || len(f.Roots) != 1 {
		t.Fatalf("roots: %v known=%v", f.Roots, f.RootsKnown)
	}
}

func TestGradleWrapperVariants(t *testing.T) {
	for _, tc := range []struct{ url, version string }{
		{`https\://services.gradle.org/distributions/gradle-8.11-rc-1-all.zip`, "8.11-rc-1"},
		{`https\://services.gradle.org/distributions-snapshots/gradle-9.8.0-20260809003445+0000-bin.zip`, "9.8.0-20260809003445+0000"},
		{`https\://services.gradle.org/distributions/gradle-7.0-all.zip`, "7.0"},
	} {
		f, err := parseGradleWrapperProps("p", []byte("distributionUrl="+tc.url+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if got := f.Packages["gradle"]; len(got) != 1 || got[0] != tc.version {
			t.Fatalf("%s: %v", tc.url, f.Packages)
		}
	}
	// Non-distribution URLs claim nothing.
	f, _ := parseGradleWrapperProps("p", []byte(`distributionUrl=https\://example.com/something-8.1.zip`+"\n"))
	if len(f.Packages) != 0 {
		t.Fatalf("junk URL parsed: %v", f.Packages)
	}
}

func TestGradleWrapperMirrorNonRegistry(t *testing.T) {
	data := []byte(`distributionUrl=https\://artifacts.corp.example/gradle/gradle-8.10.2-bin.zip
distributionSha256Sum=31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26
`)
	f, err := parseGradleWrapperProps("p", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["gradle"]; len(got) != 1 || got[0] != "8.10.2" {
		t.Fatalf("packages: %v", f.Packages)
	}
	if !f.NonRegistry["gradle"] {
		t.Fatal("mirror host not NonRegistry")
	}
	// The integrity pin still lands: the offline checksum-swap check
	// works on mirrors too.
	if f.Pin("gradle", "8.10.2").Integrity == "" {
		t.Fatal("mirror pin lost")
	}
}

func TestMavenWrapperProps(t *testing.T) {
	data := []byte(`wrapperVersion=3.3.2
distributionType=only-script
distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.9/apache-maven-3.9.9-bin.zip
distributionSha256Sum=7a9cdf674fc1703d6382f5f330b3d110ea1b512b51f1652846d9e4e8a588d766
wrapperUrl=https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.3.2/maven-wrapper-3.3.2.jar
`)
	f, err := parseMavenWrapperProps(".mvn/wrapper/maven-wrapper.properties", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["org.apache.maven:apache-maven"]; len(got) != 1 || got[0] != "3.9.9" {
		t.Fatalf("packages: %v", f.Packages)
	}
	if got := f.Packages["org.apache.maven.wrapper:maven-wrapper"]; len(got) != 1 || got[0] != "3.3.2" {
		t.Fatalf("wrapper: %v", f.Packages)
	}
	if f.Ecosystem != Maven {
		t.Fatalf("eco %q", f.Ecosystem)
	}
	if len(f.NonRegistry) != 0 {
		t.Fatalf("official host marked NonRegistry: %v", f.NonRegistry)
	}
	pin := f.Pin("org.apache.maven:apache-maven", "3.9.9")
	if pin.Integrity != "sha256:7a9cdf674fc1703d6382f5f330b3d110ea1b512b51f1652846d9e4e8a588d766" {
		t.Fatalf("integrity %q", pin.Integrity)
	}
	// No wrapperSha256Sum → host-only pin, no integrity.
	if p := f.Pin("org.apache.maven.wrapper:maven-wrapper", "3.3.2"); p.Integrity != "" || p.Host != "repo.maven.apache.org" {
		t.Fatalf("wrapper pin: %+v", p)
	}
}

func TestMavenWrapperMirror(t *testing.T) {
	// Nexus-style mirror: prefix segments stripped, coordinate still
	// parses, NonRegistry.
	data := []byte(`distributionUrl=https://nexus.corp.example/repository/maven-central/org/apache/maven/apache-maven/3.9.9/apache-maven-3.9.9-bin.zip
`)
	f, err := parseMavenWrapperProps("p", data)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["org.apache.maven:apache-maven"]; len(got) != 1 {
		t.Fatalf("packages: %v", f.Packages)
	}
	if !f.NonRegistry["org.apache.maven:apache-maven"] {
		t.Fatal("mirror not NonRegistry")
	}
	// A mirror URL that doesn't follow the repository layout claims
	// nothing (no fabricated coordinates).
	f, _ = parseMavenWrapperProps("p", []byte("distributionUrl=https://files.corp.example/downloads/apache-maven-3.9.9-bin.zip\n"))
	if len(f.Packages) != 0 {
		t.Fatalf("layout-less URL parsed: %v", f.Packages)
	}
}

func TestJavaPropertiesEscapes(t *testing.T) {
	props := parseJavaProperties([]byte("a\\:b=1\nc = with\\ttab\nlong=start\\\n  end\n# comment\n! also\nkey2: v2\n"))
	if props["a:b"] != "1" {
		t.Fatalf("escaped key: %v", props)
	}
	if props["c"] != "with\ttab" {
		t.Fatalf("tab: %q", props["c"])
	}
	if props["long"] != "startend" {
		t.Fatalf("continuation: %q", props["long"])
	}
	if props["key2"] != "v2" {
		t.Fatalf("colon sep: %v", props)
	}
}

func TestWrapperByBasename(t *testing.T) {
	p := ByBasename("gradle/wrapper/gradle-wrapper.properties")
	if p == nil || p.Kind != "gradle-wrapper.properties" || p.Ecosystem != GradleDist {
		t.Fatalf("gradle: %+v", p)
	}
	p = ByBasename(".mvn/wrapper/maven-wrapper.properties")
	if p == nil || p.Kind != "maven-wrapper.properties" || p.Ecosystem != Maven {
		t.Fatalf("maven: %+v", p)
	}
}

func TestSplitPropertyLineTrailingBackslash(t *testing.T) {
	// A lone or trailing backslash must not panic (fuzz finding) and the
	// key keeps everything scanned.
	for _, in := range []string{`\`, `key\`, `a\=b\`} {
		k, v := splitPropertyLine(in)
		_ = k
		_ = v
	}
	if k, _ := splitPropertyLine(`\`); k != "" {
		t.Fatalf("lone backslash key = %q, want empty", k)
	}
}
