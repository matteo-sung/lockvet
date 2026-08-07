package lock

import (
	"strings"
	"testing"
)

const catalogSample = `
# Version catalog.
[versions]
agp = "8.1.1"
kotlin = '1.9.10'
range = "[1.0, 2.0]"
rich = { strictly = "2.5.0" }
dyn = "1.+"

[libraries]
android-gradlePlugin = { group = "com.android.tools.build", name = "gradle", version.ref = "agp" }
guava = "com.google.guava:guava:32.1.2-jre"   # shorthand
okio = { module = "com.squareup.okio:okio", version = "3.6.0" }
bom-managed = { module = "io.ktor:ktor-client-core" }
ranged = { module = "org.example:ranged", version.ref = "range" }
dynamic = { module = "org.example:dyn", version.ref = "dyn" }
richlib = { module = "org.example:rich", version = { strictly = "9.9.9", prefer = "9.0.0" } }
dotted = { module = "org.example:dotted", version.require = "4.4.4" }

[bundles]
stuff = ["guava", "okio"]

[plugins]
kotlinJvm = { id = "org.jetbrains.kotlin.jvm", version.ref = "kotlin" }
shorthandPlugin = "com.diffplug.spotless:6.20.0"
`

func TestParseVersionCatalog(t *testing.T) {
	f, err := parseVersionCatalog("gradle/libs.versions.toml", []byte(catalogSample))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"com.android.tools.build:gradle": "8.1.1",
		"com.google.guava:guava":         "32.1.2-jre",
		"com.squareup.okio:okio":         "3.6.0",
		"org.example:rich":               "9.9.9",
		"org.example:dotted":             "4.4.4",
		"org.jetbrains.kotlin.jvm:org.jetbrains.kotlin.jvm.gradle.plugin": "1.9.10",
		"com.diffplug.spotless:com.diffplug.spotless.gradle.plugin":       "6.20.0",
	}
	for name, v := range want {
		got := f.Packages[name]
		if len(got) != 1 || got[0] != v {
			t.Errorf("%s = %v, want [%s]", name, got, v)
		}
	}
	for _, absent := range []string{"io.ktor:ktor-client-core", "org.example:ranged", "org.example:dyn"} {
		if _, ok := f.Packages[absent]; ok {
			t.Errorf("%s should be skipped (no exact version)", absent)
		}
	}
	if len(f.Packages) != len(want) {
		t.Errorf("got %d packages, want %d: %v", len(f.Packages), len(want), f.Packages)
	}
	if !f.RootsKnown || len(f.Roots) != len(want) {
		t.Errorf("all catalog entries should be roots (got %d, known=%v)", len(f.Roots), f.RootsKnown)
	}
	if f.Ecosystem != Maven {
		t.Errorf("ecosystem = %s, want Maven", f.Ecosystem)
	}
}

func TestVersionCatalogByBasename(t *testing.T) {
	for _, p := range []string{
		"gradle/libs.versions.toml",
		"libs.versions.toml",
		"gradle/tools.versions.toml",
	} {
		parser := ByBasename(p)
		if parser == nil || parser.Kind != "libs.versions.toml" {
			t.Errorf("ByBasename(%s) = %v, want libs.versions.toml parser", p, parser)
		}
	}
	if ByBasename("versions.toml") != nil {
		t.Error("bare versions.toml should not match")
	}
}

const vmSample = `<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata xmlns="https://schema.gradle.org/dependency-verification">
   <configuration>
      <verify-metadata>true</verify-metadata>
   </configuration>
   <components>
      <component group="com.google.guava" name="guava" version="32.1.2-jre">
         <artifact name="guava-32.1.2-jre.jar">
            <sha256 value="AABB01"/>
         </artifact>
         <artifact name="guava-32.1.2-jre.pom">
            <sha256 value="CCDD02"/>
         </artifact>
      </component>
      <component group="androidx.activity" name="activity" version="1.8.0">
         <artifact name="activity-1.8.0.aar">
            <sha256 value="EEFF03">
               <also-trust value="EEFF04"/>
            </sha256>
            <sha512 value="0011AA"/>
         </artifact>
      </component>
      <component group="org.example" name="pomonly" version="2.0">
         <artifact name="pomonly-2.0.pom">
            <md5 value="ABCD"/>
         </artifact>
      </component>
      <component group="org.example" name="snap" version="1.0-SNAPSHOT">
         <artifact name="snap-1.0-SNAPSHOT.jar">
            <sha256 value="FFFF"/>
         </artifact>
      </component>
   </components>
</verification-metadata>`

func TestParseVerificationMetadata(t *testing.T) {
	f, err := parseVerificationMetadata("gradle/verification-metadata.xml", []byte(vmSample))
	if err != nil {
		t.Fatal(err)
	}
	if f.Ecosystem != Maven {
		t.Errorf("ecosystem = %s, want Maven", f.Ecosystem)
	}
	if got := f.Packages["com.google.guava:guava"]; len(got) != 1 || got[0] != "32.1.2-jre" {
		t.Errorf("guava = %v", got)
	}
	// Every artifact's hashes are pinned, scoped per file — so a NEW
	// artifact appearing (Gradle resolving another variant) never flags,
	// while the SAME file changing hashes does.
	pin := f.Pin("com.google.guava:guava", "32.1.2-jre")
	if pin.Integrity != "guava-32.1.2-jre.jar#sha256:aabb01 guava-32.1.2-jre.pom#sha256:ccdd02" {
		t.Errorf("guava pin = %q", pin.Integrity)
	}
	pin = f.Pin("androidx.activity:activity", "1.8.0")
	if pin.Integrity != "activity-1.8.0.aar#sha256:eeff03 activity-1.8.0.aar#sha256:eeff04 activity-1.8.0.aar#sha512:0011aa" {
		t.Errorf("activity pin = %q", pin.Integrity)
	}
	if pin := f.Pin("org.example:pomonly", "2.0"); pin.Integrity != "pomonly-2.0.pom#md5:abcd" {
		t.Errorf("pomonly pin = %q", pin.Integrity)
	}
	if pin := f.Pin("org.example:snap", "1.0-SNAPSHOT"); pin.Integrity != "" {
		t.Errorf("SNAPSHOT must not be pinned, got %q", pin.Integrity)
	}
	if len(f.Packages) != 4 {
		t.Errorf("got %d packages, want 4", len(f.Packages))
	}
}

func TestVerificationMetadataByBasename(t *testing.T) {
	for _, p := range []string{
		"gradle/verification-metadata.xml",
		"gradle/verification-metadata.dryrun.xml",
	} {
		parser := ByBasename(p)
		if parser == nil || parser.Kind != "verification-metadata.xml" {
			t.Errorf("ByBasename(%s) = %v, want verification-metadata parser", p, parser)
		}
	}
}

func TestVerificationMetadataRepin(t *testing.T) {
	tampered := strings.Replace(vmSample, `value="AABB01"`, `value="9999FF"`, 1)
	oldF, _ := parseVerificationMetadata("gradle/verification-metadata.xml", []byte(vmSample))
	newF, _ := parseVerificationMetadata("gradle/verification-metadata.xml", []byte(tampered))
	if oldF.Pin("com.google.guava:guava", "32.1.2-jre").Integrity ==
		newF.Pin("com.google.guava:guava", "32.1.2-jre").Integrity {
		t.Fatal("tampered pin should differ")
	}
}
