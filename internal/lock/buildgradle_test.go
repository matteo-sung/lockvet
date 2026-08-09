package lock

import (
	"strings"
	"testing"
)

func TestParseBuildGradleGroovy(t *testing.T) {
	f := mustParse(t, "build.gradle", `
plugins {
    id 'org.springframework.boot' version '3.4.2'
    id 'java'
}

ext {
    grpcVersion = '1.66.0'
    unusedVersion = '9.9.9'
}
def nettyVersion = "4.1.115.Final"

dependencies {
    implementation 'com.google.guava:guava:33.4.0-jre'
    implementation "io.grpc:grpc-api:$grpcVersion"
    implementation "io.grpc:grpc-core:${grpcVersion}"
    implementation "io.netty:netty-common:${nettyVersion}"
    runtimeOnly group: 'org.postgresql', name: 'postgresql', version: '42.7.4'
    testImplementation 'junit:junit:4.13.2'
    implementation 'org.example:dynamic:1.+'
    implementation 'org.example:range:[1.0,2.0)'
    implementation "org.example:unresolved:${fromPropertiesFile}"
    implementation 'org.example:snap:2.0.0-SNAPSHOT'
    // implementation 'org.example:commented:1.0.0'
    compileOnly 'org.projectlombok:lombok:1.18.36:sources@jar'
    implementation project(':shared')
    implementation files('libs/local.jar')
}

configurations.all {
    resolutionStrategy {
        force 'org.slf4j:slf4j-api:2.0.16'
    }
}
`)
	want := map[string]string{
		"org.springframework.boot:org.springframework.boot.gradle.plugin": "3.4.2",
		"com.google.guava:guava":    "33.4.0-jre",
		"io.grpc:grpc-api":          "1.66.0",
		"io.grpc:grpc-core":         "1.66.0",
		"io.netty:netty-common":     "4.1.115.Final",
		"org.postgresql:postgresql": "42.7.4",
		"junit:junit":               "4.13.2",
		"org.projectlombok:lombok":  "1.18.36",
		"org.slf4j:slf4j-api":       "2.0.16",
		"org.example:snap":          "2.0.0-SNAPSHOT",
	}
	for name, v := range want {
		if got := f.Packages[name]; len(got) != 1 || got[0] != v {
			t.Errorf("%s = %v, want [%s]", name, got, v)
		}
	}
	for _, absent := range []string{"org.example:dynamic", "org.example:range",
		"org.example:unresolved", "org.example:commented"} {
		if _, ok := f.Packages[absent]; ok {
			t.Errorf("%s should not parse", absent)
		}
	}
	if !f.NonRegistry["org.example:snap"] {
		t.Error("SNAPSHOT dependency should be NonRegistry")
	}
	if !f.RootsKnown || len(f.Roots) != len(f.Packages) {
		t.Errorf("roots: known=%v n=%d, want all %d direct", f.RootsKnown, len(f.Roots), len(f.Packages))
	}
	if f.Ecosystem != Maven {
		t.Errorf("eco = %s, want maven", f.Ecosystem)
	}
}

func TestParseBuildGradleKotlinDSL(t *testing.T) {
	f := mustParse(t, "build.gradle.kts", `
plugins {
    kotlin("jvm") version "2.1.10"
    id("com.github.johnrengelman.shadow") version "8.1.1" apply false
}

val ktorVersion = "3.0.3"
extra["exposedVersion"] = "0.57.0"
set("flywayVersion", "11.1.0")

dependencies {
    implementation("io.ktor:ktor-server-core:$ktorVersion")
    implementation("org.jetbrains.exposed:exposed-core:${exposedVersion}")
    implementation(group = "org.flywaydb", name = "flyway-core", version = "11.1.0")
    testImplementation(kotlin("test"))
}
`)
	want := map[string]string{
		"org.jetbrains.kotlin.jvm:org.jetbrains.kotlin.jvm.gradle.plugin":               "2.1.10",
		"com.github.johnrengelman.shadow:com.github.johnrengelman.shadow.gradle.plugin": "8.1.1",
		"io.ktor:ktor-server-core":           "3.0.3",
		"org.jetbrains.exposed:exposed-core": "0.57.0",
		"org.flywaydb:flyway-core":           "11.1.0",
	}
	for name, v := range want {
		if got := f.Packages[name]; len(got) != 1 || got[0] != v {
			t.Errorf("%s = %v, want [%s]", name, got, v)
		}
	}
	if len(f.Packages) != len(want) {
		t.Errorf("parsed %d packages, want %d: %v", len(f.Packages), len(want), f.Packages)
	}
}

func TestParseBuildGradleNoise(t *testing.T) {
	// Strings that must never become packages: URLs, image refs,
	// exclusions without versions, block-commented coordinates,
	// interpolated groups.
	f := mustParse(t, "build.gradle", `
/*
 * implementation 'org.example:blockcommented:1.0.0'
 */
repositories {
    maven { url 'https://repo.example.com/releases' }
}
dependencies {
    implementation('org.example:ok:1.2.3') {
        exclude group: 'commons-logging', module: 'commons-logging'
    }
    implementation "$someGroup:artifact:1.0.0"
}
tasks.register('docker') {
    description = 'builds myrepo/myimage:2.1'
}
`)
	if got := f.Packages["org.example:ok"]; len(got) != 1 || got[0] != "1.2.3" {
		t.Fatalf("org.example:ok = %v", got)
	}
	if len(f.Packages) != 1 {
		t.Fatalf("parsed %v, want only org.example:ok", f.Packages)
	}
}

func TestParseBuildGradleSettings(t *testing.T) {
	f := mustParse(t, "settings.gradle.kts", `
pluginManagement {
    plugins {
        id("org.gradle.toolchains.foojay-resolver-convention") version "0.9.0"
    }
}
`)
	if got := f.Packages["org.gradle.toolchains.foojay-resolver-convention:org.gradle.toolchains.foojay-resolver-convention.gradle.plugin"]; len(got) != 1 || got[0] != "0.9.0" {
		t.Fatalf("foojay plugin = %v", got)
	}
}

func TestBuildGradleByBasename(t *testing.T) {
	for _, p := range []string{
		"build.gradle", "app/build.gradle.kts", "settings.gradle",
		"settings.gradle.kts", "gradle/dependencies.gradle",
		"buildSrc/src/main/kotlin/myproject.java-conventions.gradle.kts",
	} {
		got := ByBasename(p)
		if got == nil || got.Kind != "build.gradle" {
			t.Errorf("ByBasename(%s) = %v, want build.gradle", p, got)
		}
	}
}

func TestStripGradleComments(t *testing.T) {
	in := `implementation 'a:b:1.0' // implementation 'c:d:2.0'
def url = "https://example.com/x" /* not 'e:f:3.0' */
implementation 'g:h:4.0'`
	out := stripGradleComments(in)
	for _, want := range []string{"'a:b:1.0'", "https://example.com/x", "'g:h:4.0'"} {
		if !strings.Contains(out, want) {
			t.Errorf("stripped output lost %s:\n%s", want, out)
		}
	}
	for _, gone := range []string{"c:d:2.0", "e:f:3.0"} {
		if strings.Contains(out, gone) {
			t.Errorf("comment content %s survived:\n%s", gone, out)
		}
	}
	if lines := strings.Count(out, "\n"); lines != strings.Count(in, "\n") {
		t.Errorf("newline count changed: %d vs %d", lines, strings.Count(in, "\n"))
	}
}
