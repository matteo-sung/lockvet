package lock

import (
	"reflect"
	"testing"
)

func TestParseSbtBasics(t *testing.T) {
	src := `
ThisBuild / scalaVersion := "2.13.14"

val CatsVersion = "2.10.0"

libraryDependencies ++= Seq(
  "org.typelevel" %% "cats-core" % CatsVersion,
  "org.postgresql" % "postgresql" % "42.7.3",
  "org.scalatest" %% "scalatest" % "3.2.18" % Test,
  "com.example" %% "dynamic" % "2.+",
  "com.example" % "snap" % "1.0-SNAPSHOT",
)
// "org.commented" %% "out" % "9.9.9"
`
	f, err := parseSbt("build.sbt", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"org.typelevel:cats-core_2.13": "2.10.0",
		"org.postgresql:postgresql":    "42.7.3",
		"org.scalatest:scalatest_2.13": "3.2.18",
		"com.example:snap":             "1.0-SNAPSHOT",
	}
	if len(f.Packages) != len(want) {
		t.Fatalf("packages = %v", f.Packages)
	}
	for name, v := range want {
		if got := f.Packages[name]; len(got) != 1 || got[0] != v {
			t.Errorf("%s = %v, want [%s]", name, got, v)
		}
	}
	if !f.NonRegistry["com.example:snap"] {
		t.Error("SNAPSHOT must be NonRegistry")
	}
	if f.NonRegistry["org.typelevel:cats-core_2.13"] {
		t.Error("registry dep marked NonRegistry")
	}
	if !f.RootsKnown || len(f.Roots) != len(want) {
		t.Errorf("roots = %v", f.Roots)
	}
}

func TestParseSbtScala3AndValRef(t *testing.T) {
	src := `
val scala3 = "3.4.2"
ThisBuild / scalaVersion := scala3
libraryDependencies += "dev.zio" %% "zio" % "2.1.6"
`
	f, _ := parseSbt("build.sbt", []byte(src))
	if got := f.Packages["dev.zio:zio_3"]; len(got) != 1 || got[0] != "2.1.6" {
		t.Fatalf("zio = %v (packages %v)", got, f.Packages)
	}
}

func TestParseSbtUnknownSuffix(t *testing.T) {
	// No scalaVersion in file → %% suffix unknowable → NonRegistry.
	src := `libraryDependencies += "org.typelevel" %% "cats-core" % "2.10.0"`
	f, _ := parseSbt("build.sbt", []byte(src))
	if got := f.Packages["org.typelevel:cats-core"]; len(got) != 1 || got[0] != "2.10.0" {
		t.Fatalf("packages = %v", f.Packages)
	}
	if !f.NonRegistry["org.typelevel:cats-core"] {
		t.Error("suffix-unknown %% dep must be NonRegistry")
	}

	// Conflicting scalaVersions → same.
	src2 := `
lazy val a = project.settings(scalaVersion := "2.13.14")
lazy val b = project.settings(scalaVersion := "2.12.19")
libraryDependencies += "org.typelevel" %% "cats-core" % "2.10.0"
`
	f2, _ := parseSbt("build.sbt", []byte(src2))
	if !f2.NonRegistry["org.typelevel:cats-core"] {
		t.Errorf("conflicting scalaVersions must leave %%%% NonRegistry: %v", f2.Packages)
	}

	// Scala.js %%% → platform suffix unknowable.
	src3 := `
scalaVersion := "2.13.14"
libraryDependencies += "org.scala-js" %%% "scalajs-dom" % "2.8.0"
`
	f3, _ := parseSbt("build.sbt", []byte(src3))
	if !f3.NonRegistry["org.scala-js:scalajs-dom"] {
		t.Errorf("%%%%%% dep must be NonRegistry: %v", f3.Packages)
	}
}

func TestParseSbtPlugins(t *testing.T) {
	src := `
addSbtPlugin("com.github.sbt" % "sbt-native-packager" % "1.10.4")
addSbtPlugin("org.scalameta" % "sbt-scalafmt" % "2.5.2")
`
	f, _ := parseSbt("project/plugins.sbt", []byte(src))
	want := map[string]string{
		"com.github.sbt:sbt-native-packager_2.12_1.0": "1.10.4",
		"org.scalameta:sbt-scalafmt_2.12_1.0":         "2.5.2",
	}
	for name, v := range want {
		if got := f.Packages[name]; len(got) != 1 || got[0] != v {
			t.Errorf("%s = %v, want [%s]", name, got, v)
		}
	}
	if len(f.Packages) != len(want) {
		t.Errorf("plugin coordinates double-counted: %v", f.Packages)
	}
	if len(f.NonRegistry) != 0 {
		t.Errorf("NonRegistry = %v", f.NonRegistry)
	}
}

func TestParseSbtCrossModifiers(t *testing.T) {
	src := `
scalaVersion := "2.13.14"
addCompilerPlugin("org.typelevel" % "kind-projector" % "0.13.3" cross CrossVersion.full)
libraryDependencies += ("com.github.scopt" %% "scopt" % "4.1.0").cross(CrossVersion.for3Use2_13)
libraryDependencies += ("org.example" %% "weird" % "1.0.0").cross(CrossVersion.binary)
`
	f, _ := parseSbt("build.sbt", []byte(src))
	if got := f.Packages["org.typelevel:kind-projector_2.13.14"]; len(got) != 1 || got[0] != "0.13.3" {
		t.Errorf("CrossVersion.full: %v", f.Packages)
	}
	if got := f.Packages["com.github.scopt:scopt_2.13"]; len(got) != 1 || got[0] != "4.1.0" {
		t.Errorf("for3Use2_13: %v", f.Packages)
	}
	if !f.NonRegistry["org.example:weird"] {
		t.Errorf("unresolvable cross must be NonRegistry: %v", f.Packages)
	}
}

func TestParseSbtProjectScala(t *testing.T) {
	src := `
package build

import sbt._

object Dependencies {
  object Versions {
    val cats = "2.10.0"
  }
  val catsCore = "org.typelevel" %% "cats-core" % Versions.cats
  val postgres = "org.postgresql" % "postgresql" % "42.7.3"
}
`
	p := ByBasename("project/Dependencies.scala")
	if p == nil || p.Kind != "build.sbt" {
		t.Fatalf("project/Dependencies.scala parser = %+v", p)
	}
	f, _ := p.Parse("project/Dependencies.scala", []byte(src))
	// No scalaVersion in the file → cats NonRegistry bare name.
	if got := f.Packages["org.typelevel:cats-core"]; len(got) != 1 || got[0] != "2.10.0" {
		t.Fatalf("dotted-ident version: %v", f.Packages)
	}
	if got := f.Packages["org.postgresql:postgresql"]; len(got) != 1 || got[0] != "42.7.3" {
		t.Fatalf("java-style: %v", f.Packages)
	}
	// Ordinary application code parses to an empty file.
	app, _ := p.Parse("project/Build.scala", []byte(`object Main { def main(a: Array[String]) = println("x % y") }`))
	if len(app.Packages) != 0 {
		t.Errorf("app code produced packages: %v", app.Packages)
	}
	// src/…/project/… also routes (over-matching is lenient+free); a
	// scala file NOT under project/ must not.
	if ByBasename("src/main/scala/Foo.scala") != nil {
		t.Error("non-project scala file must not route")
	}
}

func TestParseSbtBuildProps(t *testing.T) {
	p := ByBasename("project/build.properties")
	if p == nil || p.Kind != "build.properties" {
		t.Fatalf("parser = %+v", p)
	}
	f, _ := p.Parse("project/build.properties", []byte("sbt.version=1.10.7\n"))
	if got := f.Packages["org.scala-sbt:sbt"]; len(got) != 1 || got[0] != "1.10.7" {
		t.Fatalf("packages = %v", f.Packages)
	}
	if !reflect.DeepEqual(f.Roots, []string{"org.scala-sbt:sbt"}) {
		t.Errorf("roots = %v", f.Roots)
	}
	// Ant-style build.properties → empty, no error.
	f2, err := p.Parse("build.properties", []byte("version=1.0\nname=app\n"))
	if err != nil || len(f2.Packages) != 0 {
		t.Errorf("ant props: %v %v", f2.Packages, err)
	}
}

func TestSbtRouting(t *testing.T) {
	for _, path := range []string{"build.sbt", "plugins.sbt", "sub/deps.sbt"} {
		p := ByBasename(path)
		if p == nil || p.Kind != "build.sbt" {
			t.Errorf("%s parser = %+v", path, p)
		}
	}
}
