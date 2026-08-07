package lock

import "testing"

const bazelModule = `"""My module."""

module(
    name = "myproject",
    version = "1.0",
)

bazel_dep(name = "rules_java", version = "8.6.1")
bazel_dep(name = "protobuf", version = "33.2", repo_name = "com_google_protobuf")
bazel_dep(
    name = "abseil-cpp",
    version = "20240116.2",
)
bazel_dep(name = "rules_testing", version = "0.6.0", dev_dependency = True)
# bazel_dep(name = "commented_out", version = "9.9.9")
bazel_dep(name = "no_version_yet")

single_version_override(
    module_name = "protobuf",
    version = "35.1",
)
git_override(
    module_name = "rules_fuzzing",
    remote = "https://github.com/example/rules_fuzzing",
    commit = "abc123",
)
bazel_dep(name = "rules_fuzzing", version = "0.5.2")
local_path_override(module_name = "my_local", path = "../local")
`

func TestBazelModule(t *testing.T) {
	f, err := parseBazelModule("MODULE.bazel", []byte(bazelModule))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Packages["rules_java"]; len(got) != 1 || got[0] != "8.6.1" {
		t.Errorf("rules_java = %v", got)
	}
	if got := f.Packages["abseil-cpp"]; len(got) != 1 || got[0] != "20240116.2" {
		t.Errorf("multi-line bazel_dep: abseil-cpp = %v", got)
	}
	if got := f.Packages["protobuf"]; len(got) != 1 || got[0] != "35.1" {
		t.Errorf("single_version_override should win: protobuf = %v", got)
	}
	if got := f.Packages["rules_testing"]; len(got) != 1 || got[0] != "0.6.0" {
		t.Errorf("dev deps still parse: rules_testing = %v", got)
	}
	if _, ok := f.Packages["commented_out"]; ok {
		t.Error("commented-out dep must not parse")
	}
	if _, ok := f.Packages["no_version_yet"]; ok {
		t.Error("version-less dep must not parse")
	}
	if !f.NonRegistry["rules_fuzzing"] {
		t.Error("git_override module should be NonRegistry")
	}
	if !f.NonRegistry["my_local"] {
		t.Error("local_path_override module should be NonRegistry")
	}
	if !f.RootsKnown {
		t.Error("every bazel_dep is a direct dep — roots are known")
	}
}
