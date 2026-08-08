package lock

import "testing"

const rebarSample = `{"1.2.0",
[{<<"certifi">>,{pkg,<<"certifi">>,<<"2.12.0">>},1},
 {<<"cowboy">>,
  {git,"https://github.com/ninenines/cowboy.git",
       {ref,"72d5f6c01204ad6b2f0acffcded9417c944b6b6c"}},
  0},
 {<<"prometheus_process_collector">>,
  {pkg,<<"prometheus_process_collector">>,<<"1.6.0">>},
  1},
 {<<"redbug">>,{pkg,<<"redbug">>,<<"2.0.6">>},0},
 {<<"uuid">>,{pkg,<<"uuid_erl">>,<<"2.0.1">>},0}]}.
[
{pkg_hash,[
 {<<"certifi">>, <<"2D1CCA2EC95F59643862AF91F001478C9863C2AC9CB6E2F89780BFD8DE987329">>},
 {<<"redbug">>,<<"63C8977A2F71F84A2ACD7E7CFAB74A5EAA787C110105379A34D63C562739B3CF">>},
 {<<"uuid">>, <<"C13F30F291F9E91278BC7B7ADF56D8D89AFD26F5DB5F6E10F13FA24C0C90FED2">>}]},
{pkg_hash_ext,[
 {<<"certifi">>, <<"266DA46BDB06D6C6BEC50941D0D1FDB69EDF4F345AA3E3BF6F14CE7E9C7BA2F7">>},
 {<<"uuid">>, <<"BC4E71DACC2E7A50B3B33FA1BCE0C3501CAE0E64ECF6F4A79A576DA9A62353F4">>}]}].
`

func TestRebarLock(t *testing.T) {
	f := mustParse(t, "rebar.lock", rebarSample)
	if f.Ecosystem != Hex {
		t.Errorf("ecosystem = %s", f.Ecosystem)
	}
	wantPkgs(t, f, map[string][]string{
		// uuid_erl: the Hex package name (pkg tuple), not the OTP app
		// name keying the entry, is what registries and OSV know.
		"certifi": {"2.12.0"}, "prometheus_process_collector": {"1.6.0"},
		"redbug": {"2.0.6"}, "uuid_erl": {"2.0.1"},
	})
	if _, ok := f.Packages["cowboy"]; ok {
		t.Errorf("git entry cowboy must be skipped")
	}
	// Integrity pins: inner (pkg_hash) + outer (pkg_hash_ext), keyed by
	// the app name in the lockfile but attached to the Hex package name.
	pin := f.Pin("certifi", "2.12.0")
	want := "2d1cca2ec95f59643862af91f001478c9863c2ac9cb6e2f89780bfd8de987329" +
		" 266da46bdb06d6c6bec50941d0d1fdb69edf4f345aa3e3bf6f14ce7e9c7ba2f7"
	if pin.Integrity != want {
		t.Errorf("certifi integrity = %q", pin.Integrity)
	}
	// redbug: inner hash only (no pkg_hash_ext entry).
	if got := f.Pin("redbug", "2.0.6").Integrity; got != "63c8977a2f71f84a2acd7e7cfab74a5eaa787c110105379a34d63c562739b3cf" {
		t.Errorf("redbug integrity = %q", got)
	}
	if got := f.Pin("uuid_erl", "2.0.1").Integrity; got == "" {
		t.Errorf("renamed fork uuid_erl lost its hashes")
	}
	// Level-0 entries are the project's direct dependencies.
	if !f.RootsKnown {
		t.Fatalf("roots should be known")
	}
	roots := map[string]bool{}
	for _, r := range f.Roots {
		roots[r] = true
	}
	if !roots["redbug"] || !roots["uuid_erl"] || roots["certifi"] ||
		roots["prometheus_process_collector"] {
		t.Errorf("roots = %v", f.Roots)
	}
}

func TestRebarLockNoHashBlocks(t *testing.T) {
	// Old "1.1.0"/beta locks: entry list only, or pkg_hash without ext.
	f := mustParse(t, "rebar.lock", `{"1.1.0",
[{<<"getopt">>,{pkg,<<"getopt">>,<<"1.0.1">>},0}]}.
`)
	wantPkgs(t, f, map[string][]string{"getopt": {"1.0.1"}})
	if got := f.Pin("getopt", "1.0.1").Integrity; got != "" {
		t.Errorf("integrity = %q", got)
	}
}
