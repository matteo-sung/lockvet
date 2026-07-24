package diffx

import (
	"reflect"
	"sort"
	"testing"

	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/vers"
)

func mk(pkgs map[string][]string) *lock.File {
	return &lock.File{Path: "package-lock.json", Kind: "package-lock.json", Ecosystem: lock.NPM, Packages: pkgs}
}

func find(fd FileDiff, name string) *Change {
	for i := range fd.Changes {
		if fd.Changes[i].Name == name {
			return &fd.Changes[i]
		}
	}
	return nil
}

func TestDiffKinds(t *testing.T) {
	oldF := mk(map[string][]string{
		"a": {"1.0.0"},
		"b": {"2.0.0"},
		"c": {"1.5.0"},
		"d": {"1.0.0"},
		"e": {"1.0.0", "2.0.0"},
	})
	newF := mk(map[string][]string{
		"a": {"1.0.1"},          // patch upgrade
		"b": {"1.9.0"},          // downgrade
		"c": {"1.5.0"},          // unchanged
		"f": {"0.1.0"},          // added
		"e": {"2.0.0", "3.0.0"}, // multi-version change
	})
	fd := Diff(oldF, newF)

	if c := find(fd, "a"); c == nil || c.Kind != Upgraded || c.Level != vers.Patch {
		t.Errorf("a: got %+v", c)
	}
	if c := find(fd, "b"); c == nil || c.Kind != Downgraded {
		t.Errorf("b: got %+v", c)
	}
	if c := find(fd, "c"); c != nil {
		t.Error("c should be absent (unchanged)")
	}
	if c := find(fd, "d"); c == nil || c.Kind != Removed {
		t.Errorf("d: got %+v", c)
	}
	if c := find(fd, "f"); c == nil || c.Kind != Added {
		t.Errorf("f: got %+v", c)
	}
	if c := find(fd, "e"); c == nil || c.Kind != Changed || c.Level != vers.Major {
		t.Errorf("e: got %+v", c)
	}
}

func TestDiffNilSides(t *testing.T) {
	f := mk(map[string][]string{"a": {"1.0.0"}})
	if fd := Diff(nil, f); len(fd.Changes) != 1 || fd.Changes[0].Kind != Added {
		t.Errorf("created lockfile: %+v", fd.Changes)
	}
	if fd := Diff(f, nil); len(fd.Changes) != 1 || fd.Changes[0].Kind != Removed {
		t.Errorf("deleted lockfile: %+v", fd.Changes)
	}
}

func TestSummarize(t *testing.T) {
	oldF := mk(map[string][]string{"a": {"1.0.0"}, "b": {"1.0.0"}})
	newF := mk(map[string][]string{"a": {"2.0.0"}, "b": {"1.0.1"}, "c": {"1.0.0"}})
	s := Summarize([]FileDiff{Diff(oldF, newF)})
	if s.Total != 3 || s.Major != 1 || s.Patch != 1 || s.Added != 1 {
		t.Errorf("summary: %+v", s)
	}
}

func TestOriginAnnotation(t *testing.T) {
	oldF := mk(map[string][]string{
		"express": {"4.17.0"}, "debug": {"2.6.8"}, "ms": {"1.0.0"}, "gone": {"1.0.0"},
	})
	newF := mk(map[string][]string{
		"express": {"4.17.1"}, "debug": {"2.6.9"}, "ms": {"2.0.0"},
	})
	newF.RootsKnown = true
	newF.Roots = []string{"express"}
	newF.Deps = map[string][]string{"express": {"debug"}, "debug": {"ms"}}
	oldF.RootsKnown = true
	oldF.Roots = []string{"express"}
	oldF.Deps = map[string][]string{"express": {"debug", "gone"}, "debug": {"ms"}}

	fd := Diff(oldF, newF)

	if c := find(fd, "express"); c == nil || c.Origin != "direct" || len(c.Via) != 0 {
		t.Errorf("express: got %+v, want direct", c)
	}
	if c := find(fd, "debug"); c == nil || c.Origin != "transitive" ||
		len(c.Via) != 1 || c.Via[0] != "express" {
		t.Errorf("debug: got %+v, want transitive via [express]", c)
	}
	if c := find(fd, "ms"); c == nil || c.Origin != "transitive" ||
		len(c.Via) != 2 || c.Via[0] != "express" || c.Via[1] != "debug" {
		t.Errorf("ms: got %+v, want transitive via [express debug]", c)
	}
	// removed packages classify against the OLD graph
	if c := find(fd, "gone"); c == nil || c.Origin != "transitive" ||
		len(c.Via) != 1 || c.Via[0] != "express" {
		t.Errorf("gone: got %+v, want transitive via [express] (old graph)", c)
	}
}

func TestOriginHeuristicRoots(t *testing.T) {
	// No recorded roots (yarn classic): packages nothing depends on
	// count as the direct set.
	oldF := mk(map[string][]string{"top": {"1.0.0"}, "leaf": {"1.0.0"}})
	newF := mk(map[string][]string{"top": {"1.1.0"}, "leaf": {"1.2.0"}})
	newF.Deps = map[string][]string{"top": {"leaf"}}

	fd := Diff(oldF, newF)
	if c := find(fd, "top"); c == nil || c.Origin != "direct" {
		t.Errorf("top: got %+v, want direct (no in-edges)", c)
	}
	if c := find(fd, "leaf"); c == nil || c.Origin != "transitive" || len(c.Via) != 1 {
		t.Errorf("leaf: got %+v, want transitive via [top]", c)
	}
}

func TestOriginUnknownWithoutGraph(t *testing.T) {
	oldF := mk(map[string][]string{"a": {"1.0.0"}})
	newF := mk(map[string][]string{"a": {"2.0.0"}})
	fd := Diff(oldF, newF)
	if c := find(fd, "a"); c == nil || c.Origin != "" {
		t.Errorf("a: got %+v, want empty origin when format has no graph", c)
	}
}

func TestOriginGoModNoEdges(t *testing.T) {
	// go.mod: roots known, no edges — non-roots are transitive, no via.
	oldF := mk(map[string][]string{"golang.org/x/sys": {"0.19.0"}})
	newF := mk(map[string][]string{"golang.org/x/sys": {"0.20.0"}})
	newF.RootsKnown = true
	newF.Roots = []string{"github.com/direct/dep"}
	fd := Diff(oldF, newF)
	if c := find(fd, "golang.org/x/sys"); c == nil || c.Origin != "transitive" || len(c.Via) != 0 {
		t.Errorf("x/sys: got %+v, want transitive with no via", c)
	}
}

func TestFilter(t *testing.T) {
	oldF := mk(map[string][]string{
		"express": {"4.17.0"}, "debug": {"2.6.8"}, "ms": {"1.0.0"},
		"@babel/core": {"7.0.0"}, "golang.org/x/sys": {"0.1.0"},
	})
	newF := mk(map[string][]string{
		"express": {"4.17.1"}, "debug": {"2.6.9"}, "ms": {"2.0.0"},
		"@babel/core": {"7.1.0"}, "golang.org/x/sys": {"0.2.0"},
	})
	newF.RootsKnown = true
	newF.Roots = []string{"express", "@babel/core", "golang.org/x/sys"}
	newF.Deps = map[string][]string{"express": {"debug"}, "debug": {"ms"}}
	diffs := []FileDiff{Diff(oldF, newF)}

	names := func(out []FileDiff) []string {
		var ns []string
		for _, fd := range out {
			for _, c := range fd.Changes {
				ns = append(ns, c.Name)
			}
		}
		sort.Strings(ns)
		return ns
	}

	// exact name, case-insensitive
	if got := names(Filter(diffs, "EXPRESS")); !reflect.DeepEqual(got, []string{"debug", "express", "ms"}) {
		t.Errorf("EXPRESS: via-chain matches missing, got %v", got)
	}
	// filtering on a transitive dep shows only it (nothing is via ms)
	if got := names(Filter(diffs, "ms")); !reflect.DeepEqual(got, []string{"ms"}) {
		t.Errorf("ms: got %v", got)
	}
	// glob crosses '/' and matches scoped/module names
	if got := names(Filter(diffs, "@babel/*")); !reflect.DeepEqual(got, []string{"@babel/core"}) {
		t.Errorf("@babel/*: got %v", got)
	}
	if got := names(Filter(diffs, "*sys*")); !reflect.DeepEqual(got, []string{"golang.org/x/sys"}) {
		t.Errorf("*sys*: got %v", got)
	}
	// comma list, whitespace tolerated
	if got := names(Filter(diffs, " ms , @babel/core ")); !reflect.DeepEqual(got, []string{"@babel/core", "ms"}) {
		t.Errorf("comma list: got %v", got)
	}
	// no match -> empty (file dropped entirely)
	if got := Filter(diffs, "nope"); len(got) != 0 {
		t.Errorf("nope: got %v", got)
	}
	// empty / blank patterns -> unchanged
	if got := Filter(diffs, " , "); len(names(got)) != 5 {
		t.Errorf("blank patterns should not filter, got %v", names(got))
	}
	// original diffs must not be mutated by filtering
	if len(diffs[0].Changes) != 5 {
		t.Errorf("Filter mutated input: %d changes left", len(diffs[0].Changes))
	}
	// '?' single char, no regex metacharacter leakage
	if got := names(Filter(diffs, "m?")); !reflect.DeepEqual(got, []string{"ms"}) {
		t.Errorf("m?: got %v", got)
	}
	if got := Filter(diffs, "m."); len(got) != 0 {
		t.Errorf("'.' must be literal, got %v", names(got))
	}
}

func TestMaxDeltaMultiVersion(t *testing.T) {
	cases := []struct {
		o, n []string
		want vers.Level
	}{
		{[]string{"10.1.0", "11.3.5"}, []string{"10.1.0", "11.3.6"}, vers.Patch},
		{[]string{"1.0.0", "5.0.0"}, []string{"1.0.1", "5.1.0"}, vers.Minor},
		{[]string{"1.0.0"}, []string{"1.0.0", "2.0.0"}, vers.Major},
		{[]string{"1.0.0", "2.0.0"}, []string{"2.0.0"}, vers.Major},
		{[]string{"3.1.0", "4.0.0"}, []string{"3.2.0", "4.0.0"}, vers.Minor},
	}
	for _, c := range cases {
		if got := maxDelta(c.o, c.n); got != c.want {
			t.Errorf("maxDelta(%v, %v) = %v, want %v", c.o, c.n, got, c.want)
		}
	}
}
