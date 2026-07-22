package diffx

import (
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
