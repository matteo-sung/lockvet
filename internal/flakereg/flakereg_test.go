package flakereg

import (
	"testing"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
)

func fixedNow() time.Time {
	return time.Date(2024, 7, 10, 12, 0, 0, 0, time.UTC)
}

func TestAnnotateAgesAndLinks(t *testing.T) {
	Now = fixedNow
	defer func() { Now = time.Now }()

	diffs := []diffx.FileDiff{{Changes: []diffx.Change{
		{
			Name: "nixpkgs", Ecosystem: "Nix", Kind: diffx.Upgraded,
			Old: []string{"2024-03-09.0123abcd"}, New: []string{"2024-07-03.deadbeef"},
			SourceRepo: "https://github.com/NixOS/nixpkgs",
		},
		{
			Name: "moved", Ecosystem: "Nix", Kind: diffx.Upgraded,
			Old: []string{"2024-03-09.0123abcd"}, New: []string{"2024-07-03.deadbeef"},
			// re-pointed input: diffx left SourceRepo empty
		},
		{
			Name: "tarball", Ecosystem: "Nix", Kind: diffx.Upgraded,
			Old: []string{"QQQQWWWW"}, New: []string{"RRRRSSSS"},
			SourceRepo: "https://github.com/o/r",
		},
		{
			Name: "npmpkg", Ecosystem: "npm", Kind: diffx.Upgraded,
			Old: []string{"1.0.0"}, New: []string{"1.1.0"},
		},
	}}}
	Annotate(diffs, 30)

	c := diffs[0].Changes[0]
	if c.PublishedAt != "2024-07-03T00:00:00Z" {
		t.Errorf("PublishedAt = %q", c.PublishedAt)
	}
	if c.AgeDays != 7 {
		t.Errorf("AgeDays = %d", c.AgeDays)
	}
	if !c.Fresh {
		t.Error("want fresh inside 30-day window")
	}
	want := "https://github.com/NixOS/nixpkgs/compare/0123abcd...deadbeef"
	if c.CompareURL != want {
		t.Errorf("CompareURL = %q, want %q", c.CompareURL, want)
	}

	if got := diffs[0].Changes[1]; got.CompareURL != "" {
		t.Errorf("moved input should get no compare link, got %q", got.CompareURL)
	} else if got.PublishedAt == "" {
		t.Error("moved input should still get an age")
	}

	if got := diffs[0].Changes[2]; got.CompareURL != "" || got.PublishedAt != "" {
		t.Errorf("narHash-only ids must produce no claims, got link=%q published=%q",
			got.CompareURL, got.PublishedAt)
	}

	if got := diffs[0].Changes[3]; got.PublishedAt != "" || got.CompareURL != "" {
		t.Error("non-Nix change must be untouched")
	}
}

func TestAnnotateFreshGate(t *testing.T) {
	Now = fixedNow
	defer func() { Now = time.Now }()

	diffs := []diffx.FileDiff{{Changes: []diffx.Change{{
		Name: "nixpkgs", Ecosystem: "Nix", Kind: diffx.Upgraded,
		Old: []string{"2024-03-09.0123abcd"}, New: []string{"2024-07-03.deadbeef"},
	}}}}
	Annotate(diffs, 7)
	if c := diffs[0].Changes[0]; c.Fresh {
		t.Error("7 days + noon should be outside a 7-day window")
	}
	diffs[0].Changes[0].Fresh = false
	diffs[0].Changes[0].PublishedAt = ""
	Annotate(diffs, 0)
	if c := diffs[0].Changes[0]; c.Fresh {
		t.Error("freshDays=0 disables the flag")
	}
}

func TestShortRev(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2024-07-03.deadbeef", "deadbeef"},
		{"2024-07-03", ""},                                                             // no rev recorded
		{"QQQQWWWW", ""},                                                               // narHash-derived id, not hex
		{"2024-07-03.QQQQWWWW", ""} /* narHash id with date */, {"2024-07-03.abc", ""}, // too short
	}
	for _, c := range cases {
		if got := shortRev(c.in); got != c.want {
			t.Errorf("shortRev(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
