package vers

import "testing"

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.2.3", "1.2.3", 0},
		{"v1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.10", -1},
		{"1.2", "1.2.0", 0},
		{"1.2.3-alpha", "1.2.3", -1},
		{"1.2.3", "1.2.3.post1", -1},
		{"0.20220101120000-abcdef123456", "0.20230101120000-abcdef123456", -1}, // go pseudo
		{"1.0.0+build5", "1.0.0", 0},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestDelta(t *testing.T) {
	cases := []struct {
		a, b string
		want Level
	}{
		{"1.2.3", "2.0.0", Major},
		{"1.2.3", "1.3.0", Minor},
		{"1.2.3", "1.2.4", Patch},
		{"1.2.3", "1.2.3", None},
		{"4.17.20", "4.17.21", Patch},
		{"1.2.3-rc1", "1.2.3", Patch},
		{"1.2.3.4", "1.2.3.5", Patch},
		{"weird", "1.0.0", Unknown},
	}
	for _, c := range cases {
		if got := Delta(c.a, c.b); got != c.want {
			t.Errorf("Delta(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestCompareDistroSuffixes(t *testing.T) {
	up := [][2]string{
		{"1.36.1-r7", "1.36.1-r20"},          // apk revision, numeric
		{"1.2.4-r3", "1.2.4_git20230717-r5"}, // apk _git snapshot is post-release
		{"2.9_alpha1", "2.9"},                // apk _alpha is pre-release
		{"1.0.0-alpha2", "1.0.0-alpha10"},    // numeric-aware alnum compare
		{"1.0.0-rc9", "1.0.0-rc10"},          // ditto
		{"1.0.0-pre1", "1.0.0"},              // pre* is a pre-release, not post
		{"7.88.1-10", "7.88.1-10+deb12u5"},   // build metadata ignored -> equal-ish; not a downgrade
	}
	for _, c := range up {
		if Compare(c[0], c[1]) > 0 {
			t.Errorf("Compare(%q, %q) > 0, want <= 0", c[0], c[1])
		}
	}
	if Compare("1.36.1-r20", "1.36.1-r7") <= 0 {
		t.Error("reverse direction wrong")
	}
	if d := Delta("1.36.1-r7", "1.36.1-r20"); d != Patch {
		t.Errorf("Delta r7->r20 = %v, want Patch", d)
	}
	if d := Delta("1.2.4-r3", "1.2.4_git20230717-r5"); d != Patch {
		t.Errorf("Delta _git = %v, want Patch", d)
	}
}

func TestCompareDebianVersions(t *testing.T) {
	up := [][2]string{
		{"1:3.8-4", "1:3.10-4"},        // epoch present, numeric compare inside
		{"3.8-4", "1:1.0-1"},           // epoch beats everything (missing = 0)
		{"1.65.2", "1.69~deb13u1"},     // ~ = pre-release of 1.69, still > 1.65.2
		{"1.69~deb13u1", "1.69"},       // ~ sorts before the plain version
		{"5.2.15-2+b2", "5.2.37-2+b9"}, // +bN build metadata ignored
		{"2.6.1", "3.0.3"},
	}
	for _, c := range up {
		if Compare(c[0], c[1]) >= 0 {
			t.Errorf("Compare(%q, %q) >= 0, want < 0", c[0], c[1])
		}
	}
	if d := Delta("1:3.8-4", "2:1.0-1"); d != Major {
		t.Errorf("epoch bump Delta = %v, want Major", d)
	}
}
