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
