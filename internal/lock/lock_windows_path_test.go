package lock

import "testing"

// Windows callers hand ByBasename OS paths with backslash separators
// (`lockvet diff C:\tmp\Cargo.lock.orig C:\tmp\Cargo.lock`); forge and git
// paths always use forward slashes.
func TestByBasenameWindowsPaths(t *testing.T) {
	cases := map[string]bool{
		`C:\Users\me\project\Cargo.lock`:         true,
		`C:\Users\me\project\requirements.txt`:   true,
		`C:\Temp\x\package-lock.json`:            true,
		`..\locks\pnpm-lock.yaml`:                true,
		`C:\weird\audio.pixi.lock`:               true,
		`C:\Users\me\project\not-a-lockfile.txt`: false,
		"plain-forward/slash/go.mod":             true,
		"mixed\\sep/deep\\Gemfile.lock":          true,
	}
	for p, want := range cases {
		if got := ByBasename(p) != nil; got != want {
			t.Errorf("ByBasename(%q) found=%v, want %v", p, got, want)
		}
	}
}
