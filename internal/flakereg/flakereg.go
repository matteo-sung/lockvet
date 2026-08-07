// Package flakereg explains Nix flake.lock changes from what the lockfile
// already records — fully offline, zero requests:
//
//   - ages and the ⏱ fresh flag come from the pinned revision's own
//     commit timestamp (flake.lock's lastModified, which the parser
//     embeds in the "<date>.<shortrev>" version it synthesizes);
//   - rev...rev compare links come from the locked repository attrs
//     (github/gitlab/git URLs), written verbatim — commit revisions
//     address themselves, so no tag verification is needed.
//
// The narHash integrity check (same revision, different tree = REPINNED)
// and the re-pointed-repository surface live in the generic pins
// machinery (internal/diffx); this layer only adds what needs the version
// string decoded.
//
// Because everything is local, it runs even with -offline/-no-meta, in
// the browser build, and never produces warnings.
package flakereg

import (
	"strings"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/taglink"
)

// Now is stubbed in tests.
var Now = time.Now

// Annotate fills ages and compare links on Nix flake input changes.
// freshDays mirrors the -fresh-days flag.
func Annotate(diffs []diffx.FileDiff, freshDays int) {
	now := Now().UTC()
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "Nix" || len(c.New) == 0 {
				continue
			}
			if t, ok := commitDate(c.New[0]); ok && c.PublishedAt == "" {
				c.PublishedAt = t.Format(time.RFC3339)
				if age := int(now.Sub(t).Hours() / 24); age >= 0 {
					c.AgeDays = age
					c.Fresh = freshDays > 0 && now.Sub(t) < time.Duration(freshDays)*24*time.Hour
				}
			}
			if c.SourceRepo == "" || c.CompareURL != "" ||
				len(c.Old) != 1 || len(c.New) != 1 {
				continue
			}
			oldRev, newRev := shortRev(c.Old[0]), shortRev(c.New[0])
			if oldRev == "" || newRev == "" || oldRev == newRev {
				continue
			}
			c.CompareURL = taglink.CompareRevsURL(c.SourceRepo, oldRev, newRev)
		}
	}
}

// commitDate decodes the "<date>.<shortrev>" (or bare "<date>") version
// the flake.lock parser synthesizes back into the pinned commit's day.
func commitDate(ver string) (time.Time, bool) {
	d := ver
	if i := strings.IndexByte(d, '.'); i >= 0 {
		d = d[:i]
	}
	t, err := time.Parse("2006-01-02", d)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// shortRev extracts the abbreviated commit revision from a synthesized
// flake version ("2026-08-01.abc12def" → "abc12def"). Versions whose id
// came from a narHash (no revision recorded) are rejected by the hex
// check — base64 is not lowercase hex.
func shortRev(ver string) string {
	i := strings.LastIndexByte(ver, '.')
	if i < 0 || i+1 >= len(ver) {
		return ""
	}
	rev := ver[i+1:]
	if len(rev) < 7 {
		return ""
	}
	for k := 0; k < len(rev); k++ {
		c := rev[k]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	return rev
}
