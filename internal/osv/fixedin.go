package osv

import (
	"strings"

	"github.com/matteo-sung/lockvet/internal/actreg"
	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/lock"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// fixTarget carries what fixedIn needs to evaluate a change's pinned
// versions against an advisory's ranges.
type fixTarget struct {
	name, eco string
	versions  []string
	vPrefix   bool // pins carry a leading "v" (Go, some Actions tags)
}

// fixTargetFor extracts the new-side versions an advisory verdict applies
// to. For GitHub Actions the raw pins (SHAs, floating majors) are resolved
// through ResolvedRefs first; when any pin stays unresolved, no fix claim
// is made for the whole change.
func fixTargetFor(c *diffx.Change) fixTarget {
	t := fixTarget{name: c.Name, eco: c.Ecosystem}
	if len(c.New) == 0 {
		return t
	}
	if lock.Ecosystem(c.Ecosystem) == lock.GitHubActions {
		for _, raw := range c.New {
			eff := actreg.Effective(c, raw)
			if !actreg.VersionLike(eff) || !strings.Contains(eff, ".") {
				return fixTarget{name: c.Name, eco: c.Ecosystem} // SHA, branch, or floating major: no claim
			}
			t.vPrefix = t.vPrefix || strings.HasPrefix(eff, "v")
			t.versions = append(t.versions, strings.TrimPrefix(eff, "v"))
		}
		return t
	}
	t.versions = c.New
	t.vPrefix = strings.HasPrefix(c.New[0], "v")
	return t
}

// fixedIn returns the smallest version that clears the advisory for every
// version in t, read from the advisory's SEMVER/ECOSYSTEM ranges. Empty
// when any pinned version has no released fix, or the ranges don't say.
func fixedIn(d vulnDetail, t fixTarget) string {
	if len(t.versions) == 0 || len(d.affected) == 0 {
		return ""
	}
	ecoBase := ecoRoot(t.eco)
	worst := ""
	for _, v := range t.versions {
		best := "" // smallest fix clearing this one version
		for _, a := range d.affected {
			if !namesEqual(a.Package.Name, t.name, ecoBase) {
				continue
			}
			if strings.Contains(t.eco, ":") {
				// Distro ecosystems (Alpine:v3.19): one advisory carries an
				// entry per release, all sharing the root — only the exact
				// release's ranges apply.
				if !strings.EqualFold(a.Package.Ecosystem, t.eco) {
					continue
				}
			} else if !strings.EqualFold(ecoRoot(a.Package.Ecosystem), ecoBase) {
				continue
			}
			var fixes []string // all fixed events, for the versions-list fallback
			inAnyRange := false
			for _, r := range a.Ranges {
				typ := strings.ToUpper(r.Type)
				if typ != "SEMVER" && typ != "ECOSYSTEM" {
					continue
				}
				in := false
				for _, ev := range r.Events {
					if iv, ok := ev["introduced"]; ok {
						in = iv == "0" || vers.Compare(v, iv) >= 0
						continue
					}
					if fv, ok := ev["fixed"]; ok {
						fixes = append(fixes, fv)
						if in && vers.Compare(v, fv) < 0 {
							if best == "" || vers.Compare(fv, best) < 0 {
								best = fv
							}
							inAnyRange = true
						}
						in = false
						continue
					}
					if lv, ok := ev["last_affected"]; ok {
						if in && vers.Compare(v, lv) <= 0 {
							inAnyRange = true // affected, and this line has no fix
						}
						in = false
					}
				}
				if in { // open-ended range: affected, no fix released
					inAnyRange = true
				}
			}
			// Advisory matched via its explicit versions list (or a range
			// shape we didn't walk): the smallest fixed event above v is
			// still the honest answer.
			if !inAnyRange && best == "" {
				for _, av := range a.Versions {
					if vers.Compare(av, v) == 0 {
						for _, fv := range fixes {
							if vers.Compare(v, fv) < 0 && (best == "" || vers.Compare(fv, best) < 0) {
								best = fv
							}
						}
						break
					}
				}
			}
			if inAnyRange && best == "" {
				return "" // affected by a line with no released fix
			}
		}
		if best == "" {
			return "" // couldn't establish a fix for this pin: no claim
		}
		if worst == "" || vers.Compare(best, worst) > 0 {
			worst = best
		}
	}
	if worst != "" && t.vPrefix && !strings.HasPrefix(worst, "v") {
		worst = "v" + worst
	}
	return worst
}

// ecoRoot strips a distro/release suffix: "Alpine:v3.19" -> "Alpine".
func ecoRoot(eco string) string {
	if i := strings.IndexByte(eco, ':'); i >= 0 {
		// Maven coordinates never appear in ecosystem strings, only names.
		return eco[:i]
	}
	return eco
}

// namesEqual compares package names the way the ecosystem does: case-
// insensitively, and with PyPI's -/_/. equivalence.
func namesEqual(a, b, eco string) bool {
	if strings.EqualFold(a, b) {
		return true
	}
	if strings.EqualFold(eco, "PyPI") {
		norm := func(s string) string {
			s = strings.ToLower(s)
			s = strings.ReplaceAll(s, "_", "-")
			return strings.ReplaceAll(s, ".", "-")
		}
		return norm(a) == norm(b)
	}
	return false
}
