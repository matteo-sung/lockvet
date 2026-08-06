// Package goreg asks the Go module proxy what it knows about the
// modules a diff introduces:
//
//   - Retractions: the retract directives in a module's latest go.mod
//     are how Go authors say "do not use these versions" — often after
//     a broken or compromised release. deps.dev relays the retracted
//     bit but drops the author's rationale (usually the issue link that
//     explains WHY); the proxy has the go.mod itself, so a bump onto a
//     retracted version shows the reason, and versions deps.dev has not
//     re-indexed yet still get flagged.
//   - Module deprecations: the "// Deprecated:" paragraph above the
//     module directive, for modules deps.dev has not caught up with.
//   - Release ages: @v/{version}.info carries the authoritative publish
//     time, so ages and the ⏱ cooldown flag work even for tags cut
//     minutes ago. Pseudo-versions embed their commit time in the
//     version string itself and cost no request at all.
//   - The proxy re-verifies Unlisted flags set by the deps.dev layer,
//     which can lag the proxy by days: a version the proxy serves is
//     not unlisted. The proxy never removes versions once cached, so a
//     version it lacks while siblings exist keeps the flag.
//
// Two anonymous GETs per changed module (@latest + that version's
// go.mod — the same endpoints `go get` itself uses, behind Google's
// CDN), plus per-version .info lookups only when deps.dev had no
// answer. The proxy sends Access-Control-Allow-Origin: *, so the
// browser (wasm) build runs the identical code path. GOPROXY is
// honoured when it points at a single proxy URL; GOPROXY=off/direct
// skips the check.
package goreg

import (
	"encoding/json"
	"fmt"
	"github.com/matteo-sung/lockvet/internal/hcache"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/diffx"
	"github.com/matteo-sung/lockvet/internal/vers"
)

// ProxyURL is the module proxy base; a var so tests can fake it. An
// explicit single-URL GOPROXY overrides it at Annotate time.
var ProxyURL = "https://proxy.golang.org"

// maxInfoLookups caps per-module @v/{version}.info requests (unlisted
// verification + age backfill).
const maxInfoLookups = 4

var client = hcache.Client(20 * time.Second)

// Now is a var so tests can pin the clock.
var Now = time.Now

const userAgent = "lockvet (+https://github.com/matteo-sung/lockvet)"

// retraction is one retract directive: a single version (lo == hi) or a
// closed interval, with the author's rationale comment when present.
type retraction struct {
	lo, hi    string
	rationale string
}

// modmeta is what the proxy knows about one module: its latest go.mod's
// retractions and deprecation notice (only when that go.mod really
// belongs to this module path — repos renamed with a redirect serve the
// NEW module's file, whose directives must not be applied to the old
// path).
type modmeta struct {
	deprecated  string // "// Deprecated:" text, "" if none
	retractions []retraction
	pathOK      bool // latest go.mod's module directive matches
}

// Annotate fills Go module proxy signals on the diffs; see the package
// comment for what it flags. Call it AFTER depsdev.Annotate (it
// re-verifies deps.dev-based Unlisted flags and backfills what deps.dev
// lacks). freshDays mirrors the -fresh-days flag for the ⏱ backfill.
// Best-effort: network errors return an error but leave diffs usable.
func Annotate(diffs []diffx.FileDiff, freshDays int) error {
	base, ok := proxyBase()
	if !ok {
		return nil // GOPROXY=off or direct: respect it
	}

	type slot struct{ fd, ci int }
	byMod := map[string][]slot{}
	for i := range diffs {
		for j := range diffs[i].Changes {
			c := &diffs[i].Changes[j]
			if c.Ecosystem != "Go" || c.NonRegistry {
				continue
			}
			if len(c.New) == 0 && !c.Unlisted {
				continue // removals: nothing incoming to vet
			}
			byMod[c.Name] = append(byMod[c.Name], slot{i, j})
		}
	}
	if len(byMod) == 0 {
		return nil
	}

	// Free pass first: pseudo-version publish times are embedded in the
	// version string — no request needed.
	for _, slots := range byMod {
		for _, s := range slots {
			backfillPseudoAge(&diffs[s.fd].Changes[s.ci], freshDays)
		}
	}

	// Fetch each module's latest go.mod (retractions + deprecation),
	// but only for modules with incoming tagged versions — retract
	// directives cannot hit pseudo-version-only changes any earlier
	// than deps.dev already does, and pseudo-only modules are often
	// forks the proxy never saw.
	need := make([]string, 0, len(byMod))
	for name, slots := range byMod {
		for _, s := range slots {
			c := &diffs[s.fd].Changes[s.ci]
			if hasTaggedIncoming(c) || c.Unlisted {
				need = append(need, name)
				break
			}
		}
	}

	metas := make(map[string]*modmeta, len(need))
	var mu sync.Mutex
	var firstErr error
	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	for _, name := range need {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			mu.Lock()
			stop := firstErr != nil
			mu.Unlock()
			if stop {
				return
			}
			m, err := fetchMeta(base, name)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			if m != nil {
				metas[name] = m
			}
		}(name)
	}
	wg.Wait()
	if firstErr != nil {
		return firstErr
	}

	for name, slots := range byMod {
		m := metas[name] // may be nil: module unknown to the proxy
		for _, s := range slots {
			c := &diffs[s.fd].Changes[s.ci]
			budget := maxInfoLookups

			// Unlisted verification: a version the proxy serves is not
			// unlisted; the proxy never forgets versions, so absence
			// while the module itself resolves keeps the flag.
			if c.Unlisted && m != nil {
				var still []string
				for _, v := range c.UnlistedVersions {
					if _, ok := fetchInfo(base, name, v, &budget); ok {
						continue // the proxy has it: deps.dev lag
					}
					still = append(still, v)
				}
				c.UnlistedVersions = still
				c.Unlisted = len(still) > 0
			}

			if len(c.New) == 0 || m == nil {
				continue
			}

			// Retractions and module deprecation for incoming versions.
			if m.pathOK {
				annotateRetract(c, m)
			}

			// Age backfill: deps.dev lags brand-new tags, which are
			// exactly what the ⏱ cooldown flag exists for.
			if c.PublishedAt == "" {
				latest := ""
				for _, v := range c.New {
					if isPseudo(v) {
						continue
					}
					if t, ok := fetchInfo(base, name, v, &budget); ok && t > latest {
						latest = t
					}
				}
				setAge(c, latest, freshDays)
			}
		}
	}
	return nil
}

// annotateRetract flags incoming versions covered by a retract
// directive, and modules deprecated upstream. The author's rationale is
// more specific than deps.dev's bare "deprecated" bit, so a non-empty
// rationale wins; otherwise an existing reason is left alone.
func annotateRetract(c *diffx.Change, m *modmeta) {
	old := map[string]bool{}
	for _, v := range c.Old {
		old[v] = true
	}
	for _, v := range c.New {
		if old[v] {
			continue
		}
		for _, r := range m.retractions {
			if !inRange(v, r) {
				continue
			}
			c.Deprecated = true
			// deps.dev relays retractions as "Version retracted: …" when
			// it has caught up; keep its text then. Otherwise ours wins —
			// version-specific rationale beats a bare or module-level
			// reason.
			already := strings.Contains(strings.ToLower(c.DeprecatedReason), "retract")
			switch {
			case already:
			case r.rationale != "":
				c.DeprecatedReason = "retracted: " + r.rationale
			case c.DeprecatedReason == "":
				c.DeprecatedReason = "retracted by the module author"
			}
			break
		}
	}
	if m.deprecated != "" {
		c.Deprecated = true
		if c.DeprecatedReason == "" {
			c.DeprecatedReason = "module deprecated: " + m.deprecated
		}
	}
}

// inRange reports whether version v (lockfile form, no "v" prefix) is
// covered by a retraction. Build metadata (+incompatible) is ignored in
// comparison, as Go's own semver rules require.
func inRange(v string, r retraction) bool {
	x := stripMeta(v)
	return vers.Compare(x, stripMeta(r.lo)) >= 0 && vers.Compare(x, stripMeta(r.hi)) <= 0
}

func stripMeta(v string) string {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	return v
}

// backfillPseudoAge parses the commit timestamp a pseudo-version embeds
// (v0.0.0-20240101120000-abcdef123456) — authoritative and free.
func backfillPseudoAge(c *diffx.Change, freshDays int) {
	if c.PublishedAt != "" || len(c.New) == 0 {
		return
	}
	latest := ""
	for _, v := range c.New {
		ts := pseudoTime(v)
		if ts > latest {
			latest = ts
		}
	}
	setAge(c, latest, freshDays)
}

// pseudoTime extracts the RFC3339 UTC time from a pseudo-version, or "".
func pseudoTime(v string) string {
	if !isPseudo(v) {
		return ""
	}
	parts := strings.Split(v, "-")
	stamp := parts[len(parts)-2]
	t, err := time.Parse("20060102150405", stamp)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func isPseudo(v string) bool {
	parts := strings.Split(v, "-")
	if len(parts) < 3 {
		return false
	}
	stamp, sha := parts[len(parts)-2], parts[len(parts)-1]
	if len(stamp) != 14 || len(sha) != 12 {
		return false
	}
	for _, r := range stamp {
		if r < '0' || r > '9' {
			return false
		}
	}
	for _, r := range sha {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func setAge(c *diffx.Change, latest string, freshDays int) {
	if latest == "" {
		return
	}
	t, err := time.Parse(time.RFC3339, latest)
	if err != nil {
		return
	}
	c.PublishedAt = t.UTC().Format(time.RFC3339)
	if age := int(Now().Sub(t).Hours() / 24); age >= 0 {
		c.AgeDays = age
		c.Fresh = freshDays > 0 && Now().Sub(t) < time.Duration(freshDays)*24*time.Hour
	}
}

func hasTaggedIncoming(c *diffx.Change) bool {
	for _, v := range c.New {
		if !isPseudo(v) {
			return true
		}
	}
	return false
}

// fetchMeta resolves a module's latest version and parses its go.mod.
// nil, nil means the proxy does not know the module (private, or
// replaced) — every signal stays quiet.
func fetchMeta(base, name string) (*modmeta, error) {
	body, status, err := get(base + "/" + escape(name) + "/@latest")
	if err != nil {
		return nil, fmt.Errorf("Go module proxy unreachable: %w", err)
	}
	if status == 404 || status == 410 {
		return nil, nil
	}
	if status != 200 {
		return nil, fmt.Errorf("Go module proxy returned HTTP %d", status)
	}
	var info struct{ Version string }
	if err := json.Unmarshal(body, &info); err != nil || info.Version == "" {
		return nil, nil
	}
	body, status, err = get(base + "/" + escape(name) + "/@v/" + escape(info.Version) + ".mod")
	if err != nil {
		return nil, fmt.Errorf("Go module proxy unreachable: %w", err)
	}
	if status != 200 {
		return nil, nil
	}
	m := parseMod(string(body))
	m.pathOK = m.pathOK && modPath(string(body)) == name
	return m, nil
}

// fetchInfo asks for one version's publish time; ok=false means the
// proxy lacks the version (or the budget ran out — callers then leave
// existing flags untouched, which errs on keeping deps.dev's answer).
func fetchInfo(base, name, version string, budget *int) (rfc3339 string, ok bool) {
	if *budget <= 0 {
		return "", false
	}
	*budget--
	v := version
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	body, status, err := get(base + "/" + escape(name) + "/@v/" + escape(v) + ".info")
	if err != nil || status != 200 {
		return "", false
	}
	var info struct{ Time string }
	if err := json.Unmarshal(body, &info); err != nil {
		return "", true // version exists; time unknown
	}
	return info.Time, true
}

func get(url string) (body []byte, status int, err error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, nil // treat as best-effort
	}
	return body, resp.StatusCode, nil
}

// escape applies the module proxy's case encoding: uppercase letters
// become "!" + lowercase (github.com/BurntSushi → github.com/!burnt!sushi).
func escape(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + ('a' - 'A'))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// proxyBase resolves the proxy to talk to: a single-URL GOPROXY wins,
// GOPROXY=off/direct disables the check, anything else (fallback lists
// with unknown semantics included) uses the default public proxy.
func proxyBase() (string, bool) {
	env := strings.TrimSpace(os.Getenv("GOPROXY"))
	if env == "" {
		return ProxyURL, true
	}
	first := env
	if i := strings.IndexAny(env, ",|"); i >= 0 {
		first = strings.TrimSpace(env[:i])
	}
	switch first {
	case "off", "direct":
		return "", false
	}
	if strings.HasPrefix(first, "http://") || strings.HasPrefix(first, "https://") {
		return strings.TrimSuffix(first, "/"), true
	}
	return ProxyURL, true
}

// ---- go.mod parsing ----

// modPath returns the module directive's path.
func modPath(src string) string {
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "module"); ok {
			rest = strings.TrimSpace(strings.TrimSuffix(rest, "\r"))
			rest = strings.Trim(rest, `"`)
			if rest != "" && !strings.HasPrefix(rest, "(") {
				return rest
			}
		}
	}
	return ""
}

// parseMod extracts retract directives (with rationale comments) and
// the "// Deprecated:" paragraph above the module directive.
func parseMod(src string) *modmeta {
	m := &modmeta{pathOK: true}
	var pending []string // contiguous comment block above the current line
	inRetract := false
	blockComment := "" // comment above "retract (" — fallback rationale
	groupComment := "" // comment inside the block: applies to the items
	// below it until a blank line, exactly how gofmt lays out grouped
	// retractions (one comment, several versions).
	for _, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))

		if strings.HasPrefix(line, "//") {
			pending = append(pending, strings.TrimSpace(strings.TrimPrefix(line, "//")))
			continue
		}
		if line == "" {
			pending = nil
			groupComment = ""
			continue
		}

		// Inline comment: rationale for this very directive.
		inline := ""
		if i := strings.Index(line, "//"); i >= 0 {
			inline = strings.TrimSpace(line[i+2:])
			line = strings.TrimSpace(line[:i])
		}

		switch {
		case strings.HasPrefix(line, "module ") || line == "module":
			if d := deprecatedText(pending); d != "" {
				m.deprecated = d
			}
		case line == "retract (":
			inRetract = true
			blockComment = firstLine(strings.Join(pending, "\n"))
			groupComment = ""
		case inRetract && line == ")":
			inRetract = false
			blockComment, groupComment = "", ""
		case strings.HasPrefix(line, "retract "):
			m.add(strings.TrimSpace(strings.TrimPrefix(line, "retract")),
				inline, strings.Join(pending, " "), "")
		case inRetract:
			if len(pending) > 0 {
				groupComment = strings.Join(pending, " ")
			}
			m.add(line, inline, groupComment, blockComment)
		}
		pending = nil
	}
	return m
}

// add records one retract item: "v1.2.3" or "[v1.0.0, v1.2.0]".
// Rationale preference: inline comment, then the comment block directly
// above the item, then the comment above the whole retract block.
func (m *modmeta) add(item, inline, above, block string) {
	rationale := inline
	if rationale == "" {
		rationale = strings.TrimSpace(above)
	}
	if rationale == "" {
		rationale = block
	}
	rationale = firstLine(rationale)
	item = strings.TrimSpace(item)
	if strings.HasPrefix(item, "[") {
		item = strings.Trim(item, "[]")
		lo, hi, ok := strings.Cut(item, ",")
		if !ok {
			return
		}
		m.retractions = append(m.retractions, retraction{
			lo: strings.TrimSpace(lo), hi: strings.TrimSpace(hi), rationale: rationale})
		return
	}
	if !strings.HasPrefix(item, "v") {
		return
	}
	m.retractions = append(m.retractions, retraction{lo: item, hi: item, rationale: rationale})
}

// deprecatedText finds the "Deprecated:" paragraph in a comment block.
func deprecatedText(block []string) string {
	for _, l := range block {
		if rest, ok := strings.CutPrefix(l, "Deprecated:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return s
}
