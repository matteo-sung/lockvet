package osv

// Local OSV databases: the per-ecosystem all.zip files OSV.dev exports to
// its public GCS bucket, downloaded once and queried on disk. With
// -osv-db DIR the vulnerability check needs no network at query time, so
// -offline (air-gapped CI) still gets real advisories — the answer to
// "how do I run this where api.osv.dev is unreachable".
//
// Layout under DIR, one directory per ecosystem (":" and " " become "_",
// so Windows paths work):
//
//	DIR/npm/all.zip            the zip exactly as OSV publishes it
//	DIR/npm/index.json.gz      lockvet's name -> advisory-ID index
//
// The index is (re)built whenever the zip changes (ETag) or is missing —
// so a directory of hand-copied all.zip files works offline too; lockvet
// indexes them locally on first use. Records marked withdrawn are
// excluded at index time, matching what api.osv.dev returns for queries.
//
// Range evaluation happens client-side with the same walk the GitHub
// Actions path and the fixed-in computation already use: SEMVER and
// ECOSYSTEM events (introduced / fixed / last_affected, open-ended
// ranges), plus the record's explicit versions list.

import (
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/matteo-sung/lockvet/internal/vers"
)

// gcsBase is where OSV publishes per-ecosystem exports; a var so tests
// can point it at a local server.
var gcsBase = "https://osv-vulnerabilities.storage.googleapis.com/"

// UseLocal routes all OSV queries to zip databases under dir. When
// download is true, missing or stale ecosystems are fetched from OSV's
// export first (conditional GET, so an unchanged database costs one 304);
// when false (-offline) the databases must already be there.
func UseLocal(dir string, download bool) {
	db = &localBackend{dir: dir, download: download}
}

type localBackend struct {
	dir      string
	download bool

	mu      sync.Mutex
	ecos    map[string]*ecoDB
	records map[string]vulnDetail // advisory ID -> decoded record
}

type ecoDB struct {
	names map[string][]string // normalized package name -> advisory IDs
	byID  map[string]*zip.File
	err   error
}

func (b *localBackend) batch(qs []query) ([]batchResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]batchResult, len(qs))
	for i, q := range qs {
		eco := q.Package.Ecosystem
		ed := b.ensure(eco)
		if ed.err != nil {
			return nil, ed.err
		}
		for _, id := range ed.names[normName(q.Package.Name, eco)] {
			rec, err := b.record(ed, id)
			if err != nil {
				continue
			}
			if q.Version != "" && !affectsVersion(rec.affected, q.Package.Name, eco, q.Version) {
				continue
			}
			out[i].Vulns = append(out[i].Vulns, struct {
				ID string `json:"id"`
			}{id})
		}
	}
	return out, nil
}

func (b *localBackend) details(ids []string) map[string]vulnDetail {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]vulnDetail{}
	for _, id := range ids {
		if v, ok := b.records[id]; ok {
			out[id] = v
		}
	}
	return out
}

// record decodes advisory id from the ecosystem's zip, memoized.
func (b *localBackend) record(ed *ecoDB, id string) (vulnDetail, error) {
	if v, ok := b.records[id]; ok {
		return v, nil
	}
	zf, ok := ed.byID[id]
	if !ok {
		return vulnDetail{}, fmt.Errorf("advisory %s not in local database", id)
	}
	r, err := zf.Open()
	if err != nil {
		return vulnDetail{}, err
	}
	defer r.Close()
	v, err := decodeVulnDoc(r)
	if err != nil {
		return vulnDetail{}, err
	}
	if b.records == nil {
		b.records = map[string]vulnDetail{}
	}
	b.records[id] = v
	return v, nil
}

// ensure opens (downloading and indexing as needed) the database for eco.
func (b *localBackend) ensure(eco string) *ecoDB {
	if ed, ok := b.ecos[eco]; ok {
		return ed
	}
	ed := &ecoDB{}
	if b.ecos == nil {
		b.ecos = map[string]*ecoDB{}
	}
	b.ecos[eco] = ed

	dir := filepath.Join(b.dir, sanitizeEco(eco))
	zipPath := filepath.Join(dir, "all.zip")
	idxPath := filepath.Join(dir, "index.json.gz")

	idx, idxErr := loadIndex(idxPath)

	if b.download {
		if err := b.refresh(eco, dir, zipPath, idxPath, &idx, idxErr == nil); err != nil {
			if idxErr == nil || fileExists(zipPath) {
				fmt.Fprintf(os.Stderr, "lockvet: warning: osv-db: refresh failed for %s (%v): using the existing database\n", eco, err)
			} else {
				ed.err = fmt.Errorf("osv-db: downloading %s database: %w", eco, err)
				return ed
			}
		}
		idx, idxErr = loadIndex(idxPath)
	}

	if idxErr != nil {
		if !fileExists(zipPath) {
			ed.err = fmt.Errorf("osv-db: no local OSV database for %s under %s — run once with network (without -offline) to download it", eco, b.dir)
			return ed
		}
		// Hand-copied all.zip: index it locally.
		var err error
		idx, err = buildIndex(zipPath, "")
		if err != nil {
			ed.err = fmt.Errorf("osv-db: indexing %s: %w", zipPath, err)
			return ed
		}
		if err := saveIndex(idxPath, idx); err != nil {
			fmt.Fprintf(os.Stderr, "lockvet: warning: osv-db: could not save index for %s: %v\n", eco, err)
		}
	}

	ed.names = idx.Names
	if len(idx.Names) > 0 {
		zr, err := zip.OpenReader(zipPath)
		if err != nil {
			ed.err = fmt.Errorf("osv-db: opening %s: %w", zipPath, err)
			return ed
		}
		ed.byID = map[string]*zip.File{}
		for _, f := range zr.File {
			ed.byID[strings.TrimSuffix(filepath.Base(f.Name), ".json")] = f
		}
	}
	return ed
}

// refresh conditionally re-downloads eco's zip and rebuilds the index.
// haveIdx says whether a loadable index (with an ETag) already exists.
func (b *localBackend) refresh(eco, dir, zipPath, idxPath string, idx *dbIndex, haveIdx bool) error {
	req, err := http.NewRequest("GET", gcsBase+strings.ReplaceAll(eco, " ", "%20")+"/all.zip", nil)
	if err != nil {
		return err
	}
	if haveIdx && idx.ETag != "" && fileExists(zipPath) {
		req.Header.Set("If-None-Match", idx.ETag)
	}
	resp, err := dlClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil
	case http.StatusNotFound:
		// OSV has no export for this ecosystem: an empty database is
		// exactly what the API would answer.
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		return saveIndex(idxPath, dbIndex{ETag: "none", Built: time.Now().UTC().Format(time.RFC3339), Names: map[string][]string{}})
	case http.StatusOK:
	default:
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "all-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	n, err := tmp.ReadFrom(resp.Body)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), zipPath); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "lockvet: osv-db: downloaded %s database (%.1f MB), indexing…\n", eco, float64(n)/1e6)
	newIdx, err := buildIndex(zipPath, resp.Header.Get("ETag"))
	if err != nil {
		return err
	}
	*idx = newIdx
	return saveIndex(idxPath, newIdx)
}

// dlClient fetches database zips: plain HTTP (hundreds of MB have no
// business in the response cache), generous timeout.
var dlClient = &http.Client{Timeout: 10 * time.Minute}

type dbIndex struct {
	ETag  string              `json:"etag"`
	Built string              `json:"built"`
	Names map[string][]string `json:"names"`
}

func loadIndex(path string) (dbIndex, error) {
	var idx dbIndex
	f, err := os.Open(path)
	if err != nil {
		return idx, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return idx, err
	}
	defer gz.Close()
	err = json.NewDecoder(gz).Decode(&idx)
	if err == nil && idx.Names == nil {
		idx.Names = map[string][]string{}
	}
	return idx, err
}

func saveIndex(path string, idx dbIndex) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "index-*.json.gz")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	gz := gzip.NewWriter(tmp)
	err = json.NewEncoder(gz).Encode(idx)
	if cerr := gz.Close(); err == nil {
		err = cerr
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// buildIndex walks every record in the zip and maps each affected
// package name to the advisory IDs naming it. Withdrawn records are
// dropped — the API excludes them from query results too.
func buildIndex(zipPath, etag string) (dbIndex, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return dbIndex{}, err
	}
	defer zr.Close()
	idx := dbIndex{ETag: etag, Built: time.Now().UTC().Format(time.RFC3339), Names: map[string][]string{}}
	for _, f := range zr.File {
		if !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		r, err := f.Open()
		if err != nil {
			return dbIndex{}, err
		}
		var doc struct {
			ID        string `json:"id"`
			Withdrawn string `json:"withdrawn"`
			Affected  []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
			} `json:"affected"`
		}
		err = json.NewDecoder(r).Decode(&doc)
		r.Close()
		if err != nil {
			continue // one malformed record shouldn't sink the database
		}
		if doc.Withdrawn != "" {
			continue
		}
		id := doc.ID
		if id == "" {
			id = strings.TrimSuffix(filepath.Base(f.Name), ".json")
		}
		seen := map[string]bool{}
		for _, a := range doc.Affected {
			key := normName(a.Package.Name, a.Package.Ecosystem)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			idx.Names[key] = append(idx.Names[key], id)
		}
	}
	return idx, nil
}

// normName is the index key for a package name: lower-cased, with PyPI's
// -/_/. equivalence folded the way namesEqual compares them.
func normName(name, eco string) string {
	s := strings.ToLower(name)
	if strings.EqualFold(ecoRoot(eco), "PyPI") {
		s = strings.ReplaceAll(s, "_", "-")
		s = strings.ReplaceAll(s, ".", "-")
	}
	return s
}

func sanitizeEco(eco string) string {
	return strings.NewReplacer(":", "_", " ", "_", "/", "_").Replace(eco)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// affectsVersion reports whether version v of (name, eco) falls in any of
// the record's affected entries — the client-side equivalent of an
// api.osv.dev version query: the explicit versions list, then SEMVER /
// ECOSYSTEM ranges walked event by event (open-ended ranges affect
// everything from their introduced version on).
func affectsVersion(aff []affectedEntry, name, eco, v string) bool {
	ecoBase := ecoRoot(eco)
	for _, a := range aff {
		if !namesEqual(a.Package.Name, name, ecoBase) {
			continue
		}
		if strings.Contains(eco, ":") {
			// Distro ecosystems (Alpine:v3.19): only the exact release's
			// entry applies.
			if !strings.EqualFold(a.Package.Ecosystem, eco) {
				continue
			}
		} else if !strings.EqualFold(ecoRoot(a.Package.Ecosystem), ecoBase) {
			continue
		}
		for _, av := range a.Versions {
			if av == v || vers.Compare(av, v) == 0 {
				return true
			}
		}
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
					if in && vers.Compare(v, fv) < 0 {
						return true
					}
					in = false
					continue
				}
				if lv, ok := ev["last_affected"]; ok {
					if in && vers.Compare(v, lv) <= 0 {
						return true
					}
					in = false
				}
			}
			if in {
				return true
			}
		}
	}
	return false
}
