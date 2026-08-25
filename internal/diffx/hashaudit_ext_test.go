package diffx

// Corpus audit, skipped unless HASH_AUDIT_DIR is set: parse every file
// under that directory with its ByBasename parser and report any pin
// integrity hash splitHash cannot label — such hashes are silently
// dropped from integrity diffing, so same-version pin swaps in that
// format compare as "no change" (the build.zig.zon bug class, fixed in
// v0.6.5). Run it against a directory of real-world lockfiles whenever
// a new hash-carrying format lands:
//
//	HASH_AUDIT_DIR=/path/to/corpus go test ./internal/diffx/ -run TestHashAuditCorpus -count=1 -v
//
// TestSplitHashRecognizesEveryParserNotation (pins_test.go) is the
// always-on distillation of the last full audit.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/matteo-sung/lockvet/internal/lock"
)

func TestHashAuditCorpus(t *testing.T) {
	root := os.Getenv("HASH_AUDIT_DIR")
	if root == "" {
		t.Skip("HASH_AUDIT_DIR not set")
	}
	nfiles, npins, nhashes, dropped := 0, 0, 0, 0
	byKind := map[string]int{} // kind -> hashes checked
	kindAlgo := map[string]map[string]int{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		parser := lock.ByBasename(p)
		if parser == nil {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		f, err := parser.Parse(p, data)
		if err != nil || f == nil {
			return nil
		}
		nfiles++
		for name, vers := range f.Pins {
			for ver, pm := range vers {
				if pm.Integrity == "" {
					continue
				}
				npins++
				for _, h := range strings.Fields(pm.Integrity) {
					nhashes++
					byKind[parser.Kind]++
					algo, val := splitHash(h)
					if algo == "" || val == "" {
						dropped++
						t.Errorf("DROPPED %s [%s] %s@%s hash=%q", p, parser.Kind, name, ver, h)
						continue
					}
					if kindAlgo[parser.Kind] == nil {
						kindAlgo[parser.Kind] = map[string]int{}
					}
					// collapse artifact-scoped prefixes for readability
					if i := strings.IndexByte(algo, '#'); i >= 0 {
						algo = "<file>#" + algo[i+1:]
					}
					kindAlgo[parser.Kind][algo]++
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("parsed %d files, %d integrity pins, %d hashes, %d dropped", nfiles, npins, nhashes, dropped)
	for kind, n := range byKind {
		t.Logf("  %-30s %6d hashes  algos=%v", kind, n, kindAlgo[kind])
	}
}
