package lock

import "testing"

// package-lock v2/v3 aliased installs record the real package in the
// entry's name field; registry claims under the alias name would be
// wrong (the yarn npm: alias precedent).
func TestNPMLockV3Alias(t *testing.T) {
	const lockjson = `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"dependencies": {"react-loadable": "npm:@docusaurus/react-loadable@^5.5.2"}},
	    "node_modules/react-loadable": {
	      "name": "@docusaurus/react-loadable",
	      "version": "5.5.2",
	      "resolved": "https://registry.npmjs.org/@docusaurus/react-loadable/-/react-loadable-5.5.2.tgz",
	      "integrity": "sha512-abc"
	    },
	    "node_modules/left-pad": {
	      "version": "1.3.0",
	      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
	    }
	  }
	}`
	f, err := parseNPMLock("package-lock.json", []byte(lockjson))
	if err != nil {
		t.Fatal(err)
	}
	if !f.NonRegistry["react-loadable"] {
		t.Error("aliased install should be NonRegistry")
	}
	if f.NonRegistry["left-pad"] {
		t.Error("plain install must stay registry")
	}
}
