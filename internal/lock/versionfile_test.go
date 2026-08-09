package lock

import "testing"

func TestParseSingleToolFiles(t *testing.T) {
	cases := []struct {
		base, data string
		wantName   string
		wantVers   []string
	}{
		{".nvmrc", "v18.16.0\n", "node", []string{"18.16.0"}},
		{".nvmrc", "18\n", "node", []string{"18"}},
		{".node-version", "20.11.0\n", "node", []string{"20.11.0"}},
		{".python-version", "3.12.4\n", "python", []string{"3.12.4"}},
		{".python-version", "3.12.4\n3.11.9\n", "python", []string{"3.11.9", "3.12.4"}},
		{".python-version", "pypy3.10-7.3.16\n", "python", []string{"pypy3.10-7.3.16"}},
		{".ruby-version", "ruby-3.3.4\n", "ruby", []string{"3.3.4"}},
		{".ruby-version", "3.3.4\n", "ruby", []string{"3.3.4"}},
		{".ruby-version", "jruby-9.4.5.0\n", "ruby", []string{"jruby-9.4.5.0"}},
		{".go-version", "1.23.4\n", "go", []string{"1.23.4"}},
		{".java-version", "corretto-17\n", "java", []string{"corretto-17"}},
		{".java-version", "17.0.9\n", "java", []string{"17.0.9"}},
		{".terraform-version", "1.5.7\n", "terraform", []string{"1.5.7"}},
		{".terragrunt-version", "0.55.1\n", "terragrunt", []string{"0.55.1"}},
	}
	for _, c := range cases {
		parse := parseSingleToolPin(c.base, singleToolFiles[c.base])
		f, err := parse(c.base, []byte(c.data))
		if err != nil {
			t.Fatalf("%s: %v", c.base, err)
		}
		got := f.Packages[c.wantName]
		if len(got) != len(c.wantVers) {
			t.Fatalf("%s %q: got %v want %v", c.base, c.data, got, c.wantVers)
		}
		for i := range got {
			if got[i] != c.wantVers[i] {
				t.Fatalf("%s %q: got %v want %v", c.base, c.data, got, c.wantVers)
			}
		}
		if !f.RootsKnown || len(f.Roots) != 1 {
			t.Fatalf("%s: roots not marked: %v", c.base, f.Roots)
		}
	}
}

func TestSingleToolFilesSymbolicClaimNothing(t *testing.T) {
	cases := []struct{ base, data string }{
		{".nvmrc", "lts/hydrogen\n"},
		{".nvmrc", "node\n"},
		{".nvmrc", "system\n"},
		{".terraform-version", "latest\n"},
		{".terraform-version", "latest:^1.5\n"},
		{".terraform-version", "min-required\n"},
		{".python-version", "myenv\n"},           // pyenv virtualenv name
		{".python-version", "3.12/envs/myenv\n"}, // pyenv virtualenv path
	}
	for _, c := range cases {
		parse := parseSingleToolPin(c.base, singleToolFiles[c.base])
		f, err := parse(c.base, []byte(c.data))
		if err != nil {
			t.Fatalf("%s: %v", c.base, err)
		}
		if len(f.Packages) != 0 {
			t.Fatalf("%s %q: expected no rows, got %v", c.base, c.data, f.Packages)
		}
	}
}

func TestSingleToolFilesByBasename(t *testing.T) {
	for _, p := range []string{
		".nvmrc", "app/.nvmrc", ".node-version", ".python-version",
		".ruby-version", ".go-version", ".java-version",
		".terraform-version", ".terragrunt-version", ".sdkmanrc",
		"mise.lock", "sub/dir/mise.lock",
	} {
		if ByBasename(p) == nil {
			t.Fatalf("ByBasename(%q) = nil", p)
		}
	}
	// A comment-only file parses empty, not as an error.
	f, err := ByBasename(".nvmrc").Parse(".nvmrc", []byte("# nothing\n"))
	if err != nil || len(f.Packages) != 0 {
		t.Fatalf("comment-only .nvmrc: %v %v", f.Packages, err)
	}
}

func TestParseSdkmanrc(t *testing.T) {
	data := `# Enable auto-env through the sdkman_auto_env config
java=17.0.9-tem
gradle=8.5
maven=3.9.6
sbt=1.9.8
kotlin=1.9.22
`
	f, err := parseSdkmanrc(".sdkmanrc", []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"java":                          {"17.0.9-tem"},
		"gradle":                        {"8.5"},
		"org.apache.maven:apache-maven": {"3.9.6"},
		"org.scala-sbt:sbt":             {"1.9.8"},
		"kotlin":                        {"1.9.22"},
	}
	for name, vers := range want {
		got := f.Packages[name]
		if len(got) != 1 || got[0] != vers[0] {
			t.Fatalf("%s: got %v want %v", name, got, vers)
		}
	}
	if f.PkgEco["gradle"] != GradleDist {
		t.Fatalf("gradle eco = %v", f.PkgEco["gradle"])
	}
	if f.PkgEco["org.apache.maven:apache-maven"] != Maven {
		t.Fatalf("maven eco = %v", f.PkgEco["org.apache.maven:apache-maven"])
	}
}
