package lock

import "testing"

const samplePom = `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.4.1</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>0.0.1-SNAPSHOT</version>
  <properties>
    <guava.version>33.4.0-jre</guava.version>
    <indirect.version>${guava.version}</indirect.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.junit</groupId>
        <artifactId>junit-bom</artifactId>
        <version>5.11.4</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>${guava.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>demo-core</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>[3.0,4.0)</version>
    </dependency>
    <dependency>
      <groupId>com.oracle</groupId>
      <artifactId>ojdbc8</artifactId>
      <version>19.3.0.0</version>
      <scope>system</scope>
    </dependency>
    <dependency>
      <groupId>net.example</groupId>
      <artifactId>mystery</artifactId>
      <version>${undefined.version}</version>
    </dependency>
    <dependency>
      <groupId>io.example</groupId>
      <artifactId>chained</artifactId>
      <version>${indirect.version}</version>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.13.0</version>
      </plugin>
      <plugin>
        <groupId>org.jacoco</groupId>
        <artifactId>jacoco-maven-plugin</artifactId>
      </plugin>
    </plugins>
  </build>
  <profiles>
    <profile>
      <id>release</id>
      <properties>
        <gpg.plugin.version>3.2.7</gpg.plugin.version>
      </properties>
      <build>
        <plugins>
          <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-gpg-plugin</artifactId>
            <version>${gpg.plugin.version}</version>
          </plugin>
        </plugins>
      </build>
    </profile>
  </profiles>
</project>`

func TestParsePomXML(t *testing.T) {
	f, err := parsePomXML("pom.xml", []byte(samplePom))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if f.Ecosystem != Maven {
		t.Errorf("ecosystem = %s, want Maven", f.Ecosystem)
	}
	want := map[string]string{
		"org.springframework.boot:spring-boot-starter-parent": "3.4.1",
		"org.junit:junit-bom":                            "5.11.4",
		"com.google.guava:guava":                         "33.4.0-jre",
		"io.example:chained":                             "33.4.0-jre",
		"org.apache.maven.plugins:maven-compiler-plugin": "3.13.0",
		"org.apache.maven.plugins:maven-gpg-plugin":      "3.2.7",
		"com.example:demo-core":                          "0.0.1-SNAPSHOT",
		"com.oracle:ojdbc8":                              "19.3.0.0",
	}
	for name, ver := range want {
		if got := f.Packages[name]; len(got) != 1 || got[0] != ver {
			t.Errorf("%s = %v, want [%s]", name, got, ver)
		}
	}
	for _, absent := range []string{
		"org.junit.jupiter:junit-jupiter",  // managed, no version
		"org.apache.commons:commons-lang3", // range
		"net.example:mystery",              // unresolved property
		"org.jacoco:jacoco-maven-plugin",   // plugin without version
	} {
		if _, ok := f.Packages[absent]; ok {
			t.Errorf("%s parsed, want skipped", absent)
		}
	}
	for _, nr := range []string{"com.example:demo-core", "com.oracle:ojdbc8"} {
		if !f.NonRegistry[nr] {
			t.Errorf("%s not NonRegistry", nr)
		}
	}
	if f.NonRegistry["com.google.guava:guava"] {
		t.Error("guava marked NonRegistry")
	}
	if !f.RootsKnown {
		t.Error("roots not known")
	}
}

func TestParsePomXMLNotMaven(t *testing.T) {
	f, err := parsePomXML("pom.xml", []byte(`<?xml version="1.0"?><config><thing/></config>`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(f.Packages) != 0 {
		t.Errorf("packages = %v, want none", f.Packages)
	}
}

func TestParsePomXMLLatin1(t *testing.T) {
	pom := "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?>\n" +
		"<project><groupId>a</groupId><artifactId>b</artifactId><version>1</version>" +
		"<!-- caf\xe9 -->" +
		"<dependencies><dependency><groupId>junit</groupId><artifactId>junit</artifactId>" +
		"<version>4.13.2</version></dependency></dependencies></project>"
	f, err := parsePomXML("pom.xml", []byte(pom))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := f.Packages["junit:junit"]; len(got) != 1 || got[0] != "4.13.2" {
		t.Errorf("junit = %v, want [4.13.2]", got)
	}
}

func TestParsePomXMLRevisionCIFriendly(t *testing.T) {
	pom := `<project>
  <groupId>com.acme</groupId><artifactId>app</artifactId><version>${revision}</version>
  <properties><revision>2.1.0</revision></properties>
  <dependencies>
    <dependency><groupId>com.acme</groupId><artifactId>lib</artifactId><version>${revision}</version></dependency>
    <dependency><groupId>org.slf4j</groupId><artifactId>slf4j-api</artifactId><version>2.0.16</version></dependency>
  </dependencies>
</project>`
	f, err := parsePomXML("pom.xml", []byte(pom))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := f.Packages["com.acme:lib"]; len(got) != 1 || got[0] != "2.1.0" {
		t.Errorf("lib = %v, want [2.1.0]", got)
	}
	if !f.NonRegistry["com.acme:lib"] {
		t.Error("${revision} dep not NonRegistry")
	}
	if f.NonRegistry["org.slf4j:slf4j-api"] {
		t.Error("slf4j marked NonRegistry")
	}
}
