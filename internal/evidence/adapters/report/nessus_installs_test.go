package report

import (
	"strings"
	"testing"
	"time"
)

// The H1 rule, case by case. Each case is one way the rule ABSTAINS or one way it files, and
// the abstentions are the point: measured on a real export, "unmarked = hand-installed" would
// have invented ~180 phantom components per host.
func TestNessusInstalls_Rule(t *testing.T) {
	rpms := nessusRPMNames("  example-agent-2.10.3-75.el8|(none) x|Example Corp|x\n  nginx-1.14.1-9.el8|(none) x|Red Hat, Inc.|x\n")
	block := func(path, version, extra string) string {
		return "\n  Path    : " + path + "\n  Version : " + version + "\n" + extra + "\n"
	}
	detect := func(name, cpe, output string) nessusDetection {
		var cpes []string
		if cpe != "" {
			cpes = []string{cpe}
		}
		return nessusDetection{pluginID: "1", pluginName: name, output: output, cpes: cpes}
	}
	for _, tc := range []struct {
		name string
		item nessusDetection
		want map[string]nessusInstall // path → install; nil = nothing filed
	}{
		{"hand-installed under /var/lib with a CPE", detect("Apache Tomcat Installed (Linux/Unix)", "cpe:/a:apache:tomcat:10.1.55", block("/var/lib/apache-tomcat-latest", "10.1.55", "")),
			map[string]nessusInstall{"/var/lib/apache-tomcat-latest": {path: "/var/lib/apache-tomcat-latest", product: "Apache Tomcat", version: "10.1.55", cpe: "cpe:/a:apache:tomcat"}}},
		{"under /usr/local counts as outside the rpm trees", detect("Foo Installed", "cpe:/a:foo:foo", block("/usr/local/foo/bin/foo", "1.2", "")),
			map[string]nessusInstall{"/usr/local/foo/bin/foo": {path: "/usr/local/foo/bin/foo", product: "Foo", version: "1.2", cpe: "cpe:/a:foo:foo"}}},
		{"unmarked under /usr is undecidable", detect("Vim Installed (Linux)", "cpe:/a:vim:vim", block("/usr/bin/vim", "8.0", "")), nil},
		{"unmarked under /lib64 is undecidable", detect("Libgcrypt Installed (Linux/UNIX)", "cpe:/a:gnupg:libgcrypt", block("/lib64/libgcrypt.so.20", "1.8.5", "")), nil},
		{"Managed by OS mark", detect("Curl Installed (Linux / Unix)", "cpe:/a:haxx:curl", block("/opt/curl/bin/curl", "7.61.1", "  Managed by OS : True")), nil},
		{"Associated Package mark", detect("OpenSSL Installed (Linux)", "cpe:/a:openssl:openssl", block("/opt/ssl/libssl.so", "1.1.1k", "  Associated Package : openssl-libs-1.1.1k-17.el8_6.x86_64")), nil},
		{"via package manager in the path", detect("PostgreSQL Client/Server Installed (Linux)", "cpe:/a:postgresql:postgresql", block("/usr/bin/postgres (via package manager)", "13.23", "")), nil},
		{"the plugin says the package manager reported it", detect("SQLite Local Detection (Linux / Unix)", "cpe:/a:sqlite:sqlite", block("/opt/sqlite3", "3.26.0", "")+"\nVersion reported by the package manager.\n"), nil},
		{"an RPM of the product is on the host (CPE product)", detect("nginx Installed (Linux)", "cpe:/a:nginx:nginx", block("/opt/nginx/sbin/nginx", "1.14.1", "")), nil},
		{"an RPM of the product is on the host (hyphenated name)", detect("Example Agent Installed (Linux)", "cpe:/a:example:agent", block("/opt/example-agent/bin/agent", "2.10.3", "")), nil},
		{"a vulnerability result establishes nothing", nessusDetection{pluginID: "2", pluginName: "Apache Tomcat Installed (Linux/Unix)", cves: []string{"CVE-2026-1"}, cpes: []string{"cpe:/a:apache:tomcat"}, output: block("/opt/tomcat2", "10.1.55", "")}, nil},
		{"a plugin name of another shape is not a detection", detect("Apache Tomcat Default Files", "cpe:/a:apache:tomcat", block("/opt/tomcat3", "10.1.55", "")), nil},
		{"a path that is not a path", detect("WebP Installed (Linux)", "cpe:/a:webmproject:libwebp", block("libwebp (via package manager)", "1.0.0", "")), nil},
		{"a block with no version", detect("Thing Installed", "cpe:/a:x:thing", "\n  Path : /opt/thing\n  Product : Thing\n"), nil},
		{"no CPE still indexes (the inventory road refuses it later)", detect("Mystery Tool Installed (Linux)", "", block("/opt/mystery/bin/mystery", "1.0", "")),
			map[string]nessusInstall{"/opt/mystery/bin/mystery": {path: "/opt/mystery/bin/mystery", product: "Mystery Tool", version: "1.0"}}},
		{"a non-application CPE is ignored", detect("Thing Installed", "cpe:/o:x:thing", block("/opt/thing2", "1.0", "")),
			map[string]nessusInstall{"/opt/thing2": {path: "/opt/thing2", product: "Thing", version: "1.0"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := nessusInstalls([]nessusDetection{tc.item}, rpms)
			if len(got) != len(tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
			for p, want := range tc.want {
				if got[p] != want {
					t.Errorf("%s = %+v, want %+v", p, got[p], want)
				}
			}
		})
	}
}

// The list plugins name their own ecosystem; the rpm-tree rule still applies to the path.
func TestNessusInstalls_ListPlugins(t *testing.T) {
	out := "\n2 found :\n\nname: babel\nversion: 2.5.1\npath: /usr/lib/python3.6/site-packages/Babel-2.5.1-py3.6.egg-info\n\nname: requests\nversion: 2.31.0\npath: /opt/app/venv/lib/python3.9/site-packages/requests-2.31.0.dist-info\n\nname: broken\npath: /opt/broken\n"
	got := nessusInstalls([]nessusDetection{{pluginID: nessusPythonListPlugin, output: out}}, nessusRPMNames("python3-babel-2.5.1-1.el8|(none) x|Red Hat, Inc.|x"))
	want := nessusInstall{path: "/opt/app/venv/lib/python3.9/site-packages/requests-2.31.0.dist-info", product: "requests", version: "2.31.0", ecosystem: "pypi"}
	if len(got) != 1 || got[want.path] != want {
		t.Errorf("got %+v, want only %+v", got, want)
	}
	gems := nessusInstalls([]nessusDetection{{pluginID: nessusGemListPlugin, output: "name: rack\nversion: 2.2.20\npath: /opt/app/specs/rack-2.2.20.gemspec\n"}}, nil)
	if purl, ok := nessusInstallPURL(gems["/opt/app/specs/rack-2.2.20.gemspec"]); !ok || purl != "pkg:gem/rack@2.2.20" {
		t.Errorf("gem purl = %q (%v)", purl, ok)
	}
	// A list install whose RPM is on the host abstains, like any other.
	owned := nessusInstalls([]nessusDetection{{pluginID: nessusGemListPlugin, output: "name: rexml\nversion: 3.4.1\npath: /opt/x/rexml.gemspec\n"}}, nessusRPMNames("rubygem-rexml-3.4.1-1.el8|(none) x|Red Hat, Inc.|x"))
	if len(owned) != 0 {
		t.Errorf("an RPM-owned gem was filed: %+v", owned)
	}
}

// H2: the purl is the table's line, else `generic` from the CPE, and no CPE is no identity.
func TestNessusInstallPURL(t *testing.T) {
	for _, tc := range []struct {
		inst nessusInstall
		want string
		ok   bool
	}{
		{nessusInstall{product: "PostgreSQL JDBC Driver", version: "42.7.13", cpe: "cpe:/a:postgresql:postgresql_jdbc_driver"}, "pkg:maven/org.postgresql/postgresql@42.7.13", true},
		{nessusInstall{product: "Apache Tomcat", version: "10.1.55", cpe: "cpe:/a:apache:tomcat"}, "pkg:generic/apache/tomcat@10.1.55", true},
		{nessusInstall{product: "Mystery Tool", version: "1.0"}, "", false},
		{nessusInstall{product: "requests", version: "2.31.0", ecosystem: "pypi"}, "pkg:pypi/requests@2.31.0", true},
	} {
		got, ok := nessusInstallPURL(tc.inst)
		if got != tc.want || ok != tc.ok {
			t.Errorf("%+v → %q %v, want %q %v", tc.inst, got, ok, tc.want, tc.ok)
		}
	}
	if nessusCPEBase("cpe:/a:apache") != "" || nessusCPEBase("cpe:/a:apache:tomcat:10.1.55") != "cpe:/a:apache:tomcat" {
		t.Error("nessusCPEBase keeps exactly vendor and product")
	}
}

// H3 counting: no path block is one record per CVE; blocks are one record per CVE per block,
// and only the blocks the index knows are filed.
func TestNessusClassC_Counts(t *testing.T) {
	idx := nessusInstallIndex{"/opt/t": {path: "/opt/t", product: "T", version: "1"}}
	filed := 0
	file := func(string, nessusInstall, []string) { filed++ }
	if kept, total := nessusClassC("  Version source : banner\n  Installed version : 8.0\n", idx, []string{"a", "b"}, file); kept != 0 || total != 2 || filed != 0 {
		t.Errorf("banner check: kept=%d total=%d filed=%d", kept, total, filed)
	}
	out := "  Path : /opt/t\n  Installed version : 1\n  Fixed version : 2\n\n  Path : /usr/bin/t\n  Installed version : 1\n  Fixed version : 2\n"
	var got nessusInstall
	var fixed []string
	kept, total := nessusClassC(out, idx, []string{"a", "b"}, func(_ string, inst nessusInstall, f []string) { filed++; got, fixed = inst, f })
	if kept != 2 || total != 4 || filed != 2 || got.version != "1" || len(fixed) != 1 || fixed[0] != "2" {
		t.Errorf("kept=%d total=%d filed=%d inst=%+v fixed=%v", kept, total, filed, got, fixed)
	}
	// A block without the version keeps the index's; without a fix, none.
	kept, total = nessusClassC("  Path : /opt/t\n", idx, []string{"a"}, func(_ string, inst nessusInstall, f []string) { got, fixed = inst, f })
	if kept != 1 || total != 1 || got.version != "1" || fixed != nil {
		t.Errorf("bare block: kept=%d total=%d inst=%+v fixed=%v", kept, total, got, fixed)
	}
}

// The report road reads the package list of the host the result is on, so a product the host
// has an RPM of is not filed as hand-installed even when the detection block is unmarked.
func TestNessusReport_HostInstallsReadThePackageList(t *testing.T) {
	doc := strings.Replace(string(readFixture(t, "nessus", "sample.input.nessus")),
		`<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506"`,
		`<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="22869" pluginName="Software Enumeration (SSH)" pluginFamily="General">
<plugin_output>
  tomcat-9.0.87-1.el8|(none) x|Red Hat, Inc.|x
</plugin_output>
</ReportItem>
<ReportItem port="0" svc_name="general" protocol="tcp" severity="0" pluginID="19506"`, 1)
	_, stats, err := nessusXML{}.Convert([]byte(doc), time.Time{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	// The two Tomcat CVEs are now skipped, not filed: 14 considered, 8 skipped.
	if stats.FindingsTotal != 14 || stats.FindingsSkipped != 8 {
		t.Errorf("stats = %+v, want total=14 skipped=8 once the host owns a tomcat RPM", stats)
	}
}
