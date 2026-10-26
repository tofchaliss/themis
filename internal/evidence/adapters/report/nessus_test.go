package report

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The Nessus report road (EDR-INTAKE-01, 2026-10-24 amendment), born tested: there is no
// earlier implementation to be byte-equal with, so the committed golden freezes THIS
// converter's bytes. Since the 2026-10-26 amendment a `.nessus` body is an SBOM by default,
// so these tests call the report converter directly — the road `kind=vuln-report` selects.
func TestNessusConvertMatchesGolden(t *testing.T) {
	body := readFixture(t, "nessus", "sample.input.nessus")
	got, stats, err := nessusXML{}.Convert(body, time.Time{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	// 4 + (1 kept, 1 unsplittable) + 3 upstream + 1 no-package + 1 on host 2 = 11 considered,
	// 5 skipped; the informational plugin carries no CVE and is not counted (N3).
	if stats.FindingsTotal != 11 || stats.FindingsSkipped != 5 {
		t.Errorf("stats = %+v, want total=11 skipped=5", stats)
	}
	if want := readFixture(t, "nessus", "sample.golden.json"); string(got) != string(want) {
		g, w := firstDiff(string(got), string(want))
		t.Errorf("output differs from the committed golden:\n got: %q\nwant: %q", g, w)
	}
}

// The judgements byte-equality cannot see.
func TestNessusSemanticInvariants(t *testing.T) {
	findings := decodeFindings(t, nessusReport(t, readFixture(t, "nessus", "sample.input.nessus")))
	if len(findings) != 6 {
		t.Fatalf("got %d findings, want 6 kept of 11 considered", len(findings))
	}
	// CVE × package, in document order; the name/version split is the RPM rule; no purl is
	// ever built (N4); the fix is the `Should be` line (N5); the time is the host's own (N6).
	f := findings[0]
	if f.CVE != "CVE-2026-0001" || f.Component.Name != "kernel" || f.Component.Version != "4.18.0-553.151.1.el8_10" ||
		f.Component.PURL != "" || f.Component.Ecosystem != "rpm" || len(f.Fixed) != 1 || f.Fixed[0] != "4.18.0-553.154.1.el8_10" ||
		f.Scanner != "nessus" || f.Severity != "High" || f.CVSSScore != 7.8 || !strings.HasPrefix(f.CVSSVector, "CVSS:3.0/") ||
		f.ObservedAt != "2026-08-11T14:05:12.000Z" {
		t.Errorf("first = %+v", f)
	}
	if f := findings[1]; f.CVE != "CVE-2026-0001" || f.Component.Name != "kernel-core" {
		t.Errorf("second = %+v, want the second package of the same CVE", f)
	}
	if f := findings[2]; f.CVE != "CVE-2026-0002" || f.Component.Name != "kernel" {
		t.Errorf("third = %+v, want the second CVE", f)
	}
	// An epoch is kept as written; `None` is no severity, and no score is the integer zero.
	if f := findings[4]; f.Component.Name != "openssl-libs" || f.Component.Version != "1:1.1.1k-14.el8_6" ||
		f.Fixed[0] != "1:1.1.1k-15.el8_6" || f.Severity != "" || f.CVSSScore != 0 {
		t.Errorf("fifth = %+v", f)
	}
	// Host 2 is kept, not merged, and timed by HOST_END read as UTC.
	if f := findings[5]; f.CVE != "CVE-2026-0001" || f.ObservedAt != "2026-08-11T19:23:46.000Z" {
		t.Errorf("sixth = %+v", f)
	}
	// No upstream version check becomes a finding (N3).
	for _, f := range findings {
		if strings.HasPrefix(f.CVE, "CVE-2023-") || f.CVE == "CVE-2026-0004" {
			t.Errorf("a skipped result was filed: %+v", f)
		}
	}
}

// N8: nothing about the host reaches the curated document.
func TestNessusEmitsNothingAboutTheHost(t *testing.T) {
	out := string(nessusReport(t, readFixture(t, "nessus", "sample.input.nessus")))
	for _, leak := range []string{"192.0.2.", "example.test", "00:00:5e", "NOTE:", "OpenSSH", "synthetic"} {
		if strings.Contains(out, leak) {
			t.Errorf("curated document contains %q", leak)
		}
	}
}

func TestNessusObservedAt(t *testing.T) {
	const host = `<NessusClientData_v2><Report><ReportHost name="h"><HostProperties>%s</HostProperties>` +
		`<ReportItem pluginFamily="Red Hat Local Security Checks"><cve>CVE-2026-1</cve>` +
		`<plugin_output>Remote package installed : a-1-1</plugin_output></ReportItem></ReportHost></Report></NessusClientData_v2>`
	for _, tc := range []struct {
		name, props, want string
		supplied          time.Time
	}{
		{"end timestamp", `<tag name="HOST_END_TIMESTAMP">1786457112</tag>`, "2026-08-11T14:05:12.000Z", time.Time{}},
		{"start timestamp when there is no end", `<tag name="HOST_START_TIMESTAMP">1786455840</tag>`, "2026-08-11T13:44:00.000Z", time.Time{}},
		{"supplied wins", `<tag name="HOST_END_TIMESTAMP">1786457112</tag>`, "2026-01-02T03:04:05.000Z", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _, err := nessusXML{}.Convert([]byte(strings.Replace(host, "%s", tc.props, 1)), tc.supplied)
			if err != nil {
				t.Fatalf("Convert: %v", err)
			}
			if fs := decodeFindings(t, out); len(fs) != 1 || fs[0].ObservedAt != tc.want {
				t.Errorf("findings = %+v, want observed_at %s", fs, tc.want)
			}
		})
	}
	// A host with no time of its own takes the document's latest.
	two := `<NessusClientData_v2><Report>` +
		`<ReportHost name="a"><HostProperties><tag name="HOST_END_TIMESTAMP">1786457112</tag></HostProperties></ReportHost>` +
		`<ReportHost name="b"><HostProperties/><ReportItem pluginFamily="Red Hat Local Security Checks"><cve>CVE-2026-1</cve>` +
		`<plugin_output>Remote package installed : a-1-1</plugin_output></ReportItem></ReportHost></Report></NessusClientData_v2>`
	out, _, err := nessusXML{}.Convert([]byte(two), time.Time{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if fs := decodeFindings(t, out); len(fs) != 1 || fs[0].ObservedAt != "2026-08-11T14:05:12.000Z" {
		t.Errorf("findings = %+v", fs)
	}
}

func TestNessusRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want error
	}{
		{"not utf-8", "<NessusClientData_v2>\xff</NessusClientData_v2>", ErrMalformedBody},
		{"not XML", `{"matches":[]}`, ErrMalformedBody},
		{"another root", `<NessusClientData/>`, ErrMalformedBody},
		{"does not parse", `<NessusClientData_v2><Report>`, ErrMalformedBody},
		{"an entity declaration", `<!DOCTYPE x [<!ENTITY e "x">]><NessusClientData_v2/>`, ErrMalformedBody},
		{"no host time and none supplied", `<NessusClientData_v2><Report><ReportHost name="h"/></Report></NessusClientData_v2>`, ErrObservedAtUnderivable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := nessusXML{}.Convert([]byte(tc.body), time.Time{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	// A supplied observed_at rescues a report with no host time (D3); an empty scan is an
	// empty document, not an error, exactly as an empty Grype report is.
	out, stats, err := nessusXML{}.Convert([]byte(`<NessusClientData_v2/>`), time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil || stats.FindingsTotal != 0 || string(out) != `{"findings":[]}` {
		t.Fatalf("supplied: %q %+v %v", out, stats, err)
	}
	if (nessusXML{}).Version() != "nessus@1" {
		t.Error("version")
	}
}

func TestSplitNVR(t *testing.T) {
	for _, tc := range []struct {
		in, name, version string
		ok                bool
	}{
		{"kernel-4.18.0-553.151.1.el8_10", "kernel", "4.18.0-553.151.1.el8_10", true},
		{"perl-DBI-1.641-5.module+el8.10.0+24438+dc2220dd", "perl-DBI", "1.641-5.module+el8.10.0+24438+dc2220dd", true},
		{"openssl-libs-1:1.1.1k-14.el8_6", "openssl-libs", "1:1.1.1k-14.el8_6", true},
		{"python3-libs-3.6.8-67.el8_10.rocky.0", "python3-libs", "3.6.8-67.el8_10.rocky.0", true},
		{"unsplittable", "", "", false},
		{"only-one", "", "", false},
		{"a--1", "", "", false},
		{"-1-1", "", "", false},
		{"a-1-", "", "", false},
	} {
		name, version, ok := splitNVR(tc.in)
		if name != tc.name || version != tc.version || ok != tc.ok {
			t.Errorf("splitNVR(%q) = %q, %q, %v; want %q, %q, %v", tc.in, name, version, ok, tc.name, tc.version, tc.ok)
		}
	}
}

// A `Should be` line with no installed line before it belongs to nothing.
func TestNessusPackagesPairing(t *testing.T) {
	pkgs, bad := nessusPackages("Should be : a-2-1\nRemote package installed : a-1-1\n\nRemote package installed : b-1-1\nShould be : b-2-1\nShould be : b-3-1\n")
	if bad != 0 || len(pkgs) != 2 || pkgs[0].fixed != "" || pkgs[1].fixed != "2-1" {
		t.Errorf("pkgs = %+v bad = %d", pkgs, bad)
	}
}

// nessusReport converts through the report road, failing the test on a refusal.
func nessusReport(t *testing.T, body []byte) []byte {
	t.Helper()
	out, _, err := nessusXML{}.Convert(body, time.Time{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	return out
}
