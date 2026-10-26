package report

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// nessusCSVHeader is the header row of a real Nessus CSV export, in its order.
const nessusCSVHeader = "Plugin ID,CVE,CVSS v2.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution," +
	"See Also,Plugin Output,STIG Severity,CVSS v4.0 Base Score,CVSS v4.0 Base+Threat Score,CVSS v3.0 Base Score," +
	"CVSS v2.0 Temporal Score,CVSS v3.0 Temporal Score,VPR Score,EPSS Score,Risk Factor,BID,XREF,MSKB," +
	"Plugin Publication Date,Plugin Modification Date,Metasploit,Core Impact,CANVAS"

var nessusCSVAt = time.Date(2026, 10, 15, 21, 30, 0, 0, time.UTC)

// The Nessus CSV road (2026-10-26 amendment C1–C6), born tested: the golden freezes THIS
// converter's bytes over a synthetic export.
func TestNessusCSVConvertMatchesGolden(t *testing.T) {
	body := readFixture(t, "nessus", "sample.input.csv")
	got, stats, err := Convert(body, nessusCSVAt)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	// 2 package lines on CVE-0001 + 1 on CVE-0002 (one host each) + 1 unsplittable line
	// + 2 upstream checks = 6 considered, 3 skipped; the row with no CVE is not counted.
	if stats.FindingsTotal != 6 || stats.FindingsSkipped != 3 {
		t.Errorf("stats = %+v, want total=6 skipped=3", stats)
	}
	if want := readFixture(t, "nessus", "sample.csv.golden.json"); string(got) != string(want) {
		g, w := firstDiff(string(got), string(want))
		t.Errorf("output differs from the committed golden:\n got: %q\nwant: %q", g, w)
	}
}

func TestNessusCSVSemanticInvariants(t *testing.T) {
	out, _, err := Convert(readFixture(t, "nessus", "sample.input.csv"), nessusCSVAt)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	findings := decodeFindings(t, out)
	if len(findings) != 3 {
		t.Fatalf("got %d findings, want 3", len(findings))
	}
	// Name + version by the RPM rule, no purl (N4), `Should be` is the fix (N5), the
	// supplied time (C3), Risk -> severity and the v3.0 score with no vector (C4).
	f := findings[0]
	if f.CVE != "CVE-2026-0001" || f.Component.Name != "kernel" || f.Component.Version != "4.18.0-553.151.1.el8_10" ||
		f.Component.PURL != "" || f.Component.Ecosystem != "rpm" || len(f.Fixed) != 1 || f.Fixed[0] != "4.18.0-553.154.1.el8_10" ||
		f.Scanner != "nessus" || f.Severity != "High" || f.CVSSScore != 7.8 || f.CVSSVector != "" ||
		f.ObservedAt != "2026-10-15T21:30:00.000Z" {
		t.Errorf("first = %+v", f)
	}
	if f := findings[1]; f.Component.Name != "kernel-core" {
		t.Errorf("second = %+v, want the second package line", f)
	}
	// `None` is no severity; no score is the integer zero.
	if f := findings[2]; f.CVE != "CVE-2026-0002" || f.Severity != "" || f.CVSSScore != 0 {
		t.Errorf("third = %+v", f)
	}
	// C5: nothing about the host.
	for _, leak := range []string{"192.0.2.", "example.test", "tcp", "Synopsis"} {
		if strings.Contains(string(out), leak) {
			t.Errorf("curated document contains %q", leak)
		}
	}
}

// C3: the CSV has no scan date, so one must be supplied — never `now`.
func TestNessusCSVNeedsASuppliedObservedAt(t *testing.T) {
	_, _, err := Convert(readFixture(t, "nessus", "sample.input.csv"), time.Time{})
	if !errors.Is(err, ErrObservedAtUnderivable) {
		t.Fatalf("err = %v, want observed_at_underivable", err)
	}
}

func TestNessusCSVRefusals(t *testing.T) {
	row := func(cols int) string { return strings.Repeat(",", cols-1) }
	header := nessusCSVHeader
	for _, tc := range []struct {
		name string
		body string
		want error
	}{
		{"not UTF-8", header + "\n\xff", ErrMalformedBody},
		{"no header row", "", ErrMalformedBody},
		{"broken quoting", header + "\n\"a", ErrMalformedBody},
		{"a duplicate header", header + ",CVE\n", ErrMalformedBody},
		{"a row with the wrong column count", header + "\n" + row(3) + "\n", ErrSourceInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := nessusCSV{}.Convert([]byte(tc.body), nessusCSVAt)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// A header with only the identifying columns is enough: score and risk are optional.
func TestNessusCSVMinimalHeader(t *testing.T) {
	body := "Plugin ID,CVE,Host,Name,Plugin Output\n" +
		"1,CVE-2026-9,192.0.2.1,x,\"Remote package installed : a-1-1\"\n"
	out, stats, err := Convert([]byte(body), nessusCSVAt)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	f := decodeFindings(t, out)
	if stats.FindingsTotal != 1 || len(f) != 1 || f[0].Component.Name != "a" || f[0].CVSSScore != 0 || f[0].Severity != "" {
		t.Errorf("stats=%+v findings=%+v", stats, f)
	}
	if (nessusCSV{}).Version() != "nessus-csv@1" {
		t.Error("version")
	}
}
