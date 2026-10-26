package report

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/evidence/adapters/parser"
)

// The Nessus inventory road (EDR-INTAKE-01, 2026-10-26 amendment P1–P8), born tested: the
// golden freezes THIS converter's bytes over a synthetic export.
func TestNessusInventoryMatchesGolden(t *testing.T) {
	got, stats, err := nessusInventory{}.Convert(readFixture(t, "nessus", "inventory.input.nessus"), time.Time{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	// Skipped: another vendor (2), a line that does not split (1), and a host whose OS is
	// not mapped (1). The duplicate zlib on host 2 collapses and is not a skip (P6).
	if stats.ComponentsSkipped != 4 || stats.FindingsTotal != 0 || stats.FindingsSkipped != 0 {
		t.Errorf("stats = %+v, want components_skipped=4 and no finding counts", stats)
	}
	if want := readFixture(t, "nessus", "inventory.golden.json"); string(got) != string(want) {
		g, w := firstDiff(string(got), string(want))
		t.Errorf("output differs from the committed golden:\n got: %q\nwant: %q", g, w)
	}
}

// What is filed is read by Evidence's ONE CycloneDX reader, unchanged (P2) — the
// property that makes the converted document a real SBOM rather than a lookalike.
func TestNessusInventoryIsReadByTheCycloneDXParser(t *testing.T) {
	doc, _, err := nessusInventory{}.Convert(readFixture(t, "nessus", "inventory.input.nessus"), time.Time{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	res, err := parser.NewRegistry().Parse(context.Background(), "cyclonedx", "", doc)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", res.Warnings)
	}
	comps := res.Inventory.Components()
	if len(comps) != 5 {
		t.Fatalf("got %d components, want 5", len(comps))
	}
	byPURL := map[string]bool{}
	for _, c := range comps {
		byPURL[c.PURL.String()] = true
		if c.Ecosystem != "rpm" || c.Name == "" || c.Version == "" {
			t.Errorf("component = %+v, want an rpm with name and version", c)
		}
	}
	for _, want := range []string{
		"pkg:rpm/redhat/zlib@1.2.11-25.el8?distro=rhel-8.10",
		"pkg:rpm/redhat/openssl-libs@1.1.1k-14.el8_6?distro=rhel-8.10&epoch=1",
		// Two hosts, two kernels: real drift, kept visible (P6).
		"pkg:rpm/redhat/kernel@4.18.0-553.151.1.el8_10?distro=rhel-8.10",
		"pkg:rpm/redhat/kernel@4.18.0-553.154.1.el8_10?distro=rhel-8.10",
	} {
		if !byPURL[want] {
			t.Errorf("missing %s in %v", want, byPURL)
		}
	}
}

// P3 + N8: no other vendor's package and nothing about the host reaches the document.
func TestNessusInventoryEmitsNothingAboutTheHostOrOtherVendors(t *testing.T) {
	doc, _, err := nessusInventory{}.Convert(readFixture(t, "nessus", "inventory.input.nessus"), time.Time{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	for _, leak := range []string{"192.0.2.", "example.test", "00:00:5e", "Example Corp", "example-agent", "htop", "gpg-pubkey", "bash", "bugzilla", "OpenSSH", "\\u0026"} {
		if strings.Contains(string(doc), leak) {
			t.Errorf("document contains %q", leak)
		}
	}
}

func TestNessusInventoryOSMapping(t *testing.T) {
	for _, tc := range []struct {
		os, vendor, want string
	}{
		{"Linux Kernel 5.14 on Rocky Linux release 9.4 (Blue Onyx)", "Rocky Enterprise Software Foundation", "pkg:rpm/rocky/a@1-1?distro=rocky-9.4"},
		{"Linux Kernel 5.14 on AlmaLinux release 9.4", "AlmaLinux", "pkg:rpm/almalinux/a@1-1?distro=almalinux-9.4"},
		{"Linux Kernel 3.10 on Red Hat Enterprise Linux release 7", "Red Hat, Inc.", "pkg:rpm/redhat/a@1-1?distro=rhel-7"},
	} {
		t.Run(tc.os, func(t *testing.T) {
			doc, _, err := nessusInventory{}.Convert([]byte(inventoryHost(tc.os, "a-1-1|(none) x|"+tc.vendor+"|x")), time.Time{})
			if err != nil {
				t.Fatalf("Convert: %v", err)
			}
			if !strings.Contains(string(doc), `"purl":"`+tc.want+`"`) {
				t.Errorf("document = %s, want purl %s", doc, tc.want)
			}
		})
	}
}

// A numeric epoch of 0 is the same as none, and is not written (P3).
func TestNessusInventoryEpochZeroIsNone(t *testing.T) {
	doc, _, err := nessusInventory{}.Convert([]byte(inventoryHost(rhel810, "a-1-1|0 x|Red Hat, Inc.|x")), time.Time{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if strings.Contains(string(doc), "epoch") {
		t.Errorf("document = %s, want no epoch qualifier", doc)
	}
}

// A supplied observed_at wins over the hosts' own times (D3).
func TestNessusInventorySuppliedObservedAtWins(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	doc, _, err := nessusInventory{}.Convert(readFixture(t, "nessus", "inventory.input.nessus"), at)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	if !strings.Contains(string(doc), `"timestamp":"2026-01-02T03:04:05Z"`) {
		t.Errorf("document = %.200s, want the supplied timestamp", doc)
	}
}

// P8 and the structural refusals, each by name.
func TestNessusInventoryRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want error
	}{
		{"not UTF-8", "<NessusClientData_v2>\xff</NessusClientData_v2>", ErrMalformedBody},
		{"not XML", `{"a":1}`, ErrMalformedBody},
		{"another XML root", `<NessusClientData/>`, ErrMalformedBody},
		{"XML that does not parse", `<NessusClientData_v2><Report>`, ErrMalformedBody},
		{"an entity", `<!DOCTYPE x [<!ENTITY e "b">]><NessusClientData_v2/>`, ErrMalformedBody},
		{"no package list (uncredentialed scan)", `<NessusClientData_v2><Report><ReportHost><HostProperties>` +
			`<tag name="operating-system">` + rhel810 + `</tag></HostProperties></ReportHost></Report></NessusClientData_v2>`, ErrSourceInvalid},
		{"no host on a mapped OS", inventoryHost("Microsoft Windows Server 2019", "a-1-1|(none) x|Red Hat, Inc.|x"), ErrSourceInvalid},
		{"no package from the OS vendor", inventoryHost(rhel810, "a-1-1|(none) x|Example Corp|x"), ErrEmptyReport},
		{"no scan time", strings.Replace(inventoryHost(rhel810, "a-1-1|(none) x|Red Hat, Inc.|x"), `<tag name="HOST_END_TIMESTAMP">1786457112</tag>`, "", 1), ErrObservedAtUnderivable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := nessusInventory{}.Convert([]byte(tc.body), time.Time{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if (nessusInventory{}).Version() != "nessus-inventory@1" {
		t.Error("version")
	}
}

const rhel810 = "Linux Kernel 4.18.0 on Red Hat Enterprise Linux release 8.10 (Ootpa)"

// inventoryHost is a one-host export with the given OS and one plugin 22869 line.
func inventoryHost(os, line string) string {
	return `<NessusClientData_v2><Report><ReportHost name="h"><HostProperties>` +
		`<tag name="HOST_END_TIMESTAMP">1786457112</tag><tag name="operating-system">` + os + `</tag></HostProperties>` +
		`<ReportItem pluginID="22869"><plugin_output>Here is the list of packages :` + "\n\n  " + line + "\n" +
		`</plugin_output></ReportItem></ReportHost></Report></NessusClientData_v2>`
}
