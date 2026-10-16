package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// KN-RANGE-ECO-1: the card keeps each range's world. The flat union still holds every range
// (older consumers unchanged); RangesFor hands a Go component only the Go and the world-less
// ranges, so an Oracle appliance's range no longer keeps go1.27.1 open; a source's later
// statements replace its earlier ones like ranges do; and a different statement set is a new
// observation, not a restatement.
func TestReconcile_RangeStatementsKeepTheirWorld(t *testing.T) {
	fl, err := domain.NewFaultline("F1", mustCVE(t, "CVE-2019-17596"))
	if err != nil {
		t.Fatal(err)
	}
	prec := domain.NewPrecedence("osv")
	c, _ := value.NewCVSS(7.5, "")
	facts := func(ranges []string, stmts ...value.RangeStatement) domain.VulnFacts {
		return domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c, AffectedRanges: ranges, RangeStatements: stmts}
	}
	osv1, _ := domain.NewVulnFactsProposal("osv", t0, facts([]string{"<1.13.2", "<21.1.1.1.0"},
		value.RangeStatement{Ecosystem: "go", Package: "stdlib", Range: "<1.13.2"},
		value.RangeStatement{Ecosystem: "oracle", Package: "weblogic", Range: "<21.1.1.1.0"}))
	// NVD's CPE bound: no ecosystem, but it names the product (another vendor's appliance).
	nvd, _ := domain.NewVulnFactsProposal("nvd", t0, facts([]string{"<=4.23.1f"},
		value.RangeStatement{Package: "some_appliance", Range: "<=4.23.1f"}))
	fl.FoldProposal(osv1, prec, openTrust())
	fl.FoldProposal(nvd, prec, openTrust())

	v := fl.View()
	if len(v.AffectedRanges) != 3 {
		t.Fatalf("flat union = %v, want all three ranges", v.AffectedRanges)
	}
	if len(v.RangeStatements) != 3 || v.RangeStatements[0].Package != "some_appliance" || v.RangeStatements[1].Ecosystem != "go" || v.RangeStatements[2].Ecosystem != "oracle" {
		t.Fatalf("statements = %+v, want the three worlds sorted (world-less first)", v.RangeStatements)
	}
	goRanges := v.RangesFor("golang", "stdlib")
	if len(goRanges) != 1 || goRanges[0] != "<1.13.2" {
		t.Fatalf("RangesFor(go, stdlib) = %v, want only the Go range (the appliance bound names another product)", goRanges)
	}
	r := value.AffectedRange{Ecosystem: "go", Groups: goRanges}
	if got := r.Applicability("go1.27.1"); got != value.RangeOutOfRange {
		t.Fatalf("go1.27.1 against %v = %s, want out_of_range (the Oracle range no longer holds it)", goRanges, got)
	}
	flat := value.AffectedRange{Ecosystem: "go", Groups: v.AffectedRanges}
	if got := flat.Applicability("go1.27.1"); got != value.RangeInRange {
		t.Fatalf("the flat union must still read as in range (that is the defect), got %s", got)
	}

	// A bare range no statement accounts for (a source that states no world at all) applies to
	// everything, including a Go component.
	bare, _ := domain.NewVulnFactsProposal("scanner/x", t0, facts([]string{"<9.9"}))
	fl.FoldProposal(bare, prec, openTrust())
	if got := fl.View().RangesFor("golang", "stdlib"); len(got) != 2 || got[1] != "<9.9" {
		t.Fatalf("with an unstated bare range: RangesFor = %v, want the Go range plus the bare one", got)
	}

	// A source's later statements replace its earlier ones.
	osv2, _ := domain.NewVulnFactsProposal("osv", t1, facts([]string{"<1.13.3"},
		value.RangeStatement{Ecosystem: "go", Package: "stdlib", Range: "<1.13.3"}))
	fl.FoldProposal(osv2, prec, openTrust())
	v = fl.View()
	// osv's earlier two statements are gone, its later one stands; nvd's appliance bound stays.
	if len(v.RangeStatements) != 2 || v.RangeStatements[0].Package != "some_appliance" || v.RangeStatements[1].Range != "<1.13.3" {
		t.Fatalf("after osv restated: statements = %+v, want nvd's appliance bound and osv's later Go one only", v.RangeStatements)
	}
	// A proposal differing only in its statements is a new observation, not a restatement.
	before := len(fl.Proposals())
	osv3, _ := domain.NewVulnFactsProposal("osv", t1, facts([]string{"<1.13.3"},
		value.RangeStatement{Ecosystem: "go", Package: "stdlib", Range: "<1.13.3"},
		value.RangeStatement{Ecosystem: "go", Package: "golang.org/x/net", Range: "<0.1.0"}))
	fl.FoldProposal(osv3, prec, openTrust())
	if len(fl.Proposals()) != before+1 {
		t.Fatalf("proposals = %d, want %d (a changed statement set is recorded)", len(fl.Proposals()), before+1)
	}
	// A card with no statements at all: RangesFor is the flat list.
	bareCard, _ := domain.NewFaultline("F2", mustCVE(t, "CVE-2026-1"))
	p, _ := domain.NewVulnFactsProposal("nvd", t0, facts([]string{"<2.0"}))
	bareCard.FoldProposal(p, prec, openTrust())
	if got := bareCard.View().RangesFor("go", "x"); len(got) != 1 || got[0] != "<2.0" {
		t.Fatalf("no statements: RangesFor = %v, want the flat list", got)
	}
}

// The statements ride the enriched event with their world, and the view orders them totally
// (ecosystem, then package, then range); a card without statements puts none on the wire.
func TestRangeStatements_OnTheEventAndTotallyOrdered(t *testing.T) {
	fl, _ := domain.NewFaultline("F3", mustCVE(t, "CVE-2026-3"))
	prec := domain.NewPrecedence("osv")
	c, _ := value.NewCVSS(7.5, "")
	p, _ := domain.NewVulnFactsProposal("osv", t0, domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c,
		AffectedRanges: []string{"<1.13.2", "<0.6.0", "<1.14.0", "<2"},
		RangeStatements: []value.RangeStatement{
			{Ecosystem: "go", Package: "stdlib", Range: "<1.14.0"},
			{Ecosystem: "go", Package: "stdlib", Range: "<1.13.2"},
			{Ecosystem: "go", Package: "golang.org/x/net", Range: "<0.6.0"},
			{Ecosystem: "apk", Package: "zlib", Range: "<2"},
		}})
	fl.FoldProposal(p, prec, openTrust())
	got := fl.View().RangeStatements
	want := []value.RangeStatement{
		{Ecosystem: "apk", Package: "zlib", Range: "<2"},
		{Ecosystem: "go", Package: "golang.org/x/net", Range: "<0.6.0"},
		{Ecosystem: "go", Package: "stdlib", Range: "<1.13.2"},
		{Ecosystem: "go", Package: "stdlib", Range: "<1.14.0"},
	}
	if len(got) != len(want) {
		t.Fatalf("statements = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("statements[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
	ev := domain.NewFaultlineEnriched(fl, t1)
	if len(ev.RangeStatements) != 4 || ev.RangeStatements[2].Ecosystem != "go" || ev.RangeStatements[2].Package != "stdlib" || ev.RangeStatements[2].Range != "<1.13.2" {
		t.Fatalf("event statements = %+v", ev.RangeStatements)
	}
	bareCard, _ := domain.NewFaultline("F4", mustCVE(t, "CVE-2026-4"))
	q, _ := domain.NewVulnFactsProposal("nvd", t0, domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c, AffectedRanges: []string{"<2.0"}})
	bareCard.FoldProposal(q, prec, openTrust())
	if ev := domain.NewFaultlineEnriched(bareCard, t1); ev.RangeStatements != nil {
		t.Fatalf("a card without statements must put none on the wire, got %+v", ev.RangeStatements)
	}
}
