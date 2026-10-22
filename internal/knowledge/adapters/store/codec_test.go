package store

import (
	"testing"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

func vulnFactsProposal(t *testing.T, source string, fixes ...domain.FixedVersion) domain.Proposal {
	t.Helper()
	cvss, _ := value.NewCVSS(7.5, "")
	p, err := domain.NewVulnFactsProposal(source, time.Unix(1_700_000_000, 0),
		domain.VulnFacts{Severity: value.SeverityHigh, CVSS: cvss, Fixes: fixes})
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	return p
}

// A fix's ecosystem must survive the persistence round trip (EDR-VEX-01 D8) — dropping it on
// decode would silently reopen the cross-ecosystem leak on every reload.
func TestProposalCodec_RoundTripsFixEcosystem(t *testing.T) {
	in := vulnFactsProposal(t, "osv",
		domain.FixedVersion{Package: "perl", Version: "4:5.26.3-419.el8", Ecosystem: "rpm"})
	raw, err := marshalProposalPayload(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := unmarshalProposal("osv", in.ObservedAt(), string(in.Kind()), raw)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	f, _ := out.VulnFacts()
	if len(f.Fixes) != 1 || f.Fixes[0].Ecosystem != "rpm" {
		t.Errorf("fixes = %v, want the rpm ecosystem preserved", f.Fixes)
	}
}

// Decode-time source stamping (D8): the append-only history cannot be edited, but a fix stored
// by a single-ecosystem feed before Ecosystem existed IS attributable from provenance alone. The
// stored bytes stay untouched — this is interpretation at the boundary, and it is what heals
// every live card (78 Alpine bounds on the measured estate) with no migration.
func TestProposalCodec_StampsEcosystemFromSingleEcosystemSources(t *testing.T) {
	legacy := []byte(`{"severity":"high","fixes":[{"package":"perl","version":"5.30.3-r0"}]}`)
	at := time.Unix(1_700_000_000, 0)

	p, err := unmarshalProposal("alpine", at, string(domain.KindVulnFacts), legacy)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f, _ := p.VulnFacts(); f.Fixes[0].Ecosystem != "apk" {
		t.Errorf("alpine fix = %v, want ecosystem stamped apk", f.Fixes)
	}

	p, err = unmarshalProposal("redhat", at, string(domain.KindVulnFacts), legacy)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f, _ := p.VulnFacts(); f.Fixes[0].Ecosystem != "rpm" {
		t.Errorf("redhat fix = %v, want ecosystem stamped rpm", f.Fixes)
	}

	// A multi-ecosystem source is deliberately NOT stamped: for osv/nvd only the per-record
	// field is evidence, and inventing one would be exactly the guessing D8 forbids.
	p, err = unmarshalProposal("osv", at, string(domain.KindVulnFacts), legacy)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f, _ := p.VulnFacts(); f.Fixes[0].Ecosystem != "" {
		t.Errorf("osv fix = %v, want ecosystem left unknown", f.Fixes)
	}

	// A stated ecosystem always beats what provenance implies — never overwritten.
	stated := []byte(`{"severity":"high","fixes":[{"package":"perl","version":"5.30.3-r0","ecosystem":"generic"}]}`)
	p, err = unmarshalProposal("alpine", at, string(domain.KindVulnFacts), stated)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if f, _ := p.VulnFacts(); f.Fixes[0].Ecosystem != "generic" {
		t.Errorf("stated fix = %v, want the recorded ecosystem kept", f.Fixes)
	}
}

// The vendor-stated product scope must survive BOTH persistence round trips (EDR-VEX-02 D5).
//
// This is the regression for the defect observed live: `Scope` was absent from both DTOs, so
// every statement reloaded scope-less. Two consequences, and the second is the worse one — the
// reconciled view compares equal-or-not on every fold, so a dropped field means the fold always
// sees a change and re-announces FaultlineEnriched forever. The measured symptom was 1844 stored
// statements of which every single one reported an empty scope.
func TestCodec_RoundTripsApplicabilityScope(t *testing.T) {
	scope := value.ProductScope{Family: value.FamilyEnterpriseLinux, Major: "8"}
	app0 := domain.Applicability{
		Package: "httpd", Status: "fixed", Justification: "Red Hat: fixed in httpd-2.4.37-65.el8 (RHSA-2026:1)",
		Scope: scope, Advisory: "RHSA-2026:1", FixedVersion: "httpd-2.4.37-65.el8", // D14 fields round-trip too
	}

	// 1. The Proposal payload — the append-only record the view is recomputed FROM.
	in, err := domain.NewApplicabilityProposal("redhat", time.Unix(1_700_000_000, 0), app0)
	if err != nil {
		t.Fatalf("proposal: %v", err)
	}
	raw, err := marshalProposalPayload(in)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	out, err := unmarshalProposal("redhat", in.ObservedAt(), string(in.Kind()), raw)
	if err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	got, ok := out.Applicability()
	if !ok {
		t.Fatal("decoded proposal carries no applicability")
	}
	if got != app0 {
		t.Errorf("proposal round trip = %+v, want %+v", got, app0)
	}

	// 2. The materialized view — reloaded before every fold, so the decoded statement must be
	// IDENTICAL or the aggregate reports a view change that did not happen.
	view := domain.EnterpriseView{Severity: value.SeverityHigh, Applicabilities: []domain.Applicability{app0}}
	vraw, err := marshalView(view)
	if err != nil {
		t.Fatalf("marshal view: %v", err)
	}
	decoded, err := unmarshalView(vraw)
	if err != nil {
		t.Fatalf("unmarshal view: %v", err)
	}
	if len(decoded.Applicabilities) != 1 || decoded.Applicabilities[0] != app0 {
		t.Errorf("view round trip = %+v, want [%+v]", decoded.Applicabilities, app0)
	}
}

// A statement stored before the scope field decodes with an EMPTY scope rather than failing —
// and an empty scope reads downstream as applicability `unknown`, which cannot suppress. The
// fail-safe direction: an unplaceable statement blocks nothing and hides nothing.
func TestCodec_ApplicabilityWithoutScopeDecodesUnknown(t *testing.T) {
	legacy := []byte(`{"package":"httpd","status":"not_affected","justification":"vulnerable_code_not_present"}`)
	p, err := unmarshalProposal("redhat", time.Unix(1_700_000_000, 0), string(domain.KindApplicability), legacy)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	a, _ := p.Applicability()
	if a.Scope.Known() {
		t.Errorf("legacy scope = %+v, want an unestablished scope", a.Scope)
	}
	if a.Package != "httpd" || a.Status != "not_affected" {
		t.Errorf("legacy statement = %+v, want the vendor's words intact", a)
	}
}

// KN-RANGE-ECO-1: a range's world survives the proposal and view round-trips; a card written
// before the field decodes with no statements.
func TestCodec_RoundTripsRangeStatements(t *testing.T) {
	c, _ := value.NewCVSS(7.5, "")
	stmts := []value.RangeStatement{{Ecosystem: "go", Package: "stdlib", Range: "<1.13.2"}, {Range: "<=4.23.1f"}}
	at := time.Unix(1_700_000_000, 0)
	p, err := domain.NewVulnFactsProposal("osv", at, domain.VulnFacts{Severity: value.SeverityHigh, CVSS: c,
		AffectedRanges: []string{"<1.13.2", "<=4.23.1f"}, RangeStatements: stmts})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := marshalProposalPayload(p)
	if err != nil {
		t.Fatal(err)
	}
	back, err := unmarshalProposal("osv", at, string(p.Kind()), raw)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := back.VulnFacts()
	if len(f.RangeStatements) != 2 || f.RangeStatements[0] != stmts[0] || f.RangeStatements[1] != stmts[1] {
		t.Fatalf("proposal round-trip statements = %+v", f.RangeStatements)
	}
	view := domain.EnterpriseView{AffectedRanges: []string{"<1.13.2"}, RangeStatements: stmts[:1]}
	vraw, err := marshalView(view)
	if err != nil {
		t.Fatal(err)
	}
	vback, err := unmarshalView(vraw)
	if err != nil {
		t.Fatal(err)
	}
	if len(vback.RangeStatements) != 1 || vback.RangeStatements[0] != stmts[0] {
		t.Fatalf("view round-trip statements = %+v", vback.RangeStatements)
	}
	old, err := unmarshalView([]byte(`{"affected_ranges":["<2.0"]}`))
	if err != nil || len(old.RangeStatements) != 0 || len(old.AffectedRanges) != 1 {
		t.Fatalf("pre-field view = %+v err=%v, want ranges only", old, err)
	}
}

// EDR-REMEDIATION-01 D5: KEV detail survives the proposal and view round trips, and a card
// stored before it decodes to "not stated".
func TestCodec_RoundTripsKEVDetail(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	added := time.Date(2024, 3, 5, 0, 0, 0, 0, time.UTC)
	due := time.Date(2024, 3, 26, 0, 0, 0, 0, time.UTC)
	p, err := domain.NewExploitSignalProposal("epsskev", at, domain.ExploitSignal{KEV: true, KEVAdded: added, KEVDue: due, KEVRansomware: true})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := marshalProposalPayload(p)
	if err != nil {
		t.Fatal(err)
	}
	back, err := unmarshalProposal("epsskev", at, string(p.Kind()), raw)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := back.ExploitSignal()
	if !s.KEV || !s.KEVRansomware || !s.KEVAdded.Equal(added) || !s.KEVDue.Equal(due) {
		t.Fatalf("proposal round trip = %+v", s)
	}
	vraw, err := marshalView(domain.EnterpriseView{KEV: true, KEVAdded: added, KEVDue: due, KEVRansomware: true})
	if err != nil {
		t.Fatal(err)
	}
	v, err := unmarshalView(vraw)
	if err != nil {
		t.Fatal(err)
	}
	if !v.KEVRansomware || !v.KEVAdded.Equal(added) || !v.KEVDue.Equal(due) {
		t.Fatalf("view round trip = %+v", v)
	}
	old, err := unmarshalView([]byte(`{"kev":true,"fixed_versions":[],"applicabilities":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !old.KEVAdded.IsZero() || !old.KEVDue.IsZero() || old.KEVRansomware {
		t.Errorf("a pre-D5 card must decode to not stated: %+v", old)
	}
	if dateOut(time.Time{}) != "" || !dateIn("garbage").IsZero() {
		t.Error("zero writes nothing; garbage reads as not stated")
	}
}
