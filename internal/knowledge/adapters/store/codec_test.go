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
		Package: "httpd", Status: "not_affected", Justification: "vulnerable_code_not_present",
		Scope: scope,
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
