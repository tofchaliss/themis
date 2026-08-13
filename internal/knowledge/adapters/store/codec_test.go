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
