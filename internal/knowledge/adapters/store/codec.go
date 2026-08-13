package store

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// viewDTO is the persisted (jsonb) shape of the materialized enterprise view. CVSS is
// split into score + vector because value.CVSS is not directly JSON-encodable.
type viewDTO struct {
	Severity       string   `json:"severity"`
	CVSSScore      float64  `json:"cvss_score"`
	CVSSVector     string   `json:"cvss_vector"`
	SeveritySource string   `json:"severity_source"`
	AffectedRanges []string `json:"affected_ranges"`
	// CarrierProducts — which product CARRIES the flaw (EDR-CORRELATION-01 D4). Additive and
	// omitempty: a card written before this decodes to empty, which classifies every component
	// as ClaimUnknown and therefore as a carrier — exactly the pre-change behaviour.
	CarrierProducts []string `json:"carrier_products,omitempty"`
	// Fixes is the authoritative, package-attributed form; FixedVersions is its flat union,
	// retained so a card written before KN-FIX-1 still decodes and so the wire shape is unchanged.
	Fixes           []fixedVersionDTO  `json:"fixes,omitempty"`
	FixedVersions   []string           `json:"fixed_versions"`
	EPSS            float64            `json:"epss"`
	KEV             bool               `json:"kev"`
	ExploitPublic   bool               `json:"exploit_public"`
	Applicabilities []applicabilityDTO `json:"applicabilities"`

	// Per-field-group trust (EDR-TRUST-01 T3). These MUST round-trip: the view is
	// reloaded before every fold, so a dropped field decodes as empty, gets recomputed,
	// and the aggregate reports a spurious view change on every single fold — firing a
	// duplicate FaultlineEnriched each time. Omitting them here is exactly the defect
	// TestViewChangeEmitsOneEvent catches.
	//
	// Adding them is backward-compatible: the column is jsonb, so pre-existing rows
	// decode with empty trust and are repopulated on their next fold — which correctly
	// reports one view change, because the view genuinely gained information.
	HeadlineTrust string `json:"headline_trust,omitempty"`
	RangeTrust    string `json:"range_trust,omitempty"`
	SignalTrust   string `json:"signal_trust,omitempty"`
}

type applicabilityDTO struct {
	Package       string `json:"package"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

func marshalView(v domain.EnterpriseView) ([]byte, error) {
	dto := viewDTO{
		Severity: string(v.Severity), CVSSScore: v.CVSS.Score(), CVSSVector: v.CVSS.Vector(),
		SeveritySource: v.SeveritySource, AffectedRanges: v.AffectedRanges,
		CarrierProducts: v.CarrierProducts,
		Fixes:           fixesToDTO(v.Fixes), FixedVersions: v.FixedVersions,
		EPSS: v.EPSS, KEV: v.KEV, ExploitPublic: v.ExploitPublic,
		HeadlineTrust: string(v.HeadlineTrust), RangeTrust: string(v.RangeTrust), SignalTrust: string(v.SignalTrust),
	}
	for _, a := range v.Applicabilities {
		dto.Applicabilities = append(dto.Applicabilities, applicabilityDTO{a.Package, a.Status, a.Justification})
	}
	return json.Marshal(dto)
}

func unmarshalView(raw []byte) (domain.EnterpriseView, error) {
	var dto viewDTO
	if err := json.Unmarshal(raw, &dto); err != nil {
		return domain.EnterpriseView{}, err
	}
	cvss, err := value.NewCVSS(dto.CVSSScore, dto.CVSSVector)
	if err != nil {
		return domain.EnterpriseView{}, err
	}
	v := domain.EnterpriseView{
		Severity: value.Severity(dto.Severity), CVSS: cvss, SeveritySource: dto.SeveritySource,
		AffectedRanges:  dto.AffectedRanges,
		CarrierProducts: dto.CarrierProducts,
		Fixes:           fixesFromDTO(dto.Fixes, dto.FixedVersions),
		FixedVersions:   dto.FixedVersions,
		EPSS:            dto.EPSS, KEV: dto.KEV, ExploitPublic: dto.ExploitPublic,
		HeadlineTrust: value.TrustClass(dto.HeadlineTrust),
		RangeTrust:    value.TrustClass(dto.RangeTrust),
		SignalTrust:   value.TrustClass(dto.SignalTrust),
	}
	for _, a := range dto.Applicabilities {
		v.Applicabilities = append(v.Applicabilities, domain.Applicability{Package: a.Package, Status: a.Status, Justification: a.Justification})
	}
	return v, nil
}

// proposalPayloadDTO is the persisted (jsonb) shape of a Proposal's kind-specific
// payload (source/observed-at/kind live in their own columns).
type proposalPayloadDTO struct {
	Severity        string            `json:"severity,omitempty"`
	CVSSScore       float64           `json:"cvss_score,omitempty"`
	CVSSVector      string            `json:"cvss_vector,omitempty"`
	AffectedRanges  []string          `json:"affected_ranges,omitempty"`
	CarrierProducts []string          `json:"carrier_products,omitempty"`
	Fixes           []fixedVersionDTO `json:"fixes,omitempty"`
	// FixedVersions is the pre-KN-FIX-1 shape, still DECODED so stored Proposals keep working;
	// nothing writes it any more.
	FixedVersions []string `json:"fixed_versions,omitempty"`
	EPSS          float64  `json:"epss,omitempty"`
	KEV           bool     `json:"kev,omitempty"`
	ExploitPublic bool     `json:"exploit_public,omitempty"`
	Package       string   `json:"package,omitempty"`
	Status        string   `json:"status,omitempty"`
	Justification string   `json:"justification,omitempty"`
}

func marshalProposalPayload(p domain.Proposal) ([]byte, error) {
	var dto proposalPayloadDTO
	switch p.Kind() {
	case domain.KindVulnFacts:
		f, _ := p.VulnFacts()
		dto.Severity = string(f.Severity)
		dto.CVSSScore = f.CVSS.Score()
		dto.CVSSVector = f.CVSS.Vector()
		dto.AffectedRanges = f.AffectedRanges
		dto.CarrierProducts = f.CarrierProducts
		dto.Fixes = fixesToDTO(f.Fixes)
	case domain.KindExploitSignal:
		s, _ := p.ExploitSignal()
		dto.EPSS = s.EPSS
		dto.KEV = s.KEV
		dto.ExploitPublic = s.ExploitPublic
	case domain.KindApplicability:
		a, _ := p.Applicability()
		dto.Package = a.Package
		dto.Status = a.Status
		dto.Justification = a.Justification
	}
	return json.Marshal(dto)
}

func unmarshalProposal(source string, observedAt time.Time, kind string, payload []byte) (domain.Proposal, error) {
	var dto proposalPayloadDTO
	if err := json.Unmarshal(payload, &dto); err != nil {
		return domain.Proposal{}, err
	}
	switch domain.ProposalKind(kind) {
	case domain.KindVulnFacts:
		cvss, err := value.NewCVSS(dto.CVSSScore, dto.CVSSVector)
		if err != nil {
			return domain.Proposal{}, err
		}
		return domain.NewVulnFactsProposal(source, observedAt, domain.VulnFacts{
			Severity: value.Severity(dto.Severity), CVSS: cvss, AffectedRanges: dto.AffectedRanges,
			CarrierProducts: dto.CarrierProducts,
			// A Proposal stored before KN-FIX-1 has only the flat list; decode it as unattributed
			// rather than dropping it. Unattributed fixes never satisfy a per-component verdict,
			// so an old row degrades to "a fix exists" instead of to a wrong decision.
			// stampFixEcosystems then backfills a missing ecosystem from the source (D8).
			Fixes: stampFixEcosystems(source, fixesFromDTO(dto.Fixes, dto.FixedVersions)),
		})
	case domain.KindExploitSignal:
		return domain.NewExploitSignalProposal(source, observedAt, domain.ExploitSignal{EPSS: dto.EPSS, KEV: dto.KEV, ExploitPublic: dto.ExploitPublic})
	case domain.KindApplicability:
		return domain.NewApplicabilityProposal(source, observedAt, domain.Applicability{Package: dto.Package, Status: dto.Status, Justification: dto.Justification})
	default:
		return domain.Proposal{}, fmt.Errorf("knowledge: unknown proposal kind %q", kind)
	}
}

// fixedVersionDTO persists a remediation with the package (and, since KN-FIX-3, the ecosystem)
// it applies to. Ecosystem is additive-optional: a row written before it decodes to "".
type fixedVersionDTO struct {
	Package   string `json:"package,omitempty"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

func fixesToDTO(fixes []domain.FixedVersion) []fixedVersionDTO {
	if len(fixes) == 0 {
		return nil
	}
	out := make([]fixedVersionDTO, 0, len(fixes))
	for _, f := range fixes {
		out = append(out, fixedVersionDTO{Package: f.Package, Version: f.Version, Ecosystem: f.Ecosystem})
	}
	return out
}

// fixesFromDTO decodes the attributed form, falling back to the legacy flat list as UNATTRIBUTED
// fixes. The fallback is what makes this migration-free: a card or Proposal written before
// KN-FIX-1 still loads, and its fixes degrade to "published, package unknown" — visible, but
// unable to decide about any component.
func fixesFromDTO(fixes []fixedVersionDTO, legacy []string) []domain.FixedVersion {
	if len(fixes) > 0 {
		out := make([]domain.FixedVersion, 0, len(fixes))
		for _, f := range fixes {
			out = append(out, domain.FixedVersion{Package: f.Package, Version: f.Version, Ecosystem: f.Ecosystem})
		}
		return out
	}
	if len(legacy) == 0 {
		return nil
	}
	out := make([]domain.FixedVersion, 0, len(legacy))
	for _, v := range legacy {
		out = append(out, domain.FixedVersion{Version: v})
	}
	return out
}

// sourceEcosystem is the decode-time healing table for the append-only history (EDR-VEX-01 D8).
// Proposals are immutable, so a fix persisted before Ecosystem existed can never be edited to
// carry one — but the SOURCE column was always stored, and these feeds each publish for exactly
// one ecosystem, so the ecosystem is derivable from provenance alone. Interpretation at the
// boundary, not mutation of the record: the stored bytes are untouched, and because the view is
// recomputed from all Proposals on every fold, every live card heals on its next enrichment with
// no migration. Multi-ecosystem sources (osv, nvd, scanners) are deliberately absent — for them
// only the per-record field the ACL now writes is evidence.
var sourceEcosystem = map[string]string{
	"redhat": "rpm",
	"alpine": "apk",
}

// stampFixEcosystems fills an EMPTY fix ecosystem from the proposal's source. A non-empty one is
// never overwritten — what the record states beats what provenance implies.
func stampFixEcosystems(source string, fixes []domain.FixedVersion) []domain.FixedVersion {
	eco, ok := sourceEcosystem[source]
	if !ok {
		return fixes
	}
	for i := range fixes {
		if fixes[i].Ecosystem == "" {
			fixes[i].Ecosystem = eco
		}
	}
	return fixes
}
