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
	Severity        string             `json:"severity"`
	CVSSScore       float64            `json:"cvss_score"`
	CVSSVector      string             `json:"cvss_vector"`
	SeveritySource  string             `json:"severity_source"`
	AffectedRanges  []string           `json:"affected_ranges"`
	FixedVersions   []string           `json:"fixed_versions"`
	EPSS            float64            `json:"epss"`
	KEV             bool               `json:"kev"`
	ExploitPublic   bool               `json:"exploit_public"`
	Applicabilities []applicabilityDTO `json:"applicabilities"`
}

type applicabilityDTO struct {
	Package       string `json:"package"`
	Status        string `json:"status"`
	Justification string `json:"justification"`
}

func marshalView(v domain.EnterpriseView) ([]byte, error) {
	dto := viewDTO{
		Severity: string(v.Severity), CVSSScore: v.CVSS.Score(), CVSSVector: v.CVSS.Vector(),
		SeveritySource: v.SeveritySource, AffectedRanges: v.AffectedRanges, FixedVersions: v.FixedVersions,
		EPSS: v.EPSS, KEV: v.KEV, ExploitPublic: v.ExploitPublic,
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
		AffectedRanges: dto.AffectedRanges, FixedVersions: dto.FixedVersions,
		EPSS: dto.EPSS, KEV: dto.KEV, ExploitPublic: dto.ExploitPublic,
	}
	for _, a := range dto.Applicabilities {
		v.Applicabilities = append(v.Applicabilities, domain.Applicability{Package: a.Package, Status: a.Status, Justification: a.Justification})
	}
	return v, nil
}

// proposalPayloadDTO is the persisted (jsonb) shape of a Proposal's kind-specific
// payload (source/observed-at/kind live in their own columns).
type proposalPayloadDTO struct {
	Severity       string   `json:"severity,omitempty"`
	CVSSScore      float64  `json:"cvss_score,omitempty"`
	CVSSVector     string   `json:"cvss_vector,omitempty"`
	AffectedRanges []string `json:"affected_ranges,omitempty"`
	FixedVersions  []string `json:"fixed_versions,omitempty"`
	EPSS           float64  `json:"epss,omitempty"`
	KEV            bool     `json:"kev,omitempty"`
	ExploitPublic  bool     `json:"exploit_public,omitempty"`
	Package        string   `json:"package,omitempty"`
	Status         string   `json:"status,omitempty"`
	Justification  string   `json:"justification,omitempty"`
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
		dto.FixedVersions = f.FixedVersions
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
			Severity: value.Severity(dto.Severity), CVSS: cvss, AffectedRanges: dto.AffectedRanges, FixedVersions: dto.FixedVersions,
		})
	case domain.KindExploitSignal:
		return domain.NewExploitSignalProposal(source, observedAt, domain.ExploitSignal{EPSS: dto.EPSS, KEV: dto.KEV, ExploitPublic: dto.ExploitPublic})
	case domain.KindApplicability:
		return domain.NewApplicabilityProposal(source, observedAt, domain.Applicability{Package: dto.Package, Status: dto.Status, Justification: dto.Justification})
	default:
		return domain.Proposal{}, fmt.Errorf("knowledge: unknown proposal kind %q", kind)
	}
}
