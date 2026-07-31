package app

import (
	"context"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// VEXStatement is one applicability statement parsed from a VEX document (adapter-produced):
// a vendor's status for a (CVE, package) pair.
type VEXStatement struct {
	CVE           string
	Package       string
	Status        string
	Justification string
}

// DocumentReader reads a raw evidence document (bytes + kind) from Evidence's read API (D6).
type DocumentReader interface {
	GetDocument(ctx context.Context, evidenceID string) (raw []byte, kind string, err error)
}

// VEXParser translates a raw VEX document into applicability statements (an ACL — OpenVEX).
type VEXParser interface {
	Parse(raw []byte) ([]VEXStatement, error)
}

// VEXApplicabilityService applies an uploaded VEX document to the cards (EDR-VEX-01 D2): it
// reads the document from Evidence, parses it, and folds one `applicability` Proposal per
// statement onto the Faultline for its CVE. The card only carries the statement — whether to
// honor a not_affected for a release is Governance's decision (Proposal Before Truth).
type VEXApplicabilityService struct {
	docs   DocumentReader
	parser VEXParser
	fold   *FaultlineService
	clock  Clock
}

// NewVEXApplicabilityService wires the VEX-apply flow.
func NewVEXApplicabilityService(docs DocumentReader, parser VEXParser, fold *FaultlineService, clock Clock) *VEXApplicabilityService {
	return &VEXApplicabilityService{docs: docs, parser: parser, fold: fold, clock: clock}
}

// Apply reads a VEX evidence document and folds its applicability statements onto the cards.
// It is idempotent: re-folding an applicability Proposal converges. Individual malformed
// statements (bad CVE id / missing package or status) are skipped, not fatal.
func (s *VEXApplicabilityService) Apply(ctx context.Context, evidenceID string) error {
	raw, _, err := s.docs.GetDocument(ctx, evidenceID)
	if err != nil {
		return err
	}
	stmts, err := s.parser.Parse(raw)
	if err != nil {
		return err
	}
	now := s.clock.Now()
	for _, st := range stmts {
		cve, err := value.NewCVEID(st.CVE)
		if err != nil {
			continue // skip an unparseable CVE id
		}
		p, err := domain.NewApplicabilityProposal("vex", now, domain.Applicability{
			Package: st.Package, Status: st.Status, Justification: st.Justification,
		})
		if err != nil {
			continue // skip an invalid statement (missing package/status)
		}
		if _, err := s.fold.FoldProposal(ctx, cve, p); err != nil {
			return err
		}
	}
	return nil
}
