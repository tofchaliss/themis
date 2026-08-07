package app

import (
	"context"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// VEXDocumentSource is the source id recorded on Proposals distilled from an OPERATOR-UPLOADED
// VEX document. It is the one Knowledge source that is not a feed ACL, so it is named here
// rather than discovered from the feed registry — and it must appear in the shipped-source
// enumeration the trust-classification guard walks (TRUST-2), or it could ship unclassified.
const VEXDocumentSource = "vex"

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

// PlannedApplicability is one VEX applicability Proposal bound to its CVE — produced by the
// read phase (PlanVEX) and folded by the write phase (ApplyVEX).
type PlannedApplicability struct {
	CVE      value.CVEID
	Proposal domain.Proposal
}

// VEXPlan is the output of the VEX read phase (PlanVEX): the applicability Proposals parsed
// from an uploaded VEX document, ready to fold. Building it does the external document read +
// parse so the write phase (ApplyVEX) touches no network and its transaction stays short — a
// long-open write transaction would pin the cluster xmin and stall the bus reader (D7).
type VEXPlan struct {
	Items []PlannedApplicability
}

// PlanVEX runs the VEX READ phase with NO transaction: it reads the document from Evidence,
// parses it, and builds one applicability Proposal per statement. Individual malformed
// statements (bad CVE id / missing package or status) are skipped, not fatal.
func (s *VEXApplicabilityService) PlanVEX(ctx context.Context, evidenceID string) (VEXPlan, error) {
	raw, _, err := s.docs.GetDocument(ctx, evidenceID)
	if err != nil {
		return VEXPlan{}, err
	}
	stmts, err := s.parser.Parse(raw)
	if err != nil {
		return VEXPlan{}, err
	}
	now := s.clock.Now()
	var plan VEXPlan
	for _, st := range stmts {
		cve, err := value.NewCVEID(st.CVE)
		if err != nil {
			continue // skip an unparseable CVE id
		}
		p, err := domain.NewApplicabilityProposal(VEXDocumentSource, now, domain.Applicability{
			Package: st.Package, Status: st.Status, Justification: st.Justification,
		})
		if err != nil {
			continue // skip an invalid statement (missing package/status)
		}
		plan.Items = append(plan.Items, PlannedApplicability{CVE: cve, Proposal: p})
	}
	return plan, nil
}

// ApplyVEX runs the VEX WRITE phase inside the caller's transaction: it folds each planned
// applicability Proposal onto the Faultline for its CVE. No network I/O. Idempotent —
// re-folding an applicability Proposal converges.
func (s *VEXApplicabilityService) ApplyVEX(ctx context.Context, plan VEXPlan) error {
	for _, item := range plan.Items {
		if _, _, err := s.fold.FoldProposal(ctx, item.CVE, item.Proposal); err != nil {
			return err
		}
	}
	return nil
}

// Apply reads a VEX evidence document and folds its applicability statements onto the cards.
// It runs the read and write phases back-to-back; the event path uses PlanVEX + ApplyVEX so
// the document read stays OUTSIDE the inbox transaction. Idempotent.
func (s *VEXApplicabilityService) Apply(ctx context.Context, evidenceID string) error {
	plan, err := s.PlanVEX(ctx, evidenceID)
	if err != nil {
		return err
	}
	return s.ApplyVEX(ctx, plan)
}
