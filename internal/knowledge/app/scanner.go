package app

import (
	"context"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// ScannerProposal is one scanner-report finding translated to a bound Proposal, plus the
// component it names — everything ScannerReportService needs to fold the fact into a card
// and record a match.
type ScannerProposal struct {
	CVE       value.CVEID
	Proposal  domain.Proposal
	Component InventoryComponent
}

// ScannerReportSource reads a release's scanner-report findings from Evidence and
// translates them to bound Proposals (EDR-KNOWLEDGE-01 D5/D6). The concrete adapter — an
// Evidence read-API client for the `scanner-report` kind + the scanner ACL — is the
// documented **prerequisite**; this port keeps ScannerReportService testable now and
// swappable later, exactly as M7 did for the discovery/watch sources.
type ScannerReportSource interface {
	ScannerProposals(ctx context.Context, evidenceID string) ([]ScannerProposal, error)
}

// ScannerReportService folds a scanner report's findings into the enterprise cards as
// advisory source Proposals and records a match per finding — mirroring CorrelationService,
// but sourced from a scanner instead of package discovery. A scanner **never sets truth**:
// each finding is a Proposal reconciled with no special authority (D2 / CON-0002), and the
// match emits ComponentMatched so Governance opens/updates a Finding downstream.
type ScannerReportService struct {
	source  ScannerReportSource
	fold    *FaultlineService
	matches MatchRecorder
	clock   Clock
}

// NewScannerReportService wires the scanner-report ingestion ports.
func NewScannerReportService(src ScannerReportSource, fold *FaultlineService, matches MatchRecorder, clock Clock) *ScannerReportService {
	return &ScannerReportService{source: src, fold: fold, matches: matches, clock: clock}
}

// Ingest folds every finding of one scanner report and records its matches. Idempotent — a
// re-run re-folds Proposals (which converge deterministically) and records no duplicate
// match. Returns the number of new matches.
func (s *ScannerReportService) Ingest(ctx context.Context, releaseID, evidenceID string) (int, error) {
	props, err := s.source.ScannerProposals(ctx, evidenceID)
	if err != nil {
		return 0, err
	}
	newMatches := 0
	for _, p := range props {
		faultlineID, err := s.fold.FoldProposal(ctx, p.CVE, p.Proposal)
		if err != nil {
			return newMatches, err
		}
		created, err := s.matches.RecordMatch(ctx, Match{
			ReleaseID: releaseID, FaultlineID: faultlineID, CVE: p.CVE.String(),
			Component: p.Component, OccurredAt: s.clock.Now(),
		})
		if err != nil {
			return newMatches, err
		}
		if created {
			newMatches++
		}
	}
	return newMatches, nil
}
