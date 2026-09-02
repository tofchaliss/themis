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
	// Origin is the match's DetectionOrigin — `scanner/<name>` from the record's `scanner`
	// field, bare `scanner` when the report names no engine (KN-SCAN-2). It is provenance,
	// not the proposal source: the source stays the closed-vocabulary `scanner` so the
	// trust/precedence tables remain enumerable (TRUST-2).
	Origin string
}

// ScannerReportSource reads a release's scanner-report findings from Evidence and
// translates them to bound Proposals (EDR-KNOWLEDGE-01 D5/D6). The concrete adapter is an
// Evidence read-API client for the `scanner-report` kind + the scanner ACL (KN-SCAN-1).
//
// skipped counts findings the translation could not use (malformed record, no canonical
// CVE). They are counted rather than fatal because one bad finding must not void a
// 400-finding report — and counted rather than silent because "we ingested the report"
// and "we ingested most of the report" must not look alike in the log line.
type ScannerReportSource interface {
	ScannerProposals(ctx context.Context, evidenceID string) (props []ScannerProposal, skipped int, err error)
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

// ScannerPlan is the read phase's output: every usable finding of one report, ready to fold
// and record, plus how many findings were skipped in translation.
type ScannerPlan struct {
	ReleaseID string
	Items     []ScannerProposal
	Skipped   int
}

// PlanIngest runs the READ phase with no transaction: fetch the report document from
// Evidence and translate its findings. All network I/O happens here, outside the inbox
// transaction — the same D7 read/write split correlation and VEX use, so the write
// transaction never pins the cluster xmin and stalls the bus reader.
func (s *ScannerReportService) PlanIngest(ctx context.Context, releaseID, evidenceID string) (ScannerPlan, error) {
	props, skipped, err := s.source.ScannerProposals(ctx, evidenceID)
	if err != nil {
		return ScannerPlan{}, err
	}
	return ScannerPlan{ReleaseID: releaseID, Items: props, Skipped: skipped}, nil
}

// ApplyIngest runs the WRITE phase inside the caller's transaction: fold every finding and
// record its match. Idempotent — a re-run re-folds Proposals (which converge
// deterministically; verbatim restatements are dropped) and records no duplicate match.
// Returns the number of new matches.
//
// Every occurrence is judged through the same seam correlation uses before it is recorded
// (EDR-VERDICT-01 D2) — a scanner is version-matched against the FILES, but backports live in
// the build release a scanner cannot see, so "the scanner already matched it" was never a
// reason to skip the vendor fixed-verdict. Only the reconciled-range gate stays
// correlation-only: a range-rejected candidate was never a match, while a scanner's finding is.
func (s *ScannerReportService) ApplyIngest(ctx context.Context, plan ScannerPlan) (int, error) {
	newMatches := 0
	for _, p := range plan.Items {
		f, _, err := s.fold.FoldProposal(ctx, p.CVE, p.Proposal)
		if err != nil {
			return newMatches, err
		}
		created, err := s.matches.RecordMatch(ctx, Match{
			ReleaseID: plan.ReleaseID, FaultlineID: f.ID(), CVE: p.CVE.String(),
			Component: p.Component, Score: f.View().Score(), Priority: f.View().Priority(),
			Fixes: append([]domain.FixedVersion(nil), f.View().Fixes...),
			// The occurrence verdict (EDR-VERDICT-01 D2), through the SAME seam correlation
			// uses. The old premise — "a scanner report is already version-matched, so record
			// as-is" — is exactly false for backports, which a scanner reading .egg-info cannot
			// see; the KN-VERDICT-1 link-(b) defect was this path recording unjudged rows. The
			// reconciled-range gate stays correlation-only (a range-rejected candidate was never
			// a match; a scanner's version-matched finding is).
			Verdict:     judgeOccurrence(f.View(), p.Component),
			CardVersion: f.Version(),
			// Why this component matched, decided against the reconciled card exactly as the
			// discovery path decides it (EDR-CORRELATION-01 D3): a scanner names the component
			// it scanned, but whether that component CARRIES the flaw is the card's knowledge,
			// not the scanner's.
			ClaimClass: domain.ClassifyClaim(
				f.View().CarrierProducts, componentPackage(p.Component), p.Component.Name),
			DetectionOrigin: p.Origin,
			OccurredAt:      s.clock.Now(),
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

// Ingest runs both phases back-to-back — the direct (non-inbox) entry point; the event path
// uses PlanIngest + ApplyIngest so document I/O stays outside the inbox transaction.
func (s *ScannerReportService) Ingest(ctx context.Context, releaseID, evidenceID string) (int, error) {
	plan, err := s.PlanIngest(ctx, releaseID, evidenceID)
	if err != nil {
		return 0, err
	}
	return s.ApplyIngest(ctx, plan)
}
