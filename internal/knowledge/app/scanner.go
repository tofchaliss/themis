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
	// inferredBridge arms the D4 guess grade of the ownership bridge (default ON), exactly as
	// on CorrelationService — one switch, one meaning, both doors.
	inferredBridge bool
	// ledger + inventory supply the identity candidate set (EDR-IDENTITY-01 D2). Both optional
	// (nil = the report is the only candidate source), because a single-context dev node has no
	// Evidence to read and must still ingest. Missing evidence narrows the candidates and
	// therefore ABSTAINS — it never synthesizes an identity.
	ledger    ReleaseEvidenceSource
	inventory InventoryReader
	// report receives the per-ingest outcome counts. The app ring never logs (CONVENTIONS R1),
	// so the counts leave through a port an adapter owns. Optional; nil = no reporting.
	report IngestReporter
}

// IngestReporter receives the outcome of one scanner-report ingest (EDR-IDENTITY-01 D6).
//
// It exists because the app ring never logs and the unresolved population must still reach an
// operator: a correct answer nobody can see is indistinguishable from a wrong one, which is the
// lesson the 2026-09-16 session paid for. `skipped` was ALREADY computed and never surfaced
// anywhere (KN-SCAN-OBS-1) — this is where that closes too.
type IngestReporter interface {
	ScannerIngest(releaseID, evidenceID string, recorded, items, skipped, unresolved int)
}

// NewScannerReportService wires the scanner-report ingestion ports.
func NewScannerReportService(src ScannerReportSource, fold *FaultlineService, matches MatchRecorder, clock Clock) *ScannerReportService {
	return &ScannerReportService{source: src, fold: fold, matches: matches, clock: clock, inferredBridge: true}
}

// WithIdentityCandidates wires the release-inventory read used to resolve a purl-less
// observation onto its twin (EDR-IDENTITY-01 D2). These are the SAME two ports
// ReverdictService.bridgeFor uses — a read, not a new seam.
//
// Kept off the constructor so every existing caller is unaffected: without it the candidate set
// is the report alone, which is the correct degradation rather than a missing feature.
func (s *ScannerReportService) WithIdentityCandidates(ledger ReleaseEvidenceSource, inv InventoryReader) *ScannerReportService {
	s.ledger, s.inventory = ledger, inv
	return s
}

// WithIngestReporter wires the per-ingest outcome reporter (D6).
func (s *ScannerReportService) WithIngestReporter(r IngestReporter) *ScannerReportService {
	s.report = r
	return s
}

// WithInferredBridge sets the D4 switch (EDR-VERDICT-01) and returns the service for chaining.
func (s *ScannerReportService) WithInferredBridge(enabled bool) *ScannerReportService {
	s.inferredBridge = enabled
	return s
}

// ScannerPlan is the read phase's output: every usable finding of one report, ready to fold
// and record, plus how many findings were skipped in translation.
type ScannerPlan struct {
	ReleaseID string
	Items     []ScannerProposal
	Skipped   int
	// Bridge is the ownership-bridge context (EDR-VERDICT-01 D3) built from the report's OWN
	// component set: a scanner that catalogued the image's rpm database and its site-packages
	// put both in one report, so the report itself is the same-inventory candidate set. Scanner
	// reports carry no explicit ownership edges — only the Inferred hop can bridge here.
	Bridge BridgeContext
	// Unresolved are observations that named a component whose identity could not be
	// established (EDR-IDENTITY-01 D2/D6). A SEPARATE POPULATION, not a filtered-out one —
	// that distinction is what makes them countable at all. No match row is written for them,
	// which is also why no `component_purl = ''` row can exist any more.
	Unresolved []UnresolvedObservation
	// EvidenceID rides along so the ingest report can name the document it read.
	EvidenceID string
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
	siblings := make([]InventoryComponent, 0, len(props))
	seen := map[string]struct{}{}
	for _, p := range props {
		key := p.Component.PURL + "|" + p.Component.Name + "@" + p.Component.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		siblings = append(siblings, p.Component)
	}

	// Identity resolution (EDR-IDENTITY-01 D2). The candidate set is the release's canonical
	// inventory PLUS the report's own usable components: the inventory is the authority on what
	// the release contains and is where the measured twin lives, while the report's own entries
	// are observations of the same release and the measured document shows twins can travel
	// together. Disagreement between the two is AMBIGUITY, which abstains — no tie-break is
	// invented, because that is exactly the case where a guess would be wrong.
	candidates := append(s.releaseCandidates(ctx, releaseID), siblings...)
	items := make([]ScannerProposal, 0, len(props))
	var unresolved []UnresolvedObservation
	for _, p := range props {
		if UsablePURL(p.Component.PURL) {
			items = append(items, p)
			continue
		}
		purl, reason := ResolveIdentity(p.Component, candidates)
		if reason != "" {
			unresolved = append(unresolved, UnresolvedObservation{
				RawPURL: p.Component.PURL, Name: p.Component.Name, Version: p.Component.Version,
				Ecosystem: p.Component.Ecosystem, Origin: p.Origin, Reason: reason,
			})
			continue
		}
		// A second representation of a component already on the release, not a new subject.
		// It lands on the twin's purl and collapses under the existing primary key; the
		// KN-SCAN-4a overlay already treats a repeat as a new observation of one occurrence.
		p.Component.PURL = purl
		items = append(items, p)
	}

	return ScannerPlan{
		ReleaseID: releaseID, EvidenceID: evidenceID, Items: items, Skipped: skipped,
		Unresolved: unresolved,
		Bridge:     BridgeContext{Siblings: siblings, InferredBridge: s.inferredBridge},
	}, nil
}

// releaseCandidates reads the release's canonical inventory — the authoritative candidate set
// for identity resolution. Returns nil when the ports are unwired (single-context dev), when
// the release never went through correlation (a scanner-ONLY release, which has no SBOM and
// therefore never a twin), or when the inventory read fails.
//
// Every one of those narrows the candidates and so tends toward ABSTENTION, never toward a
// synthesized identity. It is the same rule the D6 re-verdict sweep applies per release: a
// poorer context must never be stamped as an answer.
func (s *ScannerReportService) releaseCandidates(ctx context.Context, releaseID string) []InventoryComponent {
	if s.ledger == nil || s.inventory == nil {
		return nil
	}
	evidenceID, found, err := s.ledger.EvidenceForRelease(ctx, releaseID)
	if err != nil || !found {
		return nil
	}
	inv, err := s.inventory.GetInventory(ctx, evidenceID)
	if err != nil {
		return nil
	}
	return inv.Components
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
			Verdict:     judgeOccurrence(f.View(), p.Component, plan.Bridge),
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
	// One report per ingest, on EVERY ingest including a fully-resolved one with nothing
	// skipped (EDR-IDENTITY-01 D6). "Nothing unresolved" and "the resolver stopped running"
	// must not look alike — the same rule the feed watches and both sweeps follow.
	//
	// Reported from the WRITE phase, not the read phase: the counts describe an ingest that
	// actually happened. A plan built and never applied has ingested nothing, and saying
	// otherwise is the kind of log line that makes a stalled pipeline look healthy.
	if s.report != nil {
		s.report.ScannerIngest(plan.ReleaseID, plan.EvidenceID,
			newMatches, len(plan.Items), plan.Skipped, len(plan.Unresolved))
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
