package app

import (
	"context"
	"errors"
	"time"

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
	// sboms is the KN-SCAN-RACE-1 fallback: the release's filed SBOM read straight from
	// Evidence, for the window between the SBOM's upload and the end of its correlation.
	sboms ReleaseSBOMSource
	// facts resolves an evidence id to its release, for the on-demand unresolved query.
	facts EvidenceFactsSource
	// report receives the per-ingest outcome counts. The app ring never logs (CONVENTIONS R1),
	// so the counts leave through a port an adapter owns. Optional; nil = no reporting.
	report IngestReporter
	// corr runs discovery for the report's components that no SBOM names (KN-SCAN-5). Nil ⇒
	// the scanner's own claims are the only intelligence recorded, which is the pre-KN-SCAN-5
	// behaviour: those matches can never learn a vendor fix and never clear.
	corr *CorrelationService
	// occurrences is the release's recorded component set, the re-discovery input.
	occurrences ReleaseOccurrenceSource
	// scanLedger marks a scanner-only release as discovered so the sweep revisits it.
	scanLedger ScannerReleaseLedger
}

// ScannerReleaseLedger is the re-discovery ledger's scanner-only half (KN-SCAN-5): a release
// correlation never ran for has no ledger row and would never be swept. TouchScannerRelease
// creates the row with no evidence id (there is no SBOM to re-read) and only if none exists, so
// an SBOM's row is never overwritten; StampDiscovered moves last_discovered_at after a sweep.
type ScannerReleaseLedger interface {
	TouchScannerRelease(ctx context.Context, releaseID string, at time.Time) error
	StampDiscovered(ctx context.Context, releaseID string, at time.Time) error
	// BackfillScannerReleases rows every release that has matches but no ledger row, dated `at`,
	// so releases that predate KN-SCAN-5 join the sweep on their own (KN-SCAN-5b).
	BackfillScannerReleases(ctx context.Context, at time.Time) (int, error)
}

// EvidenceFactsSource resolves an evidence id to its kind and subject release
// (EDR-IDENTITY-01 D6). Optional; without it the unresolved query cannot run, which it reports
// honestly rather than answering "none".
type EvidenceFactsSource interface {
	EvidenceFacts(ctx context.Context, evidenceID string) (kind, releaseID string, found bool, err error)
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

// ReleaseSBOMSource resolves a release to its most recently FILED SBOM, read from Evidence
// itself rather than from the correlation ledger (KN-SCAN-RACE-1). found=false means no SBOM
// was ever filed for the release (a scanner-only release).
type ReleaseSBOMSource interface {
	SBOMForRelease(ctx context.Context, releaseID string) (evidenceID string, found bool, err error)
}

// WithReleaseSBOMs wires the Evidence-side fallback for the identity candidate set
// (KN-SCAN-RACE-1). The ledger answers only once the SBOM's correlation has COMPLETED, and a
// full-host SBOM correlates for ~14 minutes (measured 2026-10-27, 1249 packages) — so a scanner
// report uploaded a minute after its SBOM found no candidates at all, every purl-less finding
// abstained as `no_candidate`, and nothing was recorded. Evidence has the SBOM from the moment
// it is filed; that is the authority on what the release contains, correlated or not.
func (s *ScannerReportService) WithReleaseSBOMs(src ReleaseSBOMSource) *ScannerReportService {
	s.sboms = src
	return s
}

// WithIngestReporter wires the per-ingest outcome reporter (D6).
func (s *ScannerReportService) WithIngestReporter(r IngestReporter) *ScannerReportService {
	s.report = r
	return s
}

// WithEvidenceFacts wires the evidence-facts read used by the unresolved-components query (D6).
// WithDiscovery turns on feed discovery for the components only the scanner named (KN-SCAN-5):
// at ingest, and again from the re-discovery sweep over the release's recorded occurrences.
func (s *ScannerReportService) WithDiscovery(corr *CorrelationService, occurrences ReleaseOccurrenceSource, ledger ScannerReleaseLedger) *ScannerReportService {
	s.corr, s.occurrences, s.scanLedger = corr, occurrences, ledger
	return s
}

func (s *ScannerReportService) WithEvidenceFacts(f EvidenceFactsSource) *ScannerReportService {
	s.facts = f
	return s
}

// ErrNotScannerReport is returned when the queried document is not a scanner report, so it
// carries no observations to resolve.
var ErrNotScannerReport = errors.New("knowledge: evidence is not a scanner report")

// ErrNoSuchEvidence is returned for an unknown evidence id.
var ErrNoSuchEvidence = errors.New("knowledge: no such evidence")

// UnresolvedReport is the on-demand answer to "which components did this report NAME but not
// IDENTIFY?" (EDR-IDENTITY-01 D6).
type UnresolvedReport struct {
	EvidenceID string
	ReleaseID  string
	Resolved   int
	Unresolved []UnresolvedObservation
}

// UnresolvedComponents recomputes the unresolved population for one scanner report.
//
// RECOMPUTED, not stored, and that is a design decision rather than a shortcut (D5): the
// observed identifier deliberately never enters a Knowledge row, because the report's bytes are
// immutable in Evidence and duplicating them would have Knowledge owning a copy of evidence it
// does not own. So this reads the document and the release inventory back through
// PlanIngest — the SAME code path the ingest uses — which means the answer cannot drift from
// the behaviour it describes. A stored count could; that is exactly how the GOV-MIRROR-1
// divergence happened.
//
// Writes nothing. PlanIngest is the read phase; the write phase is not called.
func (s *ScannerReportService) UnresolvedComponents(ctx context.Context, evidenceID string) (UnresolvedReport, error) {
	if s.facts == nil {
		return UnresolvedReport{}, errors.New("knowledge: evidence facts source not wired")
	}
	kind, releaseID, found, err := s.facts.EvidenceFacts(ctx, evidenceID)
	if err != nil {
		return UnresolvedReport{}, err
	}
	if !found {
		return UnresolvedReport{}, ErrNoSuchEvidence
	}
	if kind != "scanner-report" {
		return UnresolvedReport{}, ErrNotScannerReport
	}
	plan, err := s.PlanIngest(ctx, releaseID, evidenceID)
	if err != nil {
		return UnresolvedReport{}, err
	}
	return UnresolvedReport{
		EvidenceID: evidenceID, ReleaseID: releaseID,
		Resolved: len(plan.Items), Unresolved: plan.Unresolved,
	}, nil
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
//
// The ledger is asked first — it is local and names the inventory correlation actually used.
// When it has no row yet, the SBOM is read from Evidence (KN-SCAN-RACE-1): a report that
// arrives while its SBOM is still correlating must resolve against the SBOM, not against
// nothing. Only a release with NO filed SBOM is a scanner-only release.
func (s *ScannerReportService) releaseCandidates(ctx context.Context, releaseID string) []InventoryComponent {
	if s.inventory == nil {
		return nil
	}
	evidenceID, found := s.releaseEvidence(ctx, releaseID)
	if !found {
		return nil
	}
	inv, err := s.inventory.GetInventory(ctx, evidenceID)
	if err != nil {
		return nil
	}
	return inv.Components
}

// releaseEvidence names the SBOM document the candidate set is read from: the ledger's
// correlated evidence when there is one, else the release's latest filed SBOM.
func (s *ScannerReportService) releaseEvidence(ctx context.Context, releaseID string) (string, bool) {
	if s.ledger != nil {
		if evidenceID, found, err := s.ledger.EvidenceForRelease(ctx, releaseID); err == nil && found {
			return evidenceID, true
		}
	}
	if s.sboms != nil {
		if evidenceID, found, err := s.sboms.SBOMForRelease(ctx, releaseID); err == nil && found {
			return evidenceID, true
		}
	}
	return "", false
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
	newMatches, err := s.applyClaims(ctx, plan)
	if err != nil {
		return newMatches, err
	}
	// KN-SCAN-5: the components only this report named get the same discovery an SBOM
	// component gets, so their cards learn the vendor's fixed builds and the verdict path can
	// clear them. A discovery failure is swallowed here, not fatal: the scanner's claims above
	// are already recorded and a feed outage must not roll them back; the sweep retries.
	if s.corr != nil {
		siblings := s.releaseCandidates(ctx, plan.ReleaseID)
		only := scannerOnlyComponents(plan.Items, siblings)
		if n, derr := s.corr.DiscoverComponents(ctx, plan.ReleaseID, only, siblings); derr == nil {
			newMatches += n
		}
		if s.scanLedger != nil {
			_ = s.scanLedger.TouchScannerRelease(ctx, plan.ReleaseID, s.clock.Now())
		}
	}
	return newMatches, nil
}

// RediscoverComponents re-runs discovery for the components recorded on a release that no SBOM
// inventory names (KN-SCAN-5): the scanner-only set. The re-discovery sweep calls it beside the
// SBOM re-correlation, so a CVE published after the scan reaches a scanner-only component too,
// and a card that has since learned the vendor fix re-judges the occurrence.
func (s *ScannerReportService) RediscoverComponents(ctx context.Context, releaseID string) (int, error) {
	if s.corr == nil || s.occurrences == nil {
		return 0, nil
	}
	recorded, err := s.occurrences.MatchComponentsForRelease(ctx, releaseID)
	if err != nil {
		return 0, err
	}
	siblings := s.releaseCandidates(ctx, releaseID)
	only := scannerOnlyComponents(componentsAsClaims(recorded), siblings)
	return s.corr.DiscoverComponents(ctx, releaseID, only, siblings)
}

// scannerOnlyComponents returns the distinct usable components among items that no SBOM
// sibling names by purl — the ones discovery has never been run for.
func scannerOnlyComponents(items []ScannerProposal, siblings []InventoryComponent) []InventoryComponent {
	inSBOM := make(map[string]struct{}, len(siblings))
	for _, sib := range siblings {
		inSBOM[sib.PURL] = struct{}{}
	}
	seen := map[string]struct{}{}
	var out []InventoryComponent
	for _, it := range items {
		c := it.Component
		if !UsablePURL(c.PURL) {
			continue
		}
		if _, ok := inSBOM[c.PURL]; ok {
			continue
		}
		if _, dup := seen[c.PURL]; dup {
			continue
		}
		seen[c.PURL] = struct{}{}
		out = append(out, c)
	}
	return out
}

func componentsAsClaims(comps []InventoryComponent) []ScannerProposal {
	out := make([]ScannerProposal, 0, len(comps))
	for _, c := range comps {
		out = append(out, ScannerProposal{Component: c})
	}
	return out
}

func (s *ScannerReportService) applyClaims(ctx context.Context, plan ScannerPlan) (int, error) {
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
