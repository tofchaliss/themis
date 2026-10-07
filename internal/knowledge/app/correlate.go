package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// InventoryComponent is one component of a release's canonical inventory, read from
// Evidence via its read API (never Evidence's tables — Book III §3.5).
type InventoryComponent struct {
	PURL      string
	Name      string
	Version   string
	Ecosystem string
	// Source is the upstream source-package name for distro (rpm) components (e.g. openssl-libs
	// -> openssl); "" for non-distro. Distro vuln databases key on the source package.
	Source string
}

// Inventory is the subset of Evidence's canonical inventory correlation needs.
type Inventory struct {
	Components []InventoryComponent
	// Owners maps an owned component's PURL to its owning component's PURL, from the SBOM's
	// explicit ownership relationships (Syft's ownership-by-file-overlap — the rpm whose file
	// list proves it installed the language package). Observed-grade bridge evidence
	// (EDR-VERDICT-01 D3); empty when the document carries no such edges — never inferred here.
	Owners map[string]string
}

// InventoryReader reads a release's inventory from Evidence's read API (D4). Knowledge
// keeps no copy — reads are transient, per correlation run.
type InventoryReader interface {
	GetInventory(ctx context.Context, evidenceID string) (Inventory, error)
}

// ProposalFor is a discovered source Proposal bound to a canonical CVE.
type ProposalFor struct {
	CVE      value.CVEID
	Proposal domain.Proposal
}

// PackageVulnSource is the lazy-discovery port (D5): given a component, it returns the
// source Proposals for the CVEs that affect that package (e.g. an OSV query-by-package
// client). Card population stays bounded by components the enterprise has actually seen.
type PackageVulnSource interface {
	VulnsForPackage(ctx context.Context, component InventoryComponent) ([]ProposalFor, error)
}

// Match is a release component that matched a Faultline.
type Match struct {
	ReleaseID   string
	FaultlineID domain.FaultlineID
	CVE         string
	Component   InventoryComponent
	Score       int // the card's composite score at match time (C6/BUG-3); rides the ComponentMatched event so Governance can stamp base_score at finding-open.
	// Priority and Fixes ride for the same reason as Score: a Finding opened after its card's
	// last enrichment would otherwise never receive a band or a fix list (BUG-3b).
	Priority string
	Fixes    []domain.FixedVersion
	// ClaimClass is why this component matched — carrier, scope, or unknown
	// (EDR-CORRELATION-01 D3). Decided here, where the card's carrier products are in hand.
	ClaimClass domain.ClaimClass
	// DetectionOrigin is which engine produced this match — `discovery` or `scanner/<name>`
	// (KN-SCAN-2). Provenance for display, never authority; see domain.MatchedComponent.
	DetectionOrigin string
	// Verdict is what judgeOccurrence concluded about this occurrence (EDR-VERDICT-01 D2):
	// recorded alongside the match, never a reason to drop it. A cleared occurrence is a
	// visible "checked and fine" row.
	Verdict domain.OccurrenceVerdict
	// CardVersion is the card version this occurrence was judged against (the D6 re-verdict
	// stamp); the catch-up sweep re-judges rows whose stamp is behind their card.
	CardVersion int
	OccurredAt  time.Time
}

// OriginDiscovery is the DetectionOrigin of every feed-correlation match, including the
// re-discovery sweep — both run through the same Correlate path, deliberately.
const OriginDiscovery = "discovery"

// MatchedOccurrence is a match already recorded for a card: which release, which component. It
// is enough to RE-ANNOUNCE that match when what the match MEANS changes.
type MatchedOccurrence struct {
	ReleaseID string
	Component InventoryComponent
}

// MatchReader lists the occurrences recorded against a card. It exists for one job: when carrier
// attribution arrives AFTER correlation (EDR-CORRELATION-01 D4 — NVD enriches on its own
// cadence), the classes stamped at match time are stale and nothing else would ever revisit them.
type MatchReader interface {
	MatchesForFaultline(ctx context.Context, faultlineID string) ([]MatchedOccurrence, error)
}

// MatchRecorder records matches idempotently and queues the ComponentMatched event; it
// also advances the matched card to the Correlated stage (D3/D7). It returns whether the
// match was new so a re-scan of the same occurrence emits no duplicate.
type MatchRecorder interface {
	RecordMatch(ctx context.Context, m Match) (bool, error)
}

// CorrelationService owns correlation (D3): it reads a release's inventory, discovers
// the vulnerabilities affecting each component, folds those source Proposals into the
// enterprise cards, and records a match per (release, faultline, component) — emitting
// ComponentMatched for Governance to open a Finding (EDR-GOVERNANCE-01 D5).
type CorrelationService struct {
	inventory InventoryReader
	discover  PackageVulnSource
	fold      *FaultlineService
	matches   MatchRecorder
	ledger    ReleaseLedger // optional: nil = no re-discovery ledger (KN-RECOR-1)
	// completed is optional (nil = the completion fact is not published). Production wiring
	// always sets it; without it a context that only correlates still works exactly as before,
	// which is the correct degradation for single-context dev and for the unit tests that
	// construct this service with no store.
	completed CorrelationAnnouncer
	clock     Clock
	// inferredBridge arms the D4 guess grade of the ownership bridge (default ON; the strict
	// estate disables it via THEMIS_VERDICT_INFERRED_BRIDGE=0 in the composition root).
	inferredBridge bool
}

// NewCorrelationService wires the correlation ports.
func NewCorrelationService(inv InventoryReader, disc PackageVulnSource, fold *FaultlineService, matches MatchRecorder, clock Clock) *CorrelationService {
	return &CorrelationService{inventory: inv, discover: disc, fold: fold, matches: matches, clock: clock, inferredBridge: true}
}

// WithInferredBridge sets the D4 switch (EDR-VERDICT-01) and returns the service for
// chaining. Kept out of the constructor so every existing call site is unaffected.
func (s *CorrelationService) WithInferredBridge(enabled bool) *CorrelationService {
	s.inferredBridge = enabled
	return s
}

// WithLedger adds the re-discovery ledger (KN-RECOR-1): every ApplyCorrelation then records
// which evidence it correlated and when, which is what the scheduled sweep drains. Separate
// from the constructor so existing call sites keep compiling; production wiring always sets it.
func (s *CorrelationService) WithLedger(l ReleaseLedger) *CorrelationService {
	s.ledger = l
	return s
}

// WithCompletion adds the per-SBOM completion announcer (EDR-DELIVERY-01 M2-1). Separate from
// the constructor for the same reason as the ledger: every existing call site keeps compiling,
// and production wiring always sets it.
func (s *CorrelationService) WithCompletion(a CorrelationAnnouncer) *CorrelationService {
	s.completed = a
	return s
}

// CorrelatedRelease is one ledger row: the release and the evidence its inventory came from.
type CorrelatedRelease struct {
	ReleaseID  string
	EvidenceID string
}

// ReleaseLedger remembers when discovery last ran per release (KN-RECOR-1). Upsert happens
// inside ApplyCorrelation's unit of work; StaleReleases feeds the re-discovery sweep.
type ReleaseLedger interface {
	UpsertCorrelatedRelease(ctx context.Context, releaseID, evidenceID string, at time.Time) error
	StaleReleases(ctx context.Context, olderThan time.Time, limit int) ([]CorrelatedRelease, error)
}

// CorrelationAnnouncer publishes the once-per-SBOM completion fact (EDR-DELIVERY-01 M2-1).
// It is a WRITE to the same unit of work the matches went into, never a network call: the
// implementation appends an outbox row, and the relay delivers it like every other Knowledge
// event. The port exists so ApplyCorrelation — which owns the end of the unit of work, and is
// therefore the only place that knows every other event for this SBOM has been queued — can
// append the completion LAST without knowing how an outbox row is written.
type CorrelationAnnouncer interface {
	// AnnounceCorrelationCompleted queues knowledge.release_correlation_completed.v1 for the
	// (release, sbom) pair, ordered after every other event already queued in this unit of work.
	AnnounceCorrelationCompleted(ctx context.Context, releaseID, sbomID, cause string, at time.Time) error
}

// PlannedMatch is one discovered (component, CVE, source Proposal) triple awaiting fold +
// record. It is the unit of a CorrelationPlan — pure data produced by the read phase and
// consumed by the write phase.
type PlannedMatch struct {
	Component InventoryComponent
	CVE       value.CVEID
	Proposal  domain.Proposal
}

// CorrelationPlan is the output of correlation's read phase (PlanCorrelation): every
// vulnerability discovered for a release's components, ready to fold and record. Building it
// performs ALL external I/O (Evidence inventory read + per-component discovery) so the write
// phase (ApplyCorrelation) touches no network and its transaction stays short — a long-open
// write transaction would pin the cluster xmin and starve the bus reader's gap-free watermark
// (EDR-EVENTBUS-01 D7). The read/write split is why the inbox runs Prepare outside its tx.
type CorrelationPlan struct {
	ReleaseID string
	// EvidenceID is the inventory the plan was built from — recorded on the re-discovery
	// ledger (KN-RECOR-1) so a later sweep re-reads the same (or a newer) inventory.
	EvidenceID string
	Items      []PlannedMatch
	// Cause is why this correlation ran — one of domain.CauseNewSBOM / domain.CauseRediscovery
	// (EDR-DELIVERY-01 M2-3). PlanCorrelation stamps the upload cause, which is what building a
	// plan from a fresh inventory means; the re-discovery sweep overrides it. It rides the plan
	// rather than the apply call because the read phase is where the reason is known.
	Cause string
	// Bridge is the ownership-bridge context judgeOccurrence needs at APPLY time
	// (EDR-VERDICT-01 D3): the sibling components of the same inventory plus its explicit
	// ownership edges. Captured in the read phase because the write phase does no I/O (D7).
	Bridge BridgeContext
}

// PlanCorrelation runs correlation's READ phase with NO transaction: it reads the release's
// inventory from Evidence and discovers the vulnerabilities affecting each component. Every
// network round-trip (the slow, rate-limited part) happens here, outside any unit of work.
// The returned plan is handed to ApplyCorrelation for the short write phase.
func (s *CorrelationService) PlanCorrelation(ctx context.Context, releaseID, evidenceID string) (CorrelationPlan, error) {
	inv, err := s.inventory.GetInventory(ctx, evidenceID)
	if err != nil {
		return CorrelationPlan{}, err
	}
	plan := CorrelationPlan{
		ReleaseID: releaseID, EvidenceID: evidenceID, Cause: domain.CauseNewSBOM,
		Bridge: BridgeContext{Siblings: inv.Components, Owners: inv.Owners, InferredBridge: s.inferredBridge},
	}
	for _, comp := range inv.Components {
		discovered, err := s.discover.VulnsForPackage(ctx, comp)
		if err != nil {
			return CorrelationPlan{}, err
		}
		for _, d := range discovered {
			plan.Items = append(plan.Items, PlannedMatch{Component: comp, CVE: d.CVE, Proposal: d.Proposal})
		}
	}
	return plan, nil
}

// ApplyCorrelation runs correlation's WRITE phase inside the caller's transaction (the inbox
// unit of work): for each planned match it folds the source Proposal onto the enterprise card
// and records a match. It performs NO network I/O, so the transaction stays short. Idempotent —
// FoldProposal converges and RecordMatch dedups, so a re-apply records no duplicate. Returns
// the number of new matches.
func (s *CorrelationService) ApplyCorrelation(ctx context.Context, plan CorrelationPlan) (int, error) {
	// The re-discovery ledger (KN-RECOR-1), stamped unconditionally — a release whose plan
	// held zero items still HAD its discovery run, and must not look eternally stale to the
	// sweep. In the same unit of work as the matches, so ledger and matches commit together.
	if s.ledger != nil && plan.EvidenceID != "" {
		if err := s.ledger.UpsertCorrelatedRelease(ctx, plan.ReleaseID, plan.EvidenceID, s.clock.Now()); err != nil {
			return 0, err
		}
	}
	newMatches := 0
	for _, item := range plan.Items {
		f, _, err := s.fold.FoldProposal(ctx, item.CVE, item.Proposal)
		if err != nil {
			return newMatches, err
		}
		// Apply Knowledge's OWN reconciled (backport-aware) affected-range knowledge (D3):
		// record a match unless the component's version is provably OUT of the reconciled
		// range. This catches the case discovery cannot — e.g. a distro backport whose
		// reconciled range excludes a version the feed's query-time filter admitted. An
		// undecidable verdict (no usable range yet, or an unparseable/absent version) KEEPS
		// the match: a parse gap must never drop a real vulnerability. This mirrors the
		// Intelligence Rule Engine, which short-circuits to not-affected only on out-of-range.
		affected := value.AffectedRange{Ecosystem: item.Component.Ecosystem, Groups: f.View().AffectedRanges}
		if affected.Applicability(item.Component.Version) == value.RangeOutOfRange {
			continue
		}
		// The occurrence verdict (EDR-VERDICT-01 D2): the vendor fixed-verdicts — the rpm
		// same-EL-stream rule (EDR-VEX-01 Phase 3) and the apk strict-bounds rule (D9) — run in
		// judgeOccurrence, shared with the scanner path. A cleared occurrence is RECORDED as
		// cleared, not dropped: "checked and fine" must be distinguishable from "never looked"
		// (the two were indistinguishable in the live KN-VERDICT-1 investigation), and a
		// recorded row is what a later re-judgement can revisit.
		created, err := s.matches.RecordMatch(ctx, Match{
			ReleaseID: plan.ReleaseID, FaultlineID: f.ID(), CVE: item.CVE.String(),
			Component: item.Component, Score: f.View().Score(),
			Priority: f.View().Priority(), Fixes: append([]domain.FixedVersion(nil), f.View().Fixes...),
			Verdict:     judgeOccurrence(f.View(), item.Component, plan.Bridge),
			CardVersion: f.Version(),
			// What this match MEANS, decided against the reconciled card (D3/D5). The match is
			// recorded either way — D2 keeps everything, because an old build inside a superseded
			// stream genuinely does need replacing. What changes is what a consumer may SAY about
			// it: a plan and the AI's grounding use carriers, the posture keeps the obligation.
			ClaimClass: domain.ClassifyClaim(
				f.View().CarrierProducts, componentPackage(item.Component), item.Component.Name),
			DetectionOrigin: OriginDiscovery,
			OccurredAt:      s.clock.Now(),
		})
		if err != nil {
			return newMatches, err
		}
		if created {
			newMatches++
		}
	}

	// The per-SBOM completion fact, appended LAST — after every fold note and every match note
	// this unit of work produced (EDR-DELIVERY-01 M2-1). Unconditional on the outcome: a plan
	// that held zero items, or whose every item fell out of the reconciled range, still
	// correlated this SBOM, and a consumer must be able to tell "evaluated, clean" from "not
	// evaluated yet". It is skipped only when there is no SBOM to name, which is the same guard
	// the ledger above uses.
	if s.completed != nil && plan.EvidenceID != "" {
		cause := plan.Cause
		if cause == "" {
			// A plan built before this field existed (a hand-constructed plan in a test) means an
			// upload: PlanCorrelation stamps the cause on every plan it builds, and the sweep is
			// the only path that overrides it.
			cause = domain.CauseNewSBOM
		}
		if !domain.ValidDiscoveryCause(cause) {
			return newMatches, fmt.Errorf("knowledge: unknown discovery cause %q", cause)
		}
		if err := s.completed.AnnounceCorrelationCompleted(ctx, plan.ReleaseID, plan.EvidenceID, cause, s.clock.Now()); err != nil {
			return newMatches, err
		}
	}
	return newMatches, nil
}

// Correlate runs the read and write phases back-to-back. It is retained for direct callers and
// tests that do not need the split; the event path uses PlanCorrelation + ApplyCorrelation so
// discovery I/O stays OUTSIDE the inbox transaction. Idempotent — a re-run converges and
// records no duplicate matches. Returns the number of new matches.
func (s *CorrelationService) Correlate(ctx context.Context, releaseID, evidenceID string) (int, error) {
	return s.CorrelateCause(ctx, releaseID, evidenceID, domain.CauseNewSBOM)
}

// CorrelateCause is Correlate with the discovery cause stated explicitly (EDR-DELIVERY-01
// M2-3). The re-discovery sweep is its reason to exist: the sweep re-runs exactly this
// machinery, and the only thing that differs is WHY — which is carried in the completion event
// so no consumer has to infer it.
func (s *CorrelationService) CorrelateCause(ctx context.Context, releaseID, evidenceID, cause string) (int, error) {
	plan, err := s.PlanCorrelation(ctx, releaseID, evidenceID)
	if err != nil {
		return 0, err
	}
	plan.Cause = cause
	return s.ApplyCorrelation(ctx, plan)
}

// componentPackage is the name a vulnerability database knows a component by. Distro databases
// key on the SOURCE package (openssl-libs is fixed by the openssl advisory), so that wins when
// present; everything else uses the component's own name.
//
// It must agree with what the feed ACLs record as a fix's package, or FixesFor silently matches
// nothing and the fixed-verdict quietly stops working — a failure that looks like extra findings
// rather than like a bug.
func componentPackage(c InventoryComponent) string {
	if s := strings.TrimSpace(c.Source); s != "" {
		return s
	}
	return strings.TrimSpace(c.Name)
}
