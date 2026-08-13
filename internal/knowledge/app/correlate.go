package app

import (
	"context"
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
	OccurredAt time.Time
}

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
	clock     Clock
}

// NewCorrelationService wires the correlation ports.
func NewCorrelationService(inv InventoryReader, disc PackageVulnSource, fold *FaultlineService, matches MatchRecorder, clock Clock) *CorrelationService {
	return &CorrelationService{inventory: inv, discover: disc, fold: fold, matches: matches, clock: clock}
}

// WithLedger adds the re-discovery ledger (KN-RECOR-1): every ApplyCorrelation then records
// which evidence it correlated and when, which is what the scheduled sweep drains. Separate
// from the constructor so existing call sites keep compiling; production wiring always sets it.
func (s *CorrelationService) WithLedger(l ReleaseLedger) *CorrelationService {
	s.ledger = l
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
	plan := CorrelationPlan{ReleaseID: releaseID, EvidenceID: evidenceID}
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
		// Vendor fixed-verdict (EDR-VEX-01 Phase 3): for an rpm component, if the installed build
		// is at or above a same-EL-stream vendor fix (Red Hat/Rocky/Alma), the backported fix is
		// present and this occurrence is NOT affected — drop the match.
		//
		// The fixes are looked up BY PACKAGE (KN-FIX-1). The view's flat FixedVersions is a union
		// across every package the CVE affects, so comparing an installed build against it could
		// satisfy the verdict using a DIFFERENT package's fix and silently drop a live
		// vulnerability. Measured on a live release: 31 real occurrences disappeared that way,
		// mostly python3-ply@3.9 and python3-pyyaml@3.12 clearing CPython's 3.6.8 fixes.
		//
		// FixesFor aggregates every source's fix for THIS package and excludes unattributed ones,
		// so the verdict rests on evidence about this component and nothing else.
		if fixes := f.View().FixesFor(componentPackage(item.Component), item.Component.Ecosystem); len(fixes) > 0 &&
			value.RPMFixedByStream(item.Component.Ecosystem, item.Component.Version, fixes) {
			continue
		}
		created, err := s.matches.RecordMatch(ctx, Match{
			ReleaseID: plan.ReleaseID, FaultlineID: f.ID(), CVE: item.CVE.String(),
			Component: item.Component, Score: f.View().Score(),
			Priority: f.View().Priority(), Fixes: append([]domain.FixedVersion(nil), f.View().Fixes...),
			// What this match MEANS, decided against the reconciled card (D3/D5). The match is
			// recorded either way — D2 keeps everything, because an old build inside a superseded
			// stream genuinely does need replacing. What changes is what a consumer may SAY about
			// it: a plan and the AI's grounding use carriers, the posture keeps the obligation.
			ClaimClass: domain.ClassifyClaim(
				f.View().CarrierProducts, componentPackage(item.Component), item.Component.Name),
			OccurredAt: s.clock.Now(),
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

// Correlate runs the read and write phases back-to-back. It is retained for direct callers and
// tests that do not need the split; the event path uses PlanCorrelation + ApplyCorrelation so
// discovery I/O stays OUTSIDE the inbox transaction. Idempotent — a re-run converges and
// records no duplicate matches. Returns the number of new matches.
func (s *CorrelationService) Correlate(ctx context.Context, releaseID, evidenceID string) (int, error) {
	plan, err := s.PlanCorrelation(ctx, releaseID, evidenceID)
	if err != nil {
		return 0, err
	}
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
