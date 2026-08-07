package app

import (
	"context"
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
	OccurredAt  time.Time
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
	clock     Clock
}

// NewCorrelationService wires the correlation ports.
func NewCorrelationService(inv InventoryReader, disc PackageVulnSource, fold *FaultlineService, matches MatchRecorder, clock Clock) *CorrelationService {
	return &CorrelationService{inventory: inv, discover: disc, fold: fold, matches: matches, clock: clock}
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
	Items     []PlannedMatch
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
	plan := CorrelationPlan{ReleaseID: releaseID}
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
	newMatches := 0
	for _, item := range plan.Items {
		f, err := s.fold.FoldProposal(ctx, item.CVE, item.Proposal)
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
		// The fixes come from THIS ITEM'S OWN Proposal, never from the card's reconciled view
		// (KN-FIX-1). The view's FixedVersions is a union across every package the CVE affects,
		// with no package association — so comparing an installed build against it could satisfy
		// the verdict using a DIFFERENT package's fix and silently drop a live vulnerability.
		// Worked example: a card covering glibc and perl-Carp carries
		// ["0:2.28-251.el8_10.38", "0:1.42-397.el8"]; installed glibc 2.28-251.el8_10.31 clears
		// perl-Carp's 1.42 and the glibc finding disappears.
		//
		// The item's Proposal is package-scoped by construction — OSV is queried BY PACKAGE, so
		// its record is about this component and nothing else. Using it narrows the verdict (a
		// fix known only to another source is not applied here), and narrowing is the safe
		// direction: keeping a match costs triage time, dropping one costs a breach.
		if vf, ok := item.Proposal.VulnFacts(); ok &&
			value.RPMFixedByStream(item.Component.Ecosystem, item.Component.Version, vf.FixedVersions) {
			continue
		}
		created, err := s.matches.RecordMatch(ctx, Match{
			ReleaseID: plan.ReleaseID, FaultlineID: f.ID(), CVE: item.CVE.String(),
			Component: item.Component, Score: f.View().Score(), OccurredAt: s.clock.Now(),
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
