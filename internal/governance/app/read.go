package app

import (
	"context"

	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

// ProjectionReader serves disposable, event-built rollups (BCK-0047 / D10). Aggregates stay
// authoritative; projections are eventually consistent and rebuildable from Governance's
// own events. Only heavy rollups get a projection — by-id / by-key reads hit the aggregate.
type ProjectionReader interface {
	// ReleasePosture lists every Finding + its current stance for a Release (the primary
	// customer-facing view).
	ReleasePosture(ctx context.Context, releaseID string) ([]PostureEntry, error)
	// FaultlineBlastRadius lists the Release ids affected by a Faultline (the Governance-side
	// mirror of the rollup Knowledge deliberately does not own — EDR-KNOWLEDGE-01 D3/D10).
	FaultlineBlastRadius(ctx context.Context, faultlineID string) ([]string, error)
}

// BlastRadiusReader reads a release's enterprise blast radius — the count of unique customers
// it reaches — from the Registry estate graph over its read API (EDR-ESTATE-01 C2/D7). It is
// a small client seam (like Knowledge→Evidence); Governance never imports Registry.
type BlastRadiusReader interface {
	BlastRadius(ctx context.Context, releaseID string) (int, error)
}

// PostureEntry is one row of a Release's security posture: the Finding, its investigation
// stage, and its current Enterprise Position stance (empty when no Position exists yet).
type PostureEntry struct {
	FindingID   domain.FindingID
	FaultlineID string
	CVE         string
	Stage       domain.Stage
	Stance      domain.Stance
	HasPosition bool
	// PositionVersion is the current Position's version when HasPosition (0 otherwise) — the
	// handle a release-scoped snapshot records so its staleness is exactly computable
	// (EDR-COMMUNICATION-01 D13.2).
	PositionVersion int
	// PositionRationale is the current Position's own words ("" when none) — carried on the
	// rollup's statements as status notes (D13), read from the join this projection already
	// pays for.
	PositionRationale string
	// BaseScore is Knowledge's CVE-intrinsic priority (0–100), materialized from the
	// FaultlineEnriched event (C6). Governance scales it by the blast multiplier (C2).
	BaseScore int
	// Multiplier is the release's blast-radius amplification (1.0–2.0×) from the estate graph
	// (C2); 1.0 when the estate is empty or unreachable (fail-safe).
	Multiplier float64
	// EffectivePriority is BaseScore × Multiplier, UNCLAMPED (range 0–200, D17) — how bad this
	// is here, independent of what was decided about it (D14). A ranking number, not a percentage.
	EffectivePriority int
	// ResidualPriority is EffectivePriority × StanceWeight(Stance) — the number a human sorts
	// the triage queue by (D14). A not_affected or accepted_risk Finding reads 0 here while
	// keeping its intrinsic EffectivePriority, so a suppressed Finding leaves the top of the
	// queue without losing the severity that would justify revisiting it.
	ResidualPriority int
	// Reservation is the trust class of the evidence the current Position rested on, when
	// that is weaker than Observed (EDR-TRUST-01 T12) — e.g. an acceptance leaning on a
	// vendor's Asserted not_affected. Empty means no Position, or one on Observed evidence.
	//
	// It is DERIVED from the accepted proposal, never stored: a stored flag can disagree
	// with the evidence it describes. Surfacing it here is part of the decision, not a
	// refinement — a reservation nobody computes is a reservation nobody sees.
	Reservation value.TrustClass
	// Components are the release components this Finding was opened for, carrying the source
	// package a fix is published under (AI-GROUND-1).
	//
	// They are on the ROLLUP, not only on the per-Finding read, because "what do I upgrade to
	// close these 231 Findings" is a release-scoped question and answering it one Finding at a
	// time is 231 round-trips. The same join serves a dashboard, a report and the AI runtime —
	// it is a reusable business view, which is what EDR-TRUST-01 T10 requires of a Domain
	// Projection, and it is why the grouping happens here as a GROUP BY rather than in a model.
	Components []domain.MatchedComponent
	// Band is Knowledge's exploitability band (critical | high+ | high | elevated | informational).
	// It is exploitability-aware rather than raw CVSS, which is why it is Knowledge's to compute
	// and Governance's only to serve — a second implementation here would be a second policy that
	// eventually disagrees. Carried on the rollup so "which of these are critical?" is one read
	// (DASH-2), not one per Faultline.
	Band string
	// Fixes are the fix versions published for THIS Finding's own components — selected, not the
	// card's cross-package union (AI-GROUND-1). Carried so a release-scoped plan can say what to
	// upgrade TO without a per-Finding read (PLAN-3).
	Fixes []FixedVersion
	// OpenCarriers counts the carrier occurrences whose verdict is still open (EDR-VERDICT-01
	// D7) — the number that decides whether this Finding is still in the queue. Scope-class
	// rows never count (they are rebuild obligations, not vulnerability claims), and a missing
	// verdict counts as open (fail-safe). When every carrier occurrence is cleared, the
	// priorities below read 0 and the Finding leaves the ranked queue — that is where the
	// noise reduction comes from, never from discounting live occurrences.
	OpenCarriers int
}

// ReadService serves the Governance read side (D10): single-Finding / single-Position reads
// from the authoritative aggregate store, and heavier rollups from projections.
type ReadService struct {
	repo     Repository
	proj     ProjectionReader
	blast    BlastRadiusReader // may be nil — the multiplier then defaults to 1.0 (fail-safe)
	blastCap int               // unique-customer count at which the multiplier saturates (C2, configurable)
	// knowledge may be nil — the FindingAssessment projection then carries the Finding alone
	// (single-context dev, or a Knowledge outage). Best-effort by design (T10).
	knowledge FaultlineKnowledgeReader
	// evidence may be nil — CompareReleases then refuses (D16, fail-CLOSED: a compare that
	// cannot verify evidence presence would over-claim "fixed"). Every other read is unaffected.
	evidence EvidencePresenceReader
	// mitigatedWeight is the one configurable stance weight (D14); the rest are structural.
	// Seeded to domain.DefaultMitigatedWeight by the constructor so a zero value can never be
	// mistaken for "suppress everything mitigated".
	mitigatedWeight float64
}

// WithMitigatedWeight overrides the `mitigated` stance weight (THEMIS_MITIGATED_WEIGHT, D14)
// and returns the service for chaining. Out-of-range values fall back to the default in
// domain.StanceWeight — a misconfigured knob must not silently zero a Finding's triage number.
func (s *ReadService) WithMitigatedWeight(w float64) *ReadService {
	s.mitigatedWeight = w
	return s
}

// WithKnowledge wires the optional Knowledge read seam used by the FindingAssessment
// projection and returns the service for chaining. Kept separate from the constructor so
// every existing caller is unaffected.
func (s *ReadService) WithKnowledge(k FaultlineKnowledgeReader) *ReadService {
	s.knowledge = k
	return s
}

// NewReadService wires the aggregate repository, the projection store, the blast-radius reader
// (nil disables the multiplier — every effective priority equals its base score), and the
// blast-radius saturation cap (THEMIS_BLAST_RADIUS_CAP). A cap < 2 is normalized to
// domain.DefaultBlastRadiusCap, so this constructor owns the invariant that the cap is always
// sane regardless of caller.
func NewReadService(repo Repository, proj ProjectionReader, blast BlastRadiusReader, blastCap int) *ReadService {
	if blastCap < 2 {
		blastCap = domain.DefaultBlastRadiusCap
	}
	return &ReadService{
		repo: repo, proj: proj, blast: blast, blastCap: blastCap,
		mitigatedWeight: domain.DefaultMitigatedWeight,
	}
}

// GetFinding returns the full Finding aggregate — current Position + Position history +
// Governance Proposals (accepted and rejected) — for full explainability (CON-0003).
func (s *ReadService) GetFinding(ctx context.Context, id domain.FindingID) (domain.Finding, error) {
	return s.repo.GetByID(ctx, id)
}

// GetFindingByKey returns the Finding for a (Release, Faultline) business key; found=false
// if none exists.
func (s *ReadService) GetFindingByKey(ctx context.Context, releaseID, faultlineID string) (domain.Finding, bool, error) {
	return s.repo.GetByKey(ctx, releaseID, faultlineID)
}

// GetPosition returns a Finding's Enterprise Position — the latest when version <= 0, or the
// specific version otherwise — and whether it exists. This is the thin fetch Communication
// does after a Position event (D8).
func (s *ReadService) GetPosition(ctx context.Context, id domain.FindingID, version int) (domain.Position, bool, error) {
	f, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return domain.Position{}, false, err
	}
	if version <= 0 {
		pos, ok := f.CurrentPosition()
		return pos, ok, nil
	}
	for _, pos := range f.Positions() {
		if pos.Version() == version {
			return pos, true, nil
		}
	}
	return domain.Position{}, false, nil
}

// ReleasePosture returns the Release security-posture rollup (D10), each Finding's base score
// scaled by the release's blast-radius multiplier (C2). The blast radius is fetched ONCE per
// release. Fail-safe: a nil reader or any read error ⇒ multiplier 1.0 (effective == base) and
// the posture still returns — a missing or unreachable estate never inflates a score or breaks
// the read.
func (s *ReadService) ReleasePosture(ctx context.Context, releaseID string) ([]PostureEntry, error) {
	entries, err := s.proj.ReleasePosture(ctx, releaseID)
	if err != nil {
		return nil, err
	}
	mult := 1.0
	if s.blast != nil {
		if customers, berr := s.blast.BlastRadius(ctx, releaseID); berr == nil {
			mult = domain.BlastMultiplier(customers, s.blastCap)
		}
	}
	for i := range entries {
		entries[i].Multiplier = mult
		entries[i].EffectivePriority = domain.EffectivePriority(entries[i].BaseScore, mult)
		// The disposition-aware triage number (D14). A Finding with no Position weighs 1.0,
		// so residual == effective until someone decides something — the two numbers only
		// diverge once a governed decision exists to divide them.
		entries[i].ResidualPriority = domain.ResidualPriority(
			entries[i].EffectivePriority, domain.StanceWeight(entries[i].Stance, s.mitigatedWeight))
		// Queue derivation from the occurrence verdicts (EDR-VERDICT-01 D7): priority comes
		// from the OPEN carrier occurrences only, at full value — one live occurrence keeps
		// the Finding at full urgency however many cleared rows sit beside it, and only a
		// Finding with components on record and NONE of them open reads 0 and leaves the
		// ranked queue. A Finding with no component rows at all (older data) keeps its
		// priority untouched: missing evidence must never clear anything.
		entries[i].OpenCarriers = openCarriers(entries[i].Components)
		if len(entries[i].Components) > 0 && entries[i].OpenCarriers == 0 {
			entries[i].EffectivePriority = 0
			entries[i].ResidualPriority = 0
		}
	}
	return entries, nil
}

// openCarriers counts the carrier occurrences still open (EDR-VERDICT-01 D7). Scope-class
// rows are rebuild obligations, not vulnerability claims, so they neither hold a Finding in
// the queue nor release it; unknown claim classes act as carrier and unknown verdicts as
// open — both fail-safe directions this codebase already committed to.
func openCarriers(comps []domain.MatchedComponent) int {
	n := 0
	for _, c := range comps {
		if c.ActsAsCarrier() && c.VerdictIsOpen() {
			n++
		}
	}
	return n
}

// FaultlineBlastRadius returns the Releases affected by a Faultline (D10).
func (s *ReadService) FaultlineBlastRadius(ctx context.Context, faultlineID string) ([]string, error) {
	return s.proj.FaultlineBlastRadius(ctx, faultlineID)
}
