package app

import (
	"context"

	"github.com/themis-project/themis/internal/governance/domain"
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
	// BaseScore is Knowledge's CVE-intrinsic priority (0–100), materialized from the
	// FaultlineEnriched event (C6). Governance scales it by the blast multiplier (C2).
	BaseScore int
	// Multiplier is the release's blast-radius amplification (1.0–2.0×) from the estate graph
	// (C2); 1.0 when the estate is empty or unreachable (fail-safe).
	Multiplier float64
	// EffectivePriority is BaseScore × Multiplier, clamped to 100 — what a human triages by.
	EffectivePriority int
}

// ReadService serves the Governance read side (D10): single-Finding / single-Position reads
// from the authoritative aggregate store, and heavier rollups from projections.
type ReadService struct {
	repo     Repository
	proj     ProjectionReader
	blast    BlastRadiusReader // may be nil — the multiplier then defaults to 1.0 (fail-safe)
	blastCap int               // unique-customer count at which the multiplier saturates (C2, configurable)
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
	return &ReadService{repo: repo, proj: proj, blast: blast, blastCap: blastCap}
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
	}
	return entries, nil
}

// FaultlineBlastRadius returns the Releases affected by a Faultline (D10).
func (s *ReadService) FaultlineBlastRadius(ctx context.Context, faultlineID string) ([]string, error) {
	return s.proj.FaultlineBlastRadius(ctx, faultlineID)
}
