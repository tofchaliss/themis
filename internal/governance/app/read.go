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

// PostureEntry is one row of a Release's security posture: the Finding, its investigation
// stage, and its current Enterprise Position stance (empty when no Position exists yet).
type PostureEntry struct {
	FindingID   domain.FindingID
	FaultlineID string
	CVE         string
	Stage       domain.Stage
	Stance      domain.Stance
	HasPosition bool
}

// ReadService serves the Governance read side (D10): single-Finding / single-Position reads
// from the authoritative aggregate store, and heavier rollups from projections.
type ReadService struct {
	repo Repository
	proj ProjectionReader
}

// NewReadService wires the aggregate repository and the projection store.
func NewReadService(repo Repository, proj ProjectionReader) *ReadService {
	return &ReadService{repo: repo, proj: proj}
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

// ReleasePosture returns the Release security-posture rollup (D10).
func (s *ReadService) ReleasePosture(ctx context.Context, releaseID string) ([]PostureEntry, error) {
	return s.proj.ReleasePosture(ctx, releaseID)
}

// FaultlineBlastRadius returns the Releases affected by a Faultline (D10).
func (s *ReadService) FaultlineBlastRadius(ctx context.Context, faultlineID string) ([]string, error) {
	return s.proj.FaultlineBlastRadius(ctx, faultlineID)
}
