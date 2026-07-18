package app

import (
	"context"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// ProjectionReader serves disposable, event-built rollups (D10). The affected-releases
// rollup is a projection over ComponentMatched (the faultline_matches rows), never card
// state — "which releases are affected by card F" is release-facing data Knowledge does
// not own on the card (D3).
type ProjectionReader interface {
	AffectedReleases(ctx context.Context, faultlineID string) ([]string, error)
}

// StageReconciler continues incomplete correlation work from persisted authoritative
// state (D11) — e.g. a card that has matches but never reached the Correlated stage.
type StageReconciler interface {
	ReconcileStuckStages(ctx context.Context) (int, error)
}

// ReadService serves the Knowledge read API (D10): a by-identity/by-CVE read of the
// authoritative aggregate plus the affected-releases projection.
type ReadService struct {
	repo Repository
	proj ProjectionReader
}

// NewReadService wires the read ports.
func NewReadService(repo Repository, proj ProjectionReader) *ReadService {
	return &ReadService{repo: repo, proj: proj}
}

// GetByID returns the card (view + provenance) by its identity.
func (s *ReadService) GetByID(ctx context.Context, id domain.FaultlineID) (domain.Faultline, error) {
	return s.repo.GetByID(ctx, id)
}

// GetByCVE returns the card by canonical CVE; found=false if none exists.
func (s *ReadService) GetByCVE(ctx context.Context, cve string) (domain.Faultline, bool, error) {
	return s.repo.GetByCVE(ctx, cve)
}

// AffectedReleases returns the releases affected by a card (the rollup projection).
func (s *ReadService) AffectedReleases(ctx context.Context, faultlineID string) ([]string, error) {
	return s.proj.AffectedReleases(ctx, faultlineID)
}

// ReconcileService is Knowledge's first-class reconciler (D11): a periodic job that
// inspects persisted authoritative state and continues incomplete work, without any
// workflow replay.
type ReconcileService struct {
	rec StageReconciler
}

// NewReconcileService wires the reconciler.
func NewReconcileService(rec StageReconciler) *ReconcileService { return &ReconcileService{rec: rec} }

// Reconcile continues incomplete correlation work and returns how many cards it fixed.
func (s *ReconcileService) Reconcile(ctx context.Context) (int, error) {
	return s.rec.ReconcileStuckStages(ctx)
}
