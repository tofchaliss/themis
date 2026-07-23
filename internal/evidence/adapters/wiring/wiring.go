// Package wiring is the Evidence context's composition helper: it bridges the
// concrete adapters onto the application ports and assembles the REST handler.
// Both cmd/evidence and the e2e tests use it, so they exercise identical wiring.
package wiring

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	evhttp "github.com/themis-project/themis/internal/evidence/adapters/http"
	"github.com/themis-project/themis/internal/evidence/adapters/parser"
	"github.com/themis-project/themis/internal/evidence/adapters/store"
	"github.com/themis-project/themis/internal/evidence/adapters/trust"
	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
)

// EvidenceAPI wires the Evidence application service over the given pool and returns
// the REST handler (routes under /evidence — mount it under /api/v1) plus the Store
// for operational tasks (outbox relay, dev purge). The subject validator is supplied
// by the composition root: a registry-backed adapter in production (the kernel's
// registry.ReleaseExists) or the allow-set stub in dev/tests. Wiring depends only on
// the app SubjectRefValidator port, so the choice never leaks in here.
func EvidenceAPI(pool *pgxpool.Pool, subject app.SubjectRefValidator) (http.Handler, *store.Store) {
	st := store.New(pool)
	svc := app.NewEvidenceService(
		trustGate{},
		parserBridge{registry: parser.NewRegistry()},
		subject,
		repoBridge{store: st},
		idGen{},
		sysClock{},
	)
	return evhttp.NewHandler(svc).Router(), st
}

// --- adapter bridges (concrete adapters -> app ports) ----------------------

type trustGate struct{}

func (trustGate) Admit(in app.TrustInput) (app.TrustOutcome, error) {
	res, err := (trust.Gate{}).Admit(trust.Artifact{
		Raw: in.Raw, Kind: in.Kind, ExpectedChecksum: in.ExpectedChecksum, Provenance: in.Provenance,
	})
	if err != nil {
		return app.TrustOutcome{}, err
	}
	return app.TrustOutcome{Fingerprint: res.Fingerprint, Status: res.Status, Provenance: res.Provenance, Reason: res.Reason}, nil
}

type parserBridge struct{ registry *parser.Registry }

func (p parserBridge) Parse(ctx context.Context, format, specVersion string, raw []byte) (domain.Inventory, []string, error) {
	res, err := p.registry.Parse(ctx, format, specVersion, raw)
	if err != nil {
		return domain.Inventory{}, nil, err
	}
	return res.Inventory, res.Warnings, nil
}

type repoBridge struct{ store *store.Store }

func (b repoBridge) Save(ctx context.Context, e domain.Evidence, raw []byte, event domain.EvidenceRegistered) (domain.EvidenceID, bool, error) {
	res, err := b.store.Save(ctx, e, raw, event)
	return res.ID, res.Created, err
}
func (b repoBridge) GetByID(ctx context.Context, id domain.EvidenceID) (domain.Evidence, error) {
	return b.store.GetByID(ctx, id)
}
func (b repoBridge) GetInventory(ctx context.Context, id domain.EvidenceID) (domain.Inventory, error) {
	return b.store.GetInventory(ctx, id)
}
func (b repoBridge) ListByRelease(ctx context.Context, releaseID string) ([]app.EvidenceSummary, error) {
	rows, err := b.store.ListByRelease(ctx, releaseID)
	if err != nil {
		return nil, err
	}
	out := make([]app.EvidenceSummary, len(rows))
	for i, r := range rows {
		out[i] = app.EvidenceSummary{ID: r.ID, Kind: r.Kind, Fingerprint: r.Fingerprint, FiledAt: r.FiledAt}
	}
	return out, nil
}

type idGen struct{}

func (idGen) NewID() domain.EvidenceID { return domain.EvidenceID(uuid.NewString()) }

type sysClock struct{}

func (sysClock) Now() time.Time { return time.Now().UTC() }
