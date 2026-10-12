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
	"github.com/themis-project/themis/internal/evidence/adapters/report"
	"github.com/themis-project/themis/internal/evidence/adapters/store"
	"github.com/themis-project/themis/internal/evidence/adapters/subjectref"
	"github.com/themis-project/themis/internal/evidence/adapters/trust"
	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

// Config is the Evidence API's composition input. Everything that differs between
// the binary and a test is here, so there is exactly one wiring and no "production
// only" path for a defect to hide in.
type Config struct {
	// Pool is the Evidence database. The `registry` schema co-locates in it, which
	// is what makes the read seam below an in-process read rather than a network
	// call (EDR-INTAKE-01 D1).
	Pool *pgxpool.Pool

	// Registry is the registry read seam, supplied by the composition root: a
	// registry-backed adapter in production, the allow-set stub in dev/tests. It
	// backs BOTH release-existence (Evidence's SubjectRef port) and intake's
	// read-only release resolution (D7) — one seam, because they are two questions
	// about the same table and wiring them separately invites them to disagree.
	Registry subjectref.Registry

	// Provision is the registry WRITE seam — the one write Evidence makes into
	// Registry: find or create a version under a project that already exists
	// (EDR-INTAKE-01 B2). Supplied by the composition root beside the read seam.
	//
	// nil is a node that wires none, and then intake REFUSES to create instead of
	// panicking (see [app.NewIntakeService]). On the dev stub that refusal is
	// unreachable anyway: the stub knows no names, so no triple ever resolves far
	// enough for a version to be created.
	Provision app.ReleaseProvisioner

	// Report is the optional parse-outcome reporter (EDR-IDENTITY-01 D6).
	Report app.ParseReporter

	// Logger is where the adapters log. nil is the no-op logger.
	Logger *observability.Logger

	// Intake configures the single intake door.
	Intake evhttp.IntakeConfig
}

// EvidenceAPI wires the Evidence application service over the configured pool and
// returns the REST handler (routes under /evidence and /intake — mount it under
// /api/v1), the Store for operational tasks (outbox relay, receipt sweeps, dev
// purge), and the intake door, which the composition root must Close and whose
// interrupted receipts it recovers at startup.
func EvidenceAPI(cfg Config) (http.Handler, *store.Store, *evhttp.Intake) {
	st := store.New(cfg.Pool)
	svc := app.NewEvidenceService(
		trustGate{},
		parserBridge{registry: parser.NewRegistry()},
		cfg.Registry,
		repoBridge{store: st},
		idGen{},
		sysClock{},
	)
	if cfg.Report != nil {
		svc = svc.WithParseReporter(cfg.Report)
	}

	// The one intake door (D1). It writes through the EXISTING Register use case
	// rather than a second path into the store: the trust gate, fingerprinting, the
	// aggregate's invariants and the outbox note in one transaction are what "filed"
	// means, and a parallel writer would be a second definition of it.
	intakeSvc := app.NewIntakeService(cfg.Intake.MaxBytes, subjectref.NewResolver(cfg.Registry), cfg.Provision, st, report.Port{}, svc)
	intake := evhttp.NewIntake(intakeSvc, st, svc, cfg.Intake, cfg.Logger)

	// The same read seam also answers "which product owns this release", which is
	// what `POST /evidence` authorizes a product-scoped key against (EDR-INTAKE-01
	// B7) — one seam again, because two wirings of the same question invite them to
	// disagree.
	return evhttp.NewHandler(svc).WithIntake(intake).WithReleaseOwnership(cfg.Registry).Router(), st, intake
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
func (b repoBridge) GetRawDocument(ctx context.Context, id domain.EvidenceID) (string, []byte, error) {
	return b.store.GetRawDocument(ctx, id)
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
		out[i] = app.EvidenceSummary{ID: r.ID, Kind: r.Kind, Fingerprint: r.Fingerprint, ProvenanceSource: r.ProvenanceSource, FiledAt: r.FiledAt}
	}
	return out, nil
}

type idGen struct{}

func (idGen) NewID() domain.EvidenceID { return domain.EvidenceID(uuid.NewString()) }

type sysClock struct{}

func (sysClock) Now() time.Time { return time.Now().UTC() }
