// Package wiring is the Governance context's composition helper: it builds the triage +
// read REST handler, the inbound Knowledge-event consumer, the outbox relay, and the
// state-based reconciler over a single pgx pool, for a cmd composition root. The Postgres
// Store implements the Repository and ProjectionReader ports directly.
package wiring

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/adapters/inbound"
	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

type idGen struct{}

func (idGen) NewID() string { return uuid.NewString() }

type sysClock struct{}

func (sysClock) Now() time.Time { return time.Now().UTC() }

// Governance bundles the wired Governance components for a composition root: the REST
// handler (routes under /findings, /releases, /faultlines — mount under /api/v1), the
// Store (operational tasks / dev purge), the inbound Knowledge-event consumer (the Finding
// worker's input), the outbox Relay, and the state-based Reconcile service.
type Governance struct {
	Handler   http.Handler
	Store     *store.Store
	Consumer  *inbound.Consumer
	Relay     *store.Relay
	Reconcile *app.ReconcileService
}

// Wire builds the Governance components over the given pool, outbox publisher, an optional
// Intelligence advisor (the D13 disable gate — pass a real client to enable AI, a no-op or
// nil to disable it), and optional Governance-owned auto-accept policies (D11).
func Wire(pool *pgxpool.Pool, pub store.Publisher, advisor app.PositionAdvisor, policies ...domain.PolicyRule) Governance {
	st := store.New(pool)
	write := app.NewFindingService(st, idGen{}, sysClock{}, policies...)
	if advisor != nil {
		write = write.WithAdvisor(advisor)
	}
	read := app.NewReadService(st, st)
	relay := store.NewRelay(pool, pub, 100)
	return Governance{
		Handler:   govhttp.NewHandler(write, read).Router(),
		Store:     st,
		Consumer:  inbound.NewConsumer(app.NewCoordinator(write)),
		Relay:     relay,
		Reconcile: app.NewReconcileService(relay),
	}
}
