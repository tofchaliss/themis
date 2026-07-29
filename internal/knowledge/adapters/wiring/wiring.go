// Package wiring is the Knowledge context's composition helper: it builds the read-side
// REST handler and the full correlation pipeline (Evidence read-API client → discovery →
// FaultlineService → store) over a pgx pool, so the binary and tests share one wiring. The
// Postgres Store implements the read ports (Repository + ProjectionReader), the MatchRecorder,
// and the transactional outbox directly.
package wiring

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/knowledge/adapters/evidence"
	"github.com/themis-project/themis/internal/knowledge/adapters/feed"
	knhttp "github.com/themis-project/themis/internal/knowledge/adapters/http"
	"github.com/themis-project/themis/internal/knowledge/adapters/inbound"
	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type idGen struct{}

func (idGen) NewID() string { return uuid.NewString() }

type sysClock struct{}

func (sysClock) Now() time.Time { return time.Now().UTC() }

// Knowledge bundles the composed Knowledge components: the read-API handler (routes under
// /faultlines — mount under /api/v1), the Store (operational tasks / dev purge), the inbound
// Evidence-event Consumer (the correlation worker's input), and the outbox Relay.
type Knowledge struct {
	Handler  http.Handler
	Store    *store.Store
	Consumer *inbound.Consumer
	Relay    *store.Relay
}

// Wire builds the Knowledge components over the given pool, Evidence read-API base URL, OSV
// discovery base URL, and outbox publisher. Reconciliation precedence ranks NVD over OSV (the
// authoritative source wins ties — D-FEED-2 source tiers).
func Wire(pool *pgxpool.Pool, evidenceBaseURL, osvBaseURL string, pub store.Publisher) Knowledge {
	st := store.New(pool)
	read := app.NewReadService(st, st)
	fold := app.NewFaultlineService(st, idGen{}, sysClock{}, domain.NewPrecedence("nvd", "osv"))
	inv := evidence.NewClient(evidenceBaseURL, nil)
	disc := feed.NewOSVClient(osvBaseURL, nil)
	corr := app.NewCorrelationService(inv, disc, fold, st, sysClock{})
	return Knowledge{
		Handler:  knhttp.NewHandler(read).Router(),
		Store:    st,
		Consumer: inbound.NewConsumer(app.NewCoordinator(corr)),
		Relay:    store.NewRelay(pool, pub, 100),
	}
}

// KnowledgeReadAPI wires the Knowledge read service over the given pool and returns the REST
// handler (routes under /faultlines — mount it under /api/v1) plus the Store. It is the
// read-only subset of Wire, kept for callers that need only the query surface.
func KnowledgeReadAPI(pool *pgxpool.Pool) (http.Handler, *store.Store) {
	st := store.New(pool)
	read := app.NewReadService(st, st)
	return knhttp.NewHandler(read).Router(), st
}
