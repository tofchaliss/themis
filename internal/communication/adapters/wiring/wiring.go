// Package wiring is the Communication context's composition helper: it builds the
// publish-trigger + read/preview REST handler, the inbound Governance Position-event
// consumer, the delivery worker, the outbox relay, and supporting services over a single
// pgx pool + a Governance read-API base URL, for a cmd composition root.
package wiring

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	govclient "github.com/themis-project/themis/internal/communication/adapters/governance"
	commhttp "github.com/themis-project/themis/internal/communication/adapters/http"
	"github.com/themis-project/themis/internal/communication/adapters/inbound"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/adapters/store"
	"github.com/themis-project/themis/internal/communication/app"
)

type idGen struct{}

func (idGen) NewID() string { return uuid.NewString() }

type sysClock struct{}

func (sysClock) Now() time.Time { return time.Now().UTC() }

// defaultRetentionWindow is how long a rendered payload is kept before pruning (D1); the
// metadata is permanent and the payload stays regenerable.
const defaultRetentionWindow = 30 * 24 * time.Hour

// Communication bundles the wired components for a composition root: the REST handler, the
// Store, the inbound Governance Position-event consumer, the delivery worker, the outbox
// relay, the state-based reconciler, and the retention worker.
type Communication struct {
	Handler   http.Handler
	Store     *store.Store
	Consumer  *inbound.Consumer
	Delivery  *app.DeliveryService
	Relay     *store.Relay
	Reconcile *app.ReconcileService
	Retention *app.RetentionService
}

// Wire builds the Communication components over the given pool, Governance read-API base
// URL, delivery channel, redactor, and outbox publisher.
func Wire(pool *pgxpool.Pool, governanceBaseURL string, deliverer app.Deliverer, redactor app.Redactor, pub store.Publisher) Communication {
	st := store.New(pool)
	positions := govclient.NewClient(governanceBaseURL, nil)
	serializers := serializer.Default()
	clock := sysClock{}

	write := app.NewPublicationService(st, positions, serializers, idGen{}, clock)
	read := app.NewReadService(st, positions, serializers)
	relay := store.NewRelay(pool, pub, 100)

	return Communication{
		Handler:   commhttp.NewHandler(write, read).Router(),
		Store:     st,
		Consumer:  inbound.NewConsumer(write),
		Delivery:  app.NewDeliveryService(st, deliverer, redactor, clock),
		Relay:     relay,
		Reconcile: app.NewReconcileService(relay),
		Retention: app.NewRetentionService(st, defaultRetentionWindow, clock),
	}
}
