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

	"github.com/themis-project/themis/internal/communication/adapters/delivery"
	govclient "github.com/themis-project/themis/internal/communication/adapters/governance"
	commhttp "github.com/themis-project/themis/internal/communication/adapters/http"
	"github.com/themis-project/themis/internal/communication/adapters/inbound"
	regclient "github.com/themis-project/themis/internal/communication/adapters/registry"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/adapters/store"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/platform/observability"
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
func Wire(pool *pgxpool.Pool, governanceBaseURL, registryBaseURL string, deliverer app.Deliverer, redactor app.Redactor, pub store.Publisher) Communication {
	st := store.New(pool)
	positions := govclient.NewClient(governanceBaseURL, nil)
	serializers := serializer.Default()
	clock := sysClock{}

	write := app.NewPublicationService(st, positions, serializers, idGen{}, clock)
	read := app.NewReadService(st, positions, serializers)
	// The release-scoped VEX rollup (EDR-COMMUNICATION-01 D13): the same Governance client
	// supplies the posture read, the Registry client the fail-closed name chain (D13.4).
	rollups := app.NewRollupService(positions, regclient.NewClient(registryBaseURL, nil), st, serializers, idGen{}, clock)
	relay := store.NewRelay(pool, pub, 100)

	return Communication{
		Handler:   commhttp.NewHandler(write, read).WithRollups(rollups).Router(),
		Store:     st,
		Consumer:  inbound.NewConsumer(write),
		Delivery:  app.NewDeliveryService(st, deliverer, redactor, clock),
		Relay:     relay,
		Reconcile: app.NewReconcileService(relay),
		Retention: app.NewRetentionService(st, defaultRetentionWindow, clock),
	}
}

// WireDelivery adds the N-M1a outward-delivery plumbing to an already-wired Communication:
// the delivery-intent service, the fake Jira/mail senders, and the worker that drives them.
// It also hands the intent service to the inbound consumer — which is what makes the event
// reader RECORD intents at all.
//
// It returns nil when cfg.Enabled is false, and then the consumer is left without an intent
// service too: a node that will not send must not accumulate a queue nobody drains. That is
// the same switch on both halves, deliberately, so "delivery is off" cannot mean "intents pile
// up invisibly".
func WireDelivery(comm Communication, cfg delivery.Config, logger *observability.Logger) *delivery.Worker {
	if !cfg.Enabled {
		return nil
	}
	if logger == nil {
		logger = observability.Nop()
	}
	intents := app.NewDeliveryIntentService(comm.Store, idGen{}, sysClock{}, app.DeliveryIntentConfig{
		DeadLetterAudience: cfg.DeadLetterAudience,
	})
	comm.Consumer.WithIntents(intents)
	return delivery.NewWorker(cfg, comm.Store, intents, map[app.IntentType]delivery.IntentDeliverer{
		app.IntentJiraIssue: delivery.NewFakeJiraDeliverer(logger),
		app.IntentEmail:     delivery.NewFakeMailDeliverer(logger),
	}, logger)
}
