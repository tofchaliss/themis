// Package wiring is the Communication context's composition helper: it builds the
// publish-trigger + read/preview REST handler, the inbound Governance event consumer, the
// publication delivery worker, the outward-action delivery-intent workers, the outbox relay,
// and supporting services over a single pgx pool + a Governance read-API base URL, for a cmd
// composition root.
package wiring

import (
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	commdelivery "github.com/themis-project/themis/internal/communication/adapters/delivery"
	govclient "github.com/themis-project/themis/internal/communication/adapters/governance"
	commhttp "github.com/themis-project/themis/internal/communication/adapters/http"
	"github.com/themis-project/themis/internal/communication/adapters/inbound"
	regclient "github.com/themis-project/themis/internal/communication/adapters/registry"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/adapters/store"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

type idGen struct{}

func (idGen) NewID() string { return uuid.NewString() }

type sysClock struct{}

func (sysClock) Now() time.Time { return time.Now().UTC() }

// defaultRetentionWindow is how long a rendered payload is kept before pruning (D1); the
// metadata is permanent and the payload stays regenerable.
const defaultRetentionWindow = 30 * 24 * time.Hour

// OutwardConfig is the outward-actions configuration a composition root passes in (R2, all
// of it documented in deploy/node.env.example and cmd/communication's config struct). It is
// deliberately isolated from the event bus's own retry envelope even though the defaults
// mirror it: sharing one knob would mean a slow mail relay could only be given more patience
// by also making the governance stream more patient.
type OutwardConfig struct {
	Intents   app.DeliveryIntentConfig
	Interval  time.Duration
	EnableFor map[domain.DeliveryKind]bool
	FakeModes map[domain.DeliveryKind]commdelivery.FakeMode
}

// Communication bundles the wired components for a composition root: the REST handler, the
// Store, the inbound Governance event consumer, the publication delivery worker, the
// outward-action delivery-intent service + its per-kind workers, the outbox relay, the
// state-based reconciler, and the retention worker.
type Communication struct {
	Handler       http.Handler
	Store         *store.Store
	Consumer      *inbound.Consumer
	Delivery      *app.DeliveryService
	Intents       *app.DeliveryIntentService
	IntentWorkers commdelivery.Workers
	Relay         *store.Relay
	Reconcile     *app.ReconcileService
	Retention     *app.RetentionService
}

// Wire builds the Communication components over the given pool, Governance read-API base
// URL, delivery channel, redactor, outbox publisher, and outward-actions configuration.
func Wire(pool *pgxpool.Pool, governanceBaseURL, registryBaseURL string, deliverer app.Deliverer,
	redactor app.Redactor, pub store.Publisher, outward OutwardConfig, logger *observability.Logger) Communication {
	if logger == nil {
		logger = observability.Nop()
	}
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

	// Outward actions (N-M1a). The recorder rides the inbound consumer — inside the bus
	// reader's transaction — and the senders ride their own workers. They share this service
	// and nothing else, which is the whole separation: the event path has no sender to call.
	intents := app.NewDeliveryIntentService(st, idGen{}, clock, outward.Intents)

	return Communication{
		Handler:       commhttp.NewHandler(write, read).WithRollups(rollups).WithDeliveryIntents(intents).Router(),
		Store:         st,
		Consumer:      inbound.NewConsumer(write).WithDeliveryIntents(intents),
		Delivery:      app.NewDeliveryService(st, deliverer, redactor, clock),
		Intents:       intents,
		IntentWorkers: intentWorkers(intents, outward, logger),
		Relay:         relay,
		Reconcile:     app.NewReconcileService(relay),
		Retention:     app.NewRetentionService(st, defaultRetentionWindow, clock),
	}
}

// intentWorkers builds one worker per ENABLED delivery kind, each over its own fake sender.
// A disabled kind gets no worker at all rather than a worker that refuses: its intents keep
// accumulating as PENDING, stay visible on the operator list, and start moving the moment it
// is switched on — whereas a refusing worker would burn their attempts and dead-letter them
// while the operator's own configuration was the cause.
//
// The senders are FAKES at N-M1a and say so in every log line. Real Jira / SMTP / CI clients
// are M2 and M3; they slot in behind the same Sender port with no change above this line.
func intentWorkers(svc *app.DeliveryIntentService, outward OutwardConfig, logger *observability.Logger) commdelivery.Workers {
	var ws commdelivery.Workers
	for _, kind := range []domain.DeliveryKind{domain.DeliveryJiraIssue, domain.DeliveryEmail, domain.DeliveryCIBuild} {
		if !outward.EnableFor[kind] {
			continue
		}
		sender := commdelivery.NewFakeSender(kind, outward.FakeModes[kind], logger)
		ws = append(ws, commdelivery.NewIntentWorker(svc, sender,
			commdelivery.WorkerConfig{Kind: kind, Interval: outward.Interval}, logger))
	}
	return ws
}
