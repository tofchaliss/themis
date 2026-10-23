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
	Handler http.Handler
	// API is the handler behind Handler, kept so WireDelivery can attach the callback route's
	// intent service after the fact (N-M2h): the router holds the pointer, so a later setter
	// takes effect.
	API       *commhttp.Handler
	Store     *store.Store
	Consumer  *inbound.Consumer
	Delivery  *app.DeliveryService
	Relay     *store.Relay
	Reconcile *app.ReconcileService
	Retention *app.RetentionService
	// Posture is Governance's release-posture read seam, carried on the bundle so WireDelivery
	// can give the outward renderer the severity counts a remediation ticket is made of (N-M1b)
	// without opening a second client against the same read API.
	Posture app.ReleaseSeverityReader
	// Identity is the Registry name chain, carried for the same reason: a ticket or a mail
	// names the product, project and version, not three UUIDs (owner ask 2026-10-21).
	Identity app.ReleaseIdentityReader
}

// Wire builds the Communication components over the given pool, Governance read-API base
// URL, delivery channel, redactor, and outbox publisher.
//
// readAPIKey is the credential BOTH read seams (Governance, Registry) send as `X-API-Key`; empty
// leaves them unauthenticated, which is the auth-off development case. One key for both, because
// they are the same kind of act — this node reading another node's read API — and a read-scoped key
// is all either needs.
func Wire(pool *pgxpool.Pool, governanceBaseURL, registryBaseURL, readAPIKey string, deliverer app.Deliverer, redactor app.Redactor, pub store.Publisher) Communication {
	st := store.New(pool)
	positions := govclient.NewClient(governanceBaseURL, nil).WithAPIKey(readAPIKey)
	serializers := serializer.Default()
	clock := sysClock{}

	write := app.NewPublicationService(st, positions, serializers, idGen{}, clock)
	read := app.NewReadService(st, positions, serializers)
	// The release-scoped VEX rollup (EDR-COMMUNICATION-01 D13): the same Governance client
	// supplies the posture read, the Registry client the fail-closed name chain (D13.4).
	identity := regclient.NewClient(registryBaseURL, nil).WithAPIKey(readAPIKey)
	rollups := app.NewRollupService(positions, identity,
		st, serializers, idGen{}, clock)
	relay := store.NewRelay(pool, pub, 100)

	api := commhttp.NewHandler(write, read).WithRollups(rollups).
		WithRemediationReports(app.NewRemediationReports(positions, serializer.RemediationRenderer{}))
	return Communication{
		Handler:   api.Router(),
		API:       api,
		Store:     st,
		Consumer:  inbound.NewConsumer(write),
		Delivery:  app.NewDeliveryService(st, deliverer, redactor, clock),
		Relay:     relay,
		Reconcile: app.NewReconcileService(relay),
		Retention: app.NewRetentionService(st, defaultRetentionWindow, clock),
		Posture:   positions,
		Identity:  identity,
	}
}

// WireDelivery adds the outward-delivery plumbing to an already-wired Communication: the
// delivery-intent service (with the N-M1b payload renderer), the senders — real or fake per
// config — and the worker that drives them. It also hands the intent service to the inbound
// consumer, which is what makes the event reader RECORD intents at all.
//
// It returns nil when cfg.Enabled is false, and then the consumer is left without an intent
// service too: a node that will not send must not accumulate a queue nobody drains. That is
// the same switch on both halves, deliberately, so "delivery is off" cannot mean "intents pile
// up invisibly".
//
// The renderer is wired whenever a posture read seam is available, independently of WHICH sender
// is selected: materialization is a property of the record (D-N-3), not of the channel, so a node
// running the fakes still stores the exact bytes it would have sent.
func WireDelivery(comm Communication, cfg delivery.Config, logger *observability.Logger) *delivery.Worker {
	if !cfg.Enabled {
		return nil
	}
	if logger == nil {
		logger = observability.Nop()
	}
	intents := app.NewDeliveryIntentService(comm.Store, idGen{}, sysClock{}, app.DeliveryIntentConfig{
		DeadLetterAudience: cfg.DeadLetterAudience,
		DecisionAudience:   cfg.DecisionAudience,
		EvaluationAudience: cfg.EvaluationAudience,
		ReviewAudience:     cfg.ReviewAudience,
		RebuildDestination: cfg.Jenkins.Job,
		WebhookRoutes:      cfg.WebhookRoutes,
	}).WithRebuildCallbacks(comm.Store)
	// Webhook routes by tag ("kind#tag=audience", EDR-REMEDIATION-01 D7) read the release's
	// effective tags over the same Registry client the names come from.
	if tags, ok := comm.Identity.(app.ReleaseTagReader); ok {
		intents = intents.WithReleaseTags(tags)
	}
	if comm.API != nil {
		comm.API.WithRebuildCallbacks(intents) // the callback route records against the same intents
		comm.API.WithWebhookHealth(comm.Store)  // D4: the Feeds page reads destination health
	}
	if comm.Posture != nil {
		intents = intents.WithPayloadRenderer(serializer.NewOutwardRenderer(comm.Posture).WithIdentity(comm.Identity).WithDashboardURL(cfg.DashboardURL))
	}
	comm.Consumer.WithIntents(intents)
	// The rebuild loop (N-M2i) needs the posture to decide; without the read seam there is no
	// loop, and a node without one still tickets and mails.
	if comm.Posture != nil {
		comm.Consumer.WithRebuildLoop(app.NewRebuildLoop(comm.Store, comm.Posture, intents, sysClock{}, cfg.RebuildMaxAttempts))
	}
	// The Store is also the REAL Jira sender's ticket index: Themis's own record of which issue a
	// Release already has is what keeps one ticket per Release when the project forbids labels on
	// create (EDR-DELIVERY-01 M1b-4a).
	// The SLA breach digest (EDR-REMEDIATION-01 D4) collects only while its route is configured.
	digest := app.NewSLADigest(comm.Store, intents, comm.Identity, idGen{}, sysClock{})
	comm.Consumer.WithSLADigest(digest)
	worker := delivery.NewWorker(cfg, comm.Store, intents, delivery.NewDeliverersWithHealth(cfg, comm.Store, comm.Store, logger), logger).
		WithSLADigest(digest)
	// The scheduled remediation summary (D6 through D4) reads the same Governance client.
	if reader, ok := comm.Posture.(app.RemediationMetricsReader); ok {
		worker = worker.WithMetricsSchedule(app.NewMetricsSchedule(reader, intents, idGen{}))
	}
	return worker
}

// The delivery-intent store answers the Jira sender's ticket-index question. Asserted here, at the
// composition root, so a port change fails the build where both halves are visible.
var _ delivery.ReleaseTicketIndex = (*store.Store)(nil)
