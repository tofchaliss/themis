// Package wiring is the Governance context's composition helper: it builds the triage +
// read REST handler, the inbound Knowledge-event consumer, the outbox relay, and the
// state-based reconciler over a single pgx pool, for a cmd composition root. The Postgres
// Store implements the Repository and ProjectionReader ports directly.
package wiring

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/governance/adapters/evidence"
	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/adapters/inbound"
	"github.com/themis-project/themis/internal/governance/adapters/knowledge"
	"github.com/themis-project/themis/internal/governance/adapters/registry"
	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

// The Registry client IS the handler's product-scope seam (EDR-DELIVERY-01 D3). Stated as an
// assertion rather than left to the call below, so a change to either side fails here — at the
// one place that can see both — instead of degrading a security check to "seam not wired".
var _ govhttp.ProductResolver = (*registry.Client)(nil)

type idGen struct{}

func (idGen) NewID() string { return uuid.NewString() }

type sysClock struct{}

func (sysClock) Now() time.Time { return time.Now().UTC() }

// Governance bundles the wired Governance components for a composition root: the REST
// handler (routes under /findings, /releases, /faultlines — mount under /api/v1), the
// Store (operational tasks / dev purge), the inbound Knowledge-event consumer (the Finding
// worker's input), the outbox Relay, the state-based Reconcile service, and the
// release-evaluation worker.
type Governance struct {
	Handler   http.Handler
	Store     *store.Store
	Consumer  *inbound.Consumer
	Relay     *store.Relay
	Reconcile *app.ReconcileService
	// Evaluations publishes governance.release_evaluated.v1 for the recorded pending rows
	// (EDR-DELIVERY-01 N-M2b). The composition root runs it on its own goroutine. It is nil when
	// no Registry URL is configured: the event names the product and the project, and the one
	// thing the worker must never do is publish them blank — so with no seam to resolve them the
	// rows stay queued, visibly, rather than draining into half-stated events.
	Evaluations *app.ReleaseEvaluationWorker
}

// Wire builds the Governance components over the given pool, outbox publisher, an optional
// Intelligence advisor (the D13 disable gate — pass a real client to enable AI, a no-op or
// nil to disable it), the Registry read-API base URL for the blast-radius multiplier (empty ⇒
// the multiplier defaults to 1.0 — fail-safe, C2), the Knowledge and Evidence read-API base
// URLs (empty degrades the assessment projection / refuses the compare read respectively —
// D16), the blast-radius saturation cap (any value < 2 is normalized to
// domain.DefaultBlastRadiusCap), the shared logger (nil ⇒ no-op; it carries the detail an
// authorization refusal withholds from the caller — EDR-DELIVERY-01 D1), and optional
// Governance-owned auto-accept policies (D11).
func Wire(
	pool *pgxpool.Pool, pub store.Publisher, advisor app.PositionAdvisor,
	registryURL, knowledgeURL, evidenceURL, readAPIKey string, blastCap int, mitigatedWeight, epssDriftThreshold float64,
	logger *observability.Logger,
	policies ...domain.PolicyRule,
) Governance {
	st := store.New(pool)
	write := app.NewFindingService(st, idGen{}, sysClock{}, policies...)
	// The disposition watcher's sensitivity (GOV-14b). An out-of-range value falls back to the
	// domain default inside the rule — a misconfigured knob must not disable the safety net under
	// a suppression mechanism that is already live.
	if epssDriftThreshold > 0 {
		write = write.WithEPSSDriftThreshold(epssDriftThreshold)
	}
	if advisor != nil {
		write = write.WithAdvisor(advisor)
	}
	// One Registry client, two seams: the blast-radius multiplier (fail-open to 1.0×) and the
	// release → product hop that confines a `product:<id>` key to its own product's Findings
	// (fail-closed — EDR-DELIVERY-01 N-M0). Empty URL ⇒ neither is wired, so only `admin` may
	// write.
	var reg *registry.Client
	var blast app.BlastRadiusReader
	if registryURL != "" {
		reg = registry.NewClient(registryURL, readClient(readAPIKey))
		blast = reg
	}
	// blastCap normalization (< 2 ⇒ domain.DefaultBlastRadiusCap) is owned by NewReadService.
	read := app.NewReadService(st, st, blast, blastCap)
	// The one configurable stance weight (D14). A zero or out-of-range value keeps the domain
	// default rather than silently zeroing every mitigated Finding's triage number.
	if mitigatedWeight > 0 {
		read = read.WithMitigatedWeight(mitigatedWeight)
	}
	// The Knowledge read seam feeds the FindingAssessment Domain Projection (T10). Empty ⇒
	// the projection carries the Finding alone, which is the same fail-safe posture the
	// blast-radius reader takes: a missing seam degrades the view, never the request.
	if knowledgeURL != "" {
		read = read.WithKnowledge(knowledge.NewClient(knowledgeURL, readClient(readAPIKey)))
	}
	// The Evidence presence seam under the compare read (D16). Empty ⇒ CompareReleases refuses —
	// fail-CLOSED, unlike the two seams above: a degraded compare would over-claim "fixed".
	if evidenceURL != "" {
		read = read.WithEvidence(evidence.NewClient(evidenceURL, readClient(readAPIKey)))
	}
	relay := store.NewRelay(pool, pub, 100)
	handler := govhttp.NewHandler(write, read).WithLogger(logger)
	if reg != nil {
		handler = handler.WithProductResolver(reg)
	}
	// The release-evaluation worker (N-M2b) — the half of the path that may fail. The inbound
	// consumer only records a pending row; this resolves the Release's owners, counts its
	// Findings and publishes. Without a Registry seam there is nothing to resolve them WITH, so
	// no worker is wired and the queue simply holds.
	var evaluations *app.ReleaseEvaluationWorker
	if reg != nil {
		evaluations = app.NewReleaseEvaluationWorker(st, reg, sysClock{}, evaluationLog{logger})
	}
	return Governance{
		Handler:     handler.Router(),
		Store:       st,
		Consumer:    inbound.NewConsumer(app.NewCoordinator(write).WithEvaluations(st)).WithLogger(logger),
		Relay:       relay,
		Reconcile:   app.NewReconcileService(relay),
		Evaluations: evaluations,
	}
}

// evaluationLog adapts the shared logger to the worker's narrow reporting port (R1: the app ring
// may not import the observability package, so the adapter ring supplies it).
type evaluationLog struct{ logger *observability.Logger }

func (l evaluationLog) Error(msg, releaseID string, err error) {
	if l.logger == nil {
		return
	}
	l.logger.Error(msg, observability.String("release_id", releaseID), observability.Err(err))
}

// readClient is the HTTP client for Governance's three read seams (Registry, Knowledge,
// Evidence). With a key, every request carries it as X-API-Key: on an estate where those nodes
// run with auth on, an unauthenticated read answers 401, which silently degrades the blast-radius
// multiplier and the assessment projection and stalls the release-evaluation worker forever
// (N-M2b). A READ-scoped key is enough — Governance writes to none of them. Empty = reads are
// unauthenticated (auth-off dev). Same variable, THEMIS_API_KEY, as Communication's reads.
func readClient(apiKey string) *http.Client {
	c := &http.Client{Timeout: 10 * time.Second}
	if apiKey = strings.TrimSpace(apiKey); apiKey != "" {
		c.Transport = apiKeyTransport{key: apiKey, base: http.DefaultTransport}
	}
	return c
}

type apiKeyTransport struct {
	key  string
	base http.RoundTripper
}

func (t apiKeyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context()) // a RoundTripper must not modify the caller's request
	r.Header.Set("X-API-Key", t.key)
	return t.base.RoundTrip(r)
}
