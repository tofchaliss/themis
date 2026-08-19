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

	"github.com/themis-project/themis/internal/governance/adapters/evidence"
	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/adapters/inbound"
	"github.com/themis-project/themis/internal/governance/adapters/knowledge"
	"github.com/themis-project/themis/internal/governance/adapters/registry"
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
// nil to disable it), the Registry read-API base URL for the blast-radius multiplier (empty ⇒
// the multiplier defaults to 1.0 — fail-safe, C2), the Knowledge and Evidence read-API base
// URLs (empty degrades the assessment projection / refuses the compare read respectively —
// D16), the blast-radius saturation cap (any value < 2 is normalized to
// domain.DefaultBlastRadiusCap), and optional Governance-owned auto-accept policies (D11).
func Wire(
	pool *pgxpool.Pool, pub store.Publisher, advisor app.PositionAdvisor,
	registryURL, knowledgeURL, evidenceURL string, blastCap int, mitigatedWeight, epssDriftThreshold float64,
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
	var blast app.BlastRadiusReader
	if registryURL != "" {
		blast = registry.NewClient(registryURL, &http.Client{Timeout: 10 * time.Second})
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
		read = read.WithKnowledge(knowledge.NewClient(knowledgeURL, &http.Client{Timeout: 10 * time.Second}))
	}
	// The Evidence presence seam under the compare read (D16). Empty ⇒ CompareReleases refuses —
	// fail-CLOSED, unlike the two seams above: a degraded compare would over-claim "fixed".
	if evidenceURL != "" {
		read = read.WithEvidence(evidence.NewClient(evidenceURL, &http.Client{Timeout: 10 * time.Second}))
	}
	relay := store.NewRelay(pool, pub, 100)
	return Governance{
		Handler:   govhttp.NewHandler(write, read).Router(),
		Store:     st,
		Consumer:  inbound.NewConsumer(app.NewCoordinator(write)),
		Relay:     relay,
		Reconcile: app.NewReconcileService(relay),
	}
}
