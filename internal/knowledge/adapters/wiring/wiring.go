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
	"github.com/themis-project/themis/internal/knowledge/adapters/vex"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// vexParserAdapter bridges the OpenVEX parser (an adapter) to the app's VEXParser port.
type vexParserAdapter struct{}

func (vexParserAdapter) Parse(raw []byte) ([]app.VEXStatement, error) {
	stmts, err := vex.ParseOpenVEX(raw)
	if err != nil {
		return nil, err
	}
	out := make([]app.VEXStatement, len(stmts))
	for i, s := range stmts {
		out[i] = app.VEXStatement{CVE: s.CVE, Package: s.Package, Status: s.Status, Justification: s.Justification}
	}
	return out, nil
}

type idGen struct{}

func (idGen) NewID() string { return uuid.NewString() }

type sysClock struct{}

func (sysClock) Now() time.Time { return time.Now().UTC() }

// Knowledge bundles the composed Knowledge components: the read-API handler (routes under
// /faultlines — mount under /api/v1), the Store (operational tasks / dev purge), the inbound
// Evidence-event Consumer (the correlation worker's input), the outbox Relay, and (when the
// NVD watch is enabled) the scheduled Watch worker for the composition root to poll.
type Knowledge struct {
	Handler  http.Handler
	Store    *store.Store
	Consumer *inbound.Consumer
	Relay    *store.Relay
	Watch    *app.WatchService            // nil when the NVD watch is disabled
	Signals  *app.SignalEnrichmentService // nil when exploit-signal enrichment is disabled
}

// NVDConfig configures the optional scheduled NVD modified-since watch (EDR-KNOWLEDGE-01 D5).
// When Enabled, Wire builds the NVD client, filters it to already-carded CVEs (relevance
// bound), and returns a WatchService on Knowledge.Watch (nil when disabled); the composition
// root schedules its Poll.
type NVDConfig struct {
	Enabled bool
	BaseURL string       // "" → the client default (services.nvd.nist.gov)
	APIKey  string       // optional; empty uses NVD's lower unauthenticated rate limit
	HTTP    *http.Client // optional; nil → http.DefaultClient
}

// SignalsConfig configures the optional scheduled exploit-signal enrichment sweep (EPSS / KEV
// / ExploitDB). When Enabled, Wire builds the bulk client and a SignalEnrichmentService on
// Knowledge.Signals (nil when disabled); the composition root schedules its Enrich. Each feed
// URL may be empty to skip that source; relevance is bounded to already-carded CVEs.
type SignalsConfig struct {
	Enabled      bool
	EPSSURL      string
	KEVURL       string
	ExploitDBURL string
	HTTP         *http.Client // optional; nil → http.DefaultClient
}

// Wire builds the Knowledge components over the given pool, Evidence read-API base URL, OSV
// discovery base URL, outbox publisher, and NVD-watch config. Reconciliation precedence ranks
// NVD over OSV (the authoritative source wins ties — D-FEED-2 source tiers), so NVD's watch
// Proposals become the reconciled headline on cards OSV created.
func Wire(pool *pgxpool.Pool, evidenceBaseURL, osvBaseURL string, pub store.Publisher, nvd NVDConfig, signals SignalsConfig) Knowledge {
	st := store.New(pool)
	read := app.NewReadService(st, st)
	fold := app.NewFaultlineService(st, idGen{}, sysClock{}, domain.NewPrecedence("nvd", "osv"))
	evClient := evidence.NewClient(evidenceBaseURL, nil)
	disc := feed.NewOSVClient(osvBaseURL, nil)
	corr := app.NewCorrelationService(evClient, disc, fold, st, sysClock{})
	// Uploaded VEX: the same Evidence client serves the raw document; the OpenVEX parser turns
	// it into applicability Proposals folded onto the cards (EDR-VEX-01 D2).
	vexSvc := app.NewVEXApplicabilityService(evClient, vexParserAdapter{}, fold, sysClock{})
	kn := Knowledge{
		Handler:  knhttp.NewHandler(read).Router(),
		Store:    st,
		Consumer: inbound.NewConsumer(app.NewCoordinator(corr, vexSvc)),
		Relay:    store.NewRelay(pool, pub, 100),
	}
	if nvd.Enabled {
		changed := feed.NewRelevanceFilteredSource(feed.NewNVDClient(nvd.BaseURL, nvd.APIKey, nvd.HTTP), st)
		kn.Watch = app.NewWatchService(changed, st, fold, sysClock{})
	}
	if signals.Enabled {
		src := feed.NewExploitSignalClient(signals.EPSSURL, signals.KEVURL, signals.ExploitDBURL, signals.HTTP)
		kn.Signals = app.NewSignalEnrichmentService(src, st, fold, sysClock{})
	}
	return kn
}

// KnowledgeReadAPI wires the Knowledge read service over the given pool and returns the REST
// handler (routes under /faultlines — mount it under /api/v1) plus the Store. It is the
// read-only subset of Wire, kept for callers that need only the query surface.
func KnowledgeReadAPI(pool *pgxpool.Pool) (http.Handler, *store.Store) {
	st := store.New(pool)
	read := app.NewReadService(st, st)
	return knhttp.NewHandler(read).Router(), st
}
