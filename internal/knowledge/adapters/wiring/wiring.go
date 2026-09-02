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
	Backfill *app.BackfillService         // nil when NVD enrichment is disabled
	Signals  *app.SignalEnrichmentService // nil when exploit-signal enrichment is disabled
	RedHat   *app.RedHatEnrichmentService // nil when the Red Hat vendor feed is disabled
	Alpine   *app.AlpineEnrichmentService // nil when the Alpine secdb feed is disabled
	Rocky    *app.RockyEnrichmentService  // nil when the Rocky RXSA errata feed is disabled
	Vexfeed  *app.VexEnrichmentService    // nil when the generic CSAF-VEX feed is disabled
	Health   *app.FeedHealthService       // always set; the schedulers record into it (B1)
	// Reattribute re-asks the discovery feeds about components already in the estate, so cards
	// folded before fix-attribution existed gain it without a new SBOM (KN-FIX-2). Always set —
	// it rides the always-on OSV discovery source, not an opt-in feed.
	Reattribute *app.ReattributeService
	// Rediscovery re-runs the full discovery fan-out for the stalest correlated releases
	// (KN-RECOR-1), so a CVE published after a release's last upload still reaches its
	// inventory. Always set — like Reattribute, it rides the always-on discovery source; the
	// composition root decides whether to run its loop.
	Rediscovery *app.RediscoveryService
}

// RediscoveryConfig tunes the KN-RECOR-1 sweep. Zero values select the app defaults
// (24h staleness, 3 releases per sweep).
type RediscoveryConfig struct {
	StaleAfter time.Duration
	Limit      int
}

// NVDConfig configures the optional scheduled NVD modified-since watch (EDR-KNOWLEDGE-01 D5).
// When Enabled, Wire builds the NVD client, filters it to already-carded CVEs (relevance
// bound), and returns a WatchService on Knowledge.Watch (nil when disabled); the composition
// root schedules its Poll.
type NVDConfig struct {
	Enabled bool
	// BackfillLimit caps how many carded CVEs one enrichment sweep fetches (0 → the default).
	BackfillLimit int
	// StaleAfter is how long a card's NVD facts stay fresh before the sweep revisits it
	// (0 → the default). Revisiting is what catches revised scores and withdrawn CVEs.
	StaleAfter time.Duration
	BaseURL    string       // "" → the client default (services.nvd.nist.gov)
	APIKey     string       // optional; empty uses NVD's lower unauthenticated rate limit
	HTTP       *http.Client // optional; nil → http.DefaultClient

	// Discovery adds NVD to the correlation discovery fan-out (A2): a per-component,
	// CPE-product-gated keyword query so a CVE only NVD's CPE data covers still yields a
	// finding. Opt-in and bounded per component (D5); off by default (no silent NVD calls at
	// correlation time). An API key is recommended — discovery issues one query per component.
	Discovery bool
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

// RedHatConfig configures the optional Red Hat vendor feed (parity B3, EDR-VEX-01 D2/Phase 3).
// When Enabled, Wire builds the per-CVE Red Hat Security Data client and a
// RedHatEnrichmentService on Knowledge.RedHat (nil when disabled); the composition root
// schedules its Enrich. Relevance-bounded to already-carded CVEs (D5); the public Hydra API
// needs no key. Covers RHEL and its 1:1 rebuilds (Rocky, Alma).
type RedHatConfig struct {
	Enabled bool
	BaseURL string // "" → the client default (access.redhat.com Hydra)
	// ChangesURL overrides the per-CVE VEX changes.csv the D10 modified-since gate reads
	// ("" → Red Hat's public VEX change log). The gate is an efficiency gate riding the same
	// opt-in: it fails open to a full sweep, so it needs no switch of its own.
	ChangesURL string
	HTTP       *http.Client // optional; nil → http.DefaultClient
}

// RockyConfig configures the optional Rocky RXSA errata feed (GUI-5, EDR-VEX-01 D11). When
// Enabled, Wire builds the errata (Apollo) client and a RockyEnrichmentService on
// Knowledge.Rocky (nil when disabled); the composition root schedules its Enrich. The RXSA
// universe is tiny, so the D5 bound is applied inside the client: the advisory set is walked
// whole and only records matching carded CVEs are kept. RLSA clones are excluded — their
// content already arrives via the Red Hat feed.
type RockyConfig struct {
	Enabled bool
	BaseURL string       // "" → the client default (errata.rockylinux.org)
	HTTP    *http.Client // optional; nil → http.DefaultClient
}

// AlpineConfig configures the optional Alpine secdb feed (GUI-2, EDR-VEX-01 D7). When Enabled,
// Wire builds the branch-DB client and an AlpineEnrichmentService on Knowledge.Alpine (nil when
// disabled); the composition root schedules its Enrich. The secdb is not per-CVE addressable, so
// the D5 bound is applied inside the client: whole branch DBs are fetched and only records
// matching carded CVEs are kept. Branches must be configured — no machine-readable index exists.
type AlpineConfig struct {
	Enabled  bool
	BaseURL  string       // "" → the client default (secdb.alpinelinux.org)
	Branches []string     // secdb branches to sweep, e.g. ["v3.18", "v3.19"]
	HTTP     *http.Client // optional; nil → http.DefaultClient
}

// VexfeedConfig configures the optional generic vendor CSAF-VEX feed (parity B4, EDR-VEX-01 D2).
// When Enabled, Wire builds the multi-base per-CVE CSAF-VEX client and a VexEnrichmentService on
// Knowledge.Vexfeed (nil when disabled); the composition root schedules its Enrich.
// Relevance-bounded to already-carded CVEs (D5). BaseURLs are CSAF-VEX directory bases whose
// per-CVE files live at /<year>/cve-<id>.json.
type VexfeedConfig struct {
	Enabled  bool
	BaseURLs []string
	HTTP     *http.Client // optional; nil → http.DefaultClient
}

// VerdictConfig carries the occurrence-verdict switches (EDR-VERDICT-01).
type VerdictConfig struct {
	// DisableInferredBridge switches OFF the ownership bridge's guess grade (D4 strict mode;
	// THEMIS_VERDICT_INFERRED_BRIDGE=0). Stated as the negation so the zero value keeps the
	// documented default: the Inferred grade is ON.
	DisableInferredBridge bool
}

// Wire builds the Knowledge components over the given pool, Evidence read-API base URL, OSV
// discovery base URL, outbox publisher, and NVD-watch config. Reconciliation precedence ranks
// NVD over OSV (the authoritative source wins ties — D-FEED-2 source tiers), so NVD's watch
// Proposals become the reconciled headline on cards OSV created.
func Wire(pool *pgxpool.Pool, evidenceBaseURL, osvBaseURL string, pub store.Publisher, nvd NVDConfig, signals SignalsConfig, redhat RedHatConfig, alpine AlpineConfig, rocky RockyConfig, vexfeed VexfeedConfig, rediscovery RediscoveryConfig, verdict VerdictConfig) Knowledge {
	st := store.New(pool)
	read := app.NewReadService(st, st)
	// Precedence ranks distro-authoritative Red Hat first, then NVD, then OSV (D-FEED-2 tiers;
	// the reconcile policy is "distro-authoritative first, then NVD, then others"). Red Hat's
	// vendor-severity + not_affected statements therefore headline the reconciled distro view.
	fold := app.NewFaultlineService(st, idGen{}, sysClock{}, domain.NewPrecedence("redhat", "nvd", "osv"), newTrustPolicy()).
		// Carrier attribution lands on NVD's cadence, later than correlation. This lets a card
		// that gains it correct the classes already stamped on its matches (CORR-1 D3/D4);
		// without it, a stable estate — where no new correlation runs — keeps every component
		// `unknown` forever.
		WithMatchReader(st)
	evClient := evidence.NewClient(evidenceBaseURL, nil)
	health := app.NewFeedHealthService(st, sysClock{})
	// OSV is the always-on discovery feed — queried per component on every upload, with no poll
	// loop to hang health off. Wrapping it is what puts the one feed that runs constantly into
	// GET /feeds alongside the scheduled ones (B1).
	disc := feed.NewHealthRecordingSource("osv", feed.NewOSVClient(osvBaseURL, nil), health)
	if nvd.Discovery {
		// NVD joins the discovery fan-out beside OSV (A2). The reconciled version-range gate in
		// correlation (A1) + the client's CPE-product gate keep the fuzzy keyword source precise.
		disc = feed.NewMultiSource(disc, feed.NewNVDClient(nvd.BaseURL, nvd.APIKey, nvd.HTTP))
	}
	corr := app.NewCorrelationService(evClient, disc, fold, st, sysClock{}).WithLedger(st).
		WithInferredBridge(!verdict.DisableInferredBridge)
	// Uploaded VEX: the same Evidence client serves the raw document; the OpenVEX parser turns
	// it into applicability Proposals folded onto the cards (EDR-VEX-01 D2).
	vexSvc := app.NewVEXApplicabilityService(evClient, vexParserAdapter{}, fold, sysClock{})
	// Uploaded scanner report (KN-SCAN-1): the same client serves the document, the scanner
	// ACL translates each finding, and matches record so Governance opens Findings. Before
	// this line existed, a scanner-report upload was accepted by Evidence and silently
	// no-op'd here — the "wiring is no gate" class.
	scanSvc := app.NewScannerReportService(evidence.NewScannerSource(evClient, feed.NewRegistry()), fold, st, sysClock{}).
		WithInferredBridge(!verdict.DisableInferredBridge)
	// The on-demand per-CVE gather (G-AI-1): explicit operator POSTs only, so it needs no
	// enable flag — the scheduled watch's opt-in guards SILENT outbound calls, and this one is
	// never silent. It reuses the same NVD client + fold path as the backfill sweep.
	gather := app.NewGatherService(fold,
		app.GatherSource{Name: "nvd", Src: feed.NewNVDClient(nvd.BaseURL, nvd.APIKey, nvd.HTTP)})
	kn := Knowledge{
		Handler:  knhttp.NewHandler(read, health).WithGather(gather).Router(),
		Store:    st,
		Consumer: inbound.NewConsumer(app.NewCoordinator(corr, vexSvc).WithScanner(scanSvc)),
		Relay:    store.NewRelay(pool, pub, 100),
		Health:   health,
		// Same discovery fan-out correlation uses — one path to the feeds, not two.
		Reattribute: app.NewReattributeService(st, disc, fold, 0),
		Rediscovery: app.NewRediscoveryService(st, corr, sysClock{}, rediscovery.StaleAfter, rediscovery.Limit),
	}
	if nvd.Enabled {
		// Per-CVE over the carded set (D5a), not a modified-since window walk. The relevance
		// bound becomes structural — only CVEs the enterprise holds are ever requested — so
		// there is no RelevanceFilteredSource to wrap it in and nothing fetched to discard.
		kn.Backfill = app.NewBackfillService("nvd",
			feed.NewNVDClient(nvd.BaseURL, nvd.APIKey, nvd.HTTP), st, fold, nvd.BackfillLimit, nvd.StaleAfter)
	}
	if signals.Enabled {
		src := feed.NewExploitSignalClient(signals.EPSSURL, signals.KEVURL, signals.ExploitDBURL, signals.HTTP)
		kn.Signals = app.NewSignalEnrichmentService(src, st, fold, sysClock{})
	}
	if redhat.Enabled {
		kn.RedHat = app.NewRedHatEnrichmentService(feed.NewRedHatClient(redhat.BaseURL, redhat.HTTP), st, fold).
			// The D10 modified-since gate: after the first full sweep, only carded CVEs the VEX
			// change log reports modified (or never-fetched ones) are re-asked. Fails open to a
			// full sweep, so it rides the feed's own opt-in with no switch of its own.
			WithChangeSignal(feed.NewRedHatChangesClient(redhat.ChangesURL, redhat.HTTP), sysClock{})
	}
	if alpine.Enabled {
		kn.Alpine = app.NewAlpineEnrichmentService(feed.NewAlpineClient(alpine.BaseURL, alpine.Branches, alpine.HTTP), st, fold)
	}
	if rocky.Enabled {
		kn.Rocky = app.NewRockyEnrichmentService(feed.NewRockyClient(rocky.BaseURL, rocky.HTTP), st, fold)
	}
	if vexfeed.Enabled {
		kn.Vexfeed = app.NewVexEnrichmentService(feed.NewCSAFVexClient(vexfeed.BaseURLs, vexfeed.HTTP), st, fold)
	}
	return kn
}
