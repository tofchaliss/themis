//go:build integration

package store_test

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/inbound"
	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// N-M2a (EDR-DELIVERY-01 M2-1 / M2a-1..M2a-4): Knowledge publishes
// knowledge.release_correlation_completed.v1 ONCE per SBOM, appended to the outbox after every
// other Knowledge event for that SBOM, with the discovery cause carried through from the path
// that ran correlation.
//
// The ordering is the only reason this event exists rather than a timer, so it is the thing
// this test proves hardest — and it proves exactly the promise and not a stronger one. The
// promise is PER SBOM: the completion follows the events of its own correlation, and says
// nothing about unrelated events that another SBOM's correlation raised in the meantime. Each
// assertion is therefore scoped to the rows one correlation produced, and the delivered half
// runs the real relay, because the bus numbers rows in append order — so the relay's publish
// order IS the seq order, and a store assertion alone would not notice a relay that reordered.
//
// The ids are UUIDs on purpose: the schema annotates release_id and sbom_id as `format: uuid`,
// and the estate carries real Registry/Evidence identities here.
const (
	testReleaseA  = "8f1b6f2e-5a61-4a2e-9d0e-7c0f1f7a1b11"
	testSBOMA     = "2c7b1f90-3d44-4f0e-8a71-19b2c6d5e4f3"
	testReleaseA2 = "0d5e8c71-4b36-4e92-9f18-6a3c7d1b2e55"
	testSBOMA2    = "9b3f6a14-7c82-4e05-b6d9-4f1a8e2c7d36"
	testReleaseB  = "b4d6c1a8-9f2e-4c7b-8e15-3a0d9c6b2f44"
	testSBOMB     = "6e9a7c25-1b48-4d3a-9f60-8c2e5b7d1a09"
	testReleaseC  = "d1c3b5a7-2e49-4f81-9a6b-0c7d8e2f3a51"
	testSBOMC     = "f0a2c4e6-7b19-4d53-8e2a-5c1b9d6f3e82"
	testReleaseE  = "5a9f3c82-0d64-4b17-8e2f-6b4d1a9c7e03"
	testSBOME     = "c8e1b479-5f20-4a63-9d8c-3e7f2a1b6d54"
	testReleaseD  = "3b7e9d41-6c28-4a0f-95d3-7e1a2c8b4f60"
	testVEXD      = "a5c8e1f3-4d72-4b09-86ae-2f9c7b0d5e31"
	testScanD     = "7d4b2f60-8e13-4c95-a0f7-1b6e3d9c2850"
)

func TestEventSchema_Knowledge_ReleaseCorrelationCompletedV1(t *testing.T) {
	// 1 — the schema, the body, and the ordering proof on the upload path. TWO SBOMs are
	// uploaded, the second after the first, so the outbox holds another correlation's events
	// after the first completion: the assertions below hold per SBOM, which is the promise, and
	// would still hold if the second upload had never happened.
	t.Run("schema_and_ordering_new_sbom", func(t *testing.T) {
		pool := newPool(t)
		ctx := context.Background()
		// Each SBOM carries components with CVEs, so each unit of work raises real Knowledge
		// events (faultline_created + faultline_enriched + component_matched per card) BEFORE its
		// completion. An SBOM that raised nothing would make the ordering vacuous.
		disc := newCompletionDiscovery()
		disc.add(t, "pkg:deb/debian/openssl@3.0", "CVE-2024-8001")
		disc.add(t, "pkg:deb/debian/zlib@1.3", "CVE-2024-8002")
		disc.add(t, "pkg:deb/debian/curl@8.5", "CVE-2024-8003")
		inbox := completionUploadPath(t, pool, completionInventory{byEvidence: map[string][]string{
			testSBOMA:  {"pkg:deb/debian/openssl@3.0", "pkg:deb/debian/zlib@1.3"},
			testSBOMA2: {"pkg:deb/debian/curl@8.5"},
		}}, disc, nil, nil)

		if err := inbox.Handle(ctx, evidenceRegistered("evt-upload-a", testReleaseA, testSBOMA, "sbom")); err != nil {
			t.Fatalf("upload path: %v", err)
		}
		if err := inbox.Handle(ctx, evidenceRegistered("evt-upload-a2", testReleaseA2, testSBOMA2, "sbom")); err != nil {
			t.Fatalf("second upload path: %v", err)
		}

		// ONE completion per SBOM, each naming its own.
		if n := count(t, pool, "SELECT count(*) FROM knowledge_outbox WHERE event_type=$1", app.EventReleaseCorrelationCompleted); n != 2 {
			t.Fatalf("completion events = %d, want exactly one per SBOM", n)
		}
		for _, sbom := range []string{testSBOMA, testSBOMA2} {
			if n := count(t, pool,
				"SELECT count(*) FROM knowledge_outbox WHERE event_type=$1 AND payload->>'sbom_id'=$2",
				app.EventReleaseCorrelationCompleted, sbom); n != 1 {
				t.Errorf("completion events for sbom %s = %d, want 1", sbom, n)
			}
		}

		rows := correlationRows(t, pool, testReleaseA)
		if len(rows) < 4 {
			t.Fatalf("rows raised by this correlation = %d, want the fold/match events plus the completion: %+v", len(rows), rows)
		}
		completion, others := splitCompletion(t, rows)

		// (c) THE ORDERING PROOF, stored half: no event of THIS correlation carries a later
		// timestamp than its completion. Equality is permitted — a coarse or frozen clock can
		// stamp a whole unit of work alike — and the relay below is what makes a shared instant
		// still deliver in the promised order.
		for _, r := range others {
			if completion.occurredAt.Before(r.occurredAt) {
				t.Errorf("completion occurred_at %v precedes %q at %v", completion.occurredAt, r.eventType, r.occurredAt)
			}
		}

		// (a) + (b): the payload satisfies the checked-in v1 schema and says what it was asked to.
		assertCompletionSchema(t, completion.payload)
		body := decodeCompletion(t, completion.payload)
		if body.ReleaseID != testReleaseA || body.SBOMID != testSBOMA {
			t.Errorf("body = %+v, want release %s / sbom %s", body, testReleaseA, testSBOMA)
		}
		if body.Cause != domain.CauseNewSBOM {
			t.Errorf("cause = %q, want %q for an upload", body.Cause, domain.CauseNewSBOM)
		}
		if body.OccurredAt.IsZero() || !body.OccurredAt.Equal(completion.occurredAt) {
			t.Errorf("body occurred_at %v disagrees with the envelope's %v", body.OccurredAt, completion.occurredAt)
		}
		// RFC3339 on the wire, the form the schema's date-time annotation names.
		if _, err := time.Parse(time.RFC3339, rawCompletionField(t, completion.payload, "occurred_at")); err != nil {
			t.Errorf("occurred_at is not RFC3339: %v", err)
		}

		// THE ORDERING PROOF, delivered half: the bus numbers rows in append order, so the
		// relay's publish order IS the seq order. The completion's seq must exceed every other
		// event of THIS SBOM's correlation — nothing is claimed about the other SBOM's events.
		pub := &fakePublisher{}
		if _, err := store.NewRelay(pool, pub, 100).DeliverPending(ctx); err != nil {
			t.Fatalf("relay: %v", err)
		}
		if got := count(t, pool, "SELECT count(*) FROM knowledge_outbox WHERE sent_at IS NULL"); got != 0 {
			t.Fatalf("undelivered rows = %d, want the whole outbox drained", got)
		}
		assertCompletionDeliveredLast(t, pub, rows)
	})

	// 2 — an SBOM with nothing to report still publishes. Silence must mean a fault, never
	// "evaluated, clean": a subscriber cannot tell those apart, and the rebuild loop's stop
	// condition is literally "the targeted set is empty".
	t.Run("zero_match_publishes", func(t *testing.T) {
		pool := newPool(t)
		ctx := context.Background()
		inbox := completionUploadPath(t, pool, completionInventory{byEvidence: map[string][]string{
			testSBOMB: {"pkg:pypi/quiet@1"},
		}}, newCompletionDiscovery(), nil, nil)

		if err := inbox.Handle(ctx, evidenceRegistered("evt-upload-b", testReleaseB, testSBOMB, "sbom")); err != nil {
			t.Fatalf("upload path: %v", err)
		}

		rows := correlationRows(t, pool, testReleaseB)
		if len(rows) != 1 {
			t.Fatalf("rows = %+v, want exactly the completion event for a zero-match SBOM", rows)
		}
		completion, _ := splitCompletion(t, rows)
		assertCompletionSchema(t, completion.payload)
		body := decodeCompletion(t, completion.payload)
		if body.SBOMID != testSBOMB || body.Cause != domain.CauseNewSBOM {
			t.Errorf("body = %+v, want sbom %s with cause new_sbom", body, testSBOMB)
		}
	})

	// 3 — the re-discovery sweep publishes the SAME event with the other cause. Both causes are
	// exercised against one release here, which also proves the event is per correlation RUN:
	// the sweep's completion is a second event, ordered after everything the sweep raised.
	t.Run("cause_rediscovery", func(t *testing.T) {
		pool := newPool(t)
		ctx := context.Background()
		st := store.New(pool)
		disc := newCompletionDiscovery()
		corr := completionCorrelation(t, pool, service(pool), completionInventory{byEvidence: map[string][]string{
			testSBOMC: {"pkg:rpm/rocky/openssl@3.0.7"},
		}}, disc)
		inbox := store.NewInboxConsumer(pool, inbound.NewConsumer(app.NewCoordinator(corr, nil)))

		// The upload first — it stamps the KN-RECOR-1 ledger, which is what the sweep drains.
		if err := inbox.Handle(ctx, evidenceRegistered("evt-upload-c", testReleaseC, testSBOMC, "sbom")); err != nil {
			t.Fatalf("upload path: %v", err)
		}
		// A CVE the feeds did not know at upload time — the sweep's whole point, and it makes
		// the sweep raise its own fold/match events to be ordered against.
		disc.add(t, "pkg:rpm/rocky/openssl@3.0.7", "CVE-2026-9001")

		swept, newMatches, err := app.NewRediscoveryService(st, corr, realClock{}, time.Nanosecond, 10).Sweep(ctx)
		if err != nil || swept != 1 || newMatches != 1 {
			t.Fatalf("Sweep = (%d, %d, %v), want the release swept and the new CVE matched", swept, newMatches, err)
		}

		rows := correlationRows(t, pool, testReleaseC)
		completions := make([]outboxRow, 0, 2)
		for _, r := range rows {
			if r.eventType == app.EventReleaseCorrelationCompleted {
				completions = append(completions, r)
			}
		}
		if len(completions) != 2 {
			t.Fatalf("completion events = %d, want one per correlation run (the upload and the sweep)", len(completions))
		}
		if completions[1].occurredAt.Before(completions[0].occurredAt) {
			completions[0], completions[1] = completions[1], completions[0]
		}
		if got := decodeCompletion(t, completions[0].payload).Cause; got != domain.CauseNewSBOM {
			t.Errorf("first cause = %q, want new_sbom", got)
		}
		assertCompletionSchema(t, completions[1].payload)
		body := decodeCompletion(t, completions[1].payload)
		if body.Cause != domain.CauseRediscovery {
			t.Errorf("sweep cause = %q, want %q — a sweep must never read as a new upload", body.Cause, domain.CauseRediscovery)
		}
		if body.ReleaseID != testReleaseC || body.SBOMID != testSBOMC {
			t.Errorf("body = %+v, want the swept release/sbom", body)
		}
		// The sweep's completion is delivered after everything the sweep raised — the same
		// ordering promise, on the path that does NOT run inside an inbox transaction.
		pub := &fakePublisher{}
		if _, err := store.NewRelay(pool, pub, 100).DeliverPending(ctx); err != nil {
			t.Fatalf("relay: %v", err)
		}
		assertCompletionDeliveredLast(t, pub, rows)
	})

	// 3b — the mechanism under the ordering promise, exercised where it actually bites: a clock
	// that gives a whole unit of work ONE instant. Real correlation reads the clock per note, so
	// the timestamps normally differ on their own and nothing here would be tested; a frozen or
	// coarse clock is exactly the case the outbox cannot settle by itself, because it has no
	// sequence column. The relay's secondary sort is what carries it, and this is its regression
	// test rather than a restatement of it.
	t.Run("shared_instant_still_orders_the_completion_last", func(t *testing.T) {
		pool := newPool(t)
		ctx := context.Background()
		st := store.New(pool)
		instant := time.Unix(1_700_000_000, 0).UTC()

		// A card saved with NO notes, so the only rows in play are the two sharing the instant.
		card, err := domain.NewFaultline("fl-tie", cveID(t, "CVE-2024-8300"))
		if err != nil {
			t.Fatalf("faultline: %v", err)
		}
		if err := st.Save(ctx, card, true, 0, nil); err != nil {
			t.Fatalf("save: %v", err)
		}
		if _, err := st.RecordMatch(ctx, app.Match{
			ReleaseID: testReleaseE, FaultlineID: card.ID(), CVE: "CVE-2024-8300",
			Component: app.InventoryComponent{PURL: "pkg:deb/debian/openssl@3.0"}, OccurredAt: instant,
		}); err != nil {
			t.Fatalf("record match: %v", err)
		}
		if err := st.AnnounceCorrelationCompleted(ctx, testReleaseE, testSBOME, domain.CauseNewSBOM, instant); err != nil {
			t.Fatalf("announce: %v", err)
		}

		rows := correlationRows(t, pool, testReleaseE)
		completion, others := splitCompletion(t, rows)
		if len(others) != 1 {
			t.Fatalf("rows = %+v, want the match and the completion", rows)
		}
		if !completion.occurredAt.Equal(others[0].occurredAt) {
			t.Fatalf("the fixture must share one instant: %v vs %v", completion.occurredAt, others[0].occurredAt)
		}
		pub := &fakePublisher{}
		if _, err := store.NewRelay(pool, pub, 100).DeliverPending(ctx); err != nil {
			t.Fatalf("relay: %v", err)
		}
		assertCompletionDeliveredLast(t, pub, rows)
	})

	// 4 — only an SBOM completes a correlation. A VEX and a scanner-report upload both fold
	// knowledge and raise events, and neither may publish this one: there is no SBOM
	// correlation to declare finished, and a consumer that treated either as one would evaluate
	// a release on a posture nobody finished computing.
	t.Run("vex_and_scanner_report_do_not_publish", func(t *testing.T) {
		pool := newPool(t)
		ctx := context.Background()
		docs := completionDocs{}
		scan := newCompletionScanner(t, "pkg:rpm/rocky/httpd@2.4.37", "CVE-2024-8100")
		inbox := completionUploadPath(t, pool, completionInventory{}, newCompletionDiscovery(), docs, scan)

		if err := inbox.Handle(ctx, evidenceRegistered("evt-vex-d", testReleaseD, testVEXD, "vex")); err != nil {
			t.Fatalf("vex path: %v", err)
		}
		if err := inbox.Handle(ctx, evidenceRegistered("evt-scan-d", testReleaseD, testScanD, "scanner-report")); err != nil {
			t.Fatalf("scanner-report path: %v", err)
		}

		// Both paths really ran — otherwise this would pass for the wrong reason.
		if n := count(t, pool, "SELECT count(*) FROM knowledge_outbox"); n == 0 {
			t.Fatal("neither the VEX nor the scanner-report upload raised anything — the negative path proves nothing")
		}
		if n := count(t, pool, "SELECT count(*) FROM faultlines"); n != 2 {
			t.Errorf("faultlines = %d, want one from the VEX statement and one from the scanner finding", n)
		}
		if n := count(t, pool, "SELECT count(*) FROM knowledge_outbox WHERE event_type=$1", app.EventReleaseCorrelationCompleted); n != 0 {
			t.Errorf("completion events = %d, want 0 — only an SBOM completes a correlation", n)
		}
		for _, id := range []string{testVEXD, testScanD} {
			if n := count(t, pool,
				"SELECT count(*) FROM knowledge_outbox WHERE payload->>'sbom_id' = $1", id); n != 0 {
				t.Errorf("evidence %s produced %d completion events, want 0", id, n)
			}
		}
	})
}

// --- fixtures -------------------------------------------------------------------------------

// completionInventory is the Evidence inventory read phase, reduced to a PURL list per evidence
// id — so one wired path can serve two SBOMs with different contents.
type completionInventory struct{ byEvidence map[string][]string }

func (c completionInventory) GetInventory(_ context.Context, evidenceID string) (app.Inventory, error) {
	inv := app.Inventory{}
	for _, p := range c.byEvidence[evidenceID] {
		inv.Components = append(inv.Components, app.InventoryComponent{PURL: p, Name: p, Version: "1"})
	}
	return inv, nil
}

// completionDiscovery is the per-component discovery fan-out, scripted per PURL and mutable so
// a test can make the feeds learn something between an upload and a sweep.
type completionDiscovery struct{ byPURL map[string][]app.ProposalFor }

func newCompletionDiscovery() *completionDiscovery {
	return &completionDiscovery{byPURL: map[string][]app.ProposalFor{}}
}

func (d *completionDiscovery) add(t *testing.T, purl, cve string) {
	t.Helper()
	d.byPURL[purl] = append(d.byPURL[purl], app.ProposalFor{
		CVE: cveID(t, cve), Proposal: vulnFacts(t, "nvd", value.SeverityHigh),
	})
}

func (d *completionDiscovery) VulnsForPackage(_ context.Context, c app.InventoryComponent) ([]app.ProposalFor, error) {
	return d.byPURL[c.PURL], nil
}

// completionDocs + completionParser stand in for an uploaded VEX document: one applicability
// statement, which folds onto a card and therefore raises real Knowledge events.
type completionDocs struct{}

func (completionDocs) GetDocument(_ context.Context, _ string) ([]byte, string, error) {
	return []byte(`{}`), "vex", nil
}

type completionParser struct{}

func (completionParser) Parse([]byte) ([]app.VEXStatement, error) {
	return []app.VEXStatement{{
		CVE: "CVE-2024-8200", Package: "openssl", Status: "not_affected",
		Justification: "vulnerable_code_not_present",
	}}, nil
}

// completionScanner stands in for an uploaded scanner report: one finding, which folds and
// records a match.
type completionScanner struct{ props []app.ScannerProposal }

func newCompletionScanner(t *testing.T, purl, cve string) *completionScanner {
	t.Helper()
	return &completionScanner{props: []app.ScannerProposal{{
		CVE:       cveID(t, cve),
		Proposal:  vulnFacts(t, "nvd", value.SeverityHigh),
		Component: app.InventoryComponent{PURL: purl, Name: "httpd", Version: "2.4.37"},
		Origin:    "scanner/trivy",
	}}}
}

func (s *completionScanner) ScannerProposals(_ context.Context, _ string) ([]app.ScannerProposal, int, error) {
	return s.props, 0, nil
}

// completionCorrelation builds the real correlation service over the real store — the store is
// the match recorder, the re-discovery ledger AND the completion announcer, exactly as
// production wiring assembles it. fold is shared by every path a test wires: one
// FaultlineService means one id generator, so two paths cannot mint the same Faultline id.
func completionCorrelation(t *testing.T, pool *pgxpool.Pool, fold *app.FaultlineService, inv app.InventoryReader, disc app.PackageVulnSource) *app.CorrelationService {
	t.Helper()
	st := store.New(pool)
	return app.NewCorrelationService(inv, disc, fold, st, realClock{}).
		WithLedger(st).WithCompletion(st)
}

// completionUploadPath wires the whole inbound path an Evidence upload takes: the inbound
// consumer decoding the wire event, the coordinator dispatching on the evidence KIND, and the
// inbox consumer owning the transaction every write joins. Driving the real path is what makes
// the kind gate a gate rather than a claim. docs/scan may be nil when the test drives only SBOMs.
func completionUploadPath(
	t *testing.T, pool *pgxpool.Pool, inv app.InventoryReader, disc app.PackageVulnSource,
	docs app.DocumentReader, scan app.ScannerReportSource,
) *store.InboxConsumer {
	t.Helper()
	fold := service(pool)
	var vexSvc *app.VEXApplicabilityService
	if docs != nil {
		vexSvc = app.NewVEXApplicabilityService(docs, completionParser{}, fold, realClock{})
	}
	coord := app.NewCoordinator(completionCorrelation(t, pool, fold, inv, disc), vexSvc)
	if scan != nil {
		coord = coord.WithScanner(app.NewScannerReportService(scan, fold, store.New(pool), realClock{}))
	}
	return store.NewInboxConsumer(pool, inbound.NewConsumer(coord))
}

// evidenceRegistered builds the Evidence wire event the inbound consumer decodes.
func evidenceRegistered(envelopeID, releaseID, evidenceID, kind string) event.Envelope {
	payload, _ := json.Marshal(map[string]string{
		"evidence_id": evidenceID, "kind": kind, "subject_release_id": releaseID,
	})
	return event.Envelope{ID: envelopeID, Type: "EvidenceRegistered", Payload: payload}
}

// --- assertions -----------------------------------------------------------------------------

type outboxRow struct {
	id         string
	eventType  string
	subject    string
	payload    []byte
	occurredAt time.Time
}

// correlationRows returns the outbox rows raised by ONE release's correlation: the events that
// name the release (the matches and the completion) plus the card events of the cards it matched
// (whose subject is the faultline id). This is the set the ordering promise is about — scoping
// to it is what keeps the assertions from enshrining a global order the contract does not claim.
// The row id is also the kernel Envelope id the relay publishes, which is how the delivered
// order is scoped to the same set.
func correlationRows(t *testing.T, pool *pgxpool.Pool, releaseID string) []outboxRow {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT id, event_type, subject, payload, occurred_at
		FROM knowledge_outbox
		WHERE payload->>'ReleaseID' = $1
		   OR payload->>'release_id' = $1
		   OR subject IN (SELECT faultline_id FROM faultline_matches WHERE release_id = $1)
		ORDER BY occurred_at`, releaseID)
	if err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	defer rows.Close()
	var out []outboxRow
	for rows.Next() {
		var r outboxRow
		if err := rows.Scan(&r.id, &r.eventType, &r.subject, &r.payload, &r.occurredAt); err != nil {
			t.Fatalf("scan outbox: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("outbox rows: %v", err)
	}
	return out
}

// splitCompletion separates the one completion row from the events it concludes.
func splitCompletion(t *testing.T, rows []outboxRow) (outboxRow, []outboxRow) {
	t.Helper()
	var completion outboxRow
	var others []outboxRow
	found := 0
	for _, r := range rows {
		if r.eventType == app.EventReleaseCorrelationCompleted {
			completion = r
			found++
			continue
		}
		others = append(others, r)
	}
	if found != 1 {
		t.Fatalf("completion rows = %d, want exactly 1: %+v", found, rows)
	}
	return completion, others
}

// assertCompletionDeliveredLast proves the seq ordering: among the envelopes belonging to this
// correlation, every completion is published after every event it concludes. The bus numbers
// rows in append order, so the relay's publish order is the seq order.
func assertCompletionDeliveredLast(t *testing.T, pub *fakePublisher, rows []outboxRow) {
	t.Helper()
	inSet := make(map[string]string, len(rows))
	for _, r := range rows {
		inSet[r.id] = r.eventType
	}
	lastOther, lastCompletion := -1, -1
	seen := 0
	for i, env := range pub.delivered {
		typ, ok := inSet[env.ID]
		if !ok {
			continue // another SBOM's correlation — the promise says nothing about it
		}
		seen++
		if typ == app.EventReleaseCorrelationCompleted {
			if lastOther > i {
				t.Errorf("a completion was published at %d, before an event of its own correlation at %d", i, lastOther)
			}
			lastCompletion = i
			continue
		}
		lastOther = i
	}
	if seen != len(rows) {
		t.Fatalf("delivered %d of this correlation's %d rows", seen, len(rows))
	}
	if lastCompletion < lastOther {
		t.Errorf("the last completion published at %d precedes an event of its correlation at %d — its bus seq must exceed every other event for that SBOM",
			lastCompletion, lastOther)
	}
}

// completionSchemaFS embeds the checked-in schema so the assertion reads the SAME artifact a
// consumer is handed, and reads it without depending on the test's working directory.
//
//go:embed schemas/knowledge.release_correlation_completed.v1.schema.json
var completionSchemaFS embed.FS

func assertCompletionSchema(t *testing.T, payload []byte) {
	t.Helper()
	const name = "knowledge.release_correlation_completed.v1.schema.json"
	raw, err := completionSchemaFS.ReadFile("schemas/" + name)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(name, doc); err != nil {
		t.Fatalf("add schema: %v", err)
	}
	sch, err := c.Compile(name)
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Errorf("payload fails %s:\npayload=%s\nerror=%v", name, payload, err)
	}
}

func decodeCompletion(t *testing.T, payload []byte) domain.ReleaseCorrelationCompleted {
	t.Helper()
	var body domain.ReleaseCorrelationCompleted
	if err := json.Unmarshal(payload, &body); err != nil {
		t.Fatalf("decode completion payload %s: %v", payload, err)
	}
	return body
}

// rawCompletionField reads a field as it appears ON THE WIRE, before Go re-parses it.
func rawCompletionField(t *testing.T, payload []byte, field string) string {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	s, ok := raw[field].(string)
	if !ok {
		t.Fatalf("payload %s has no string %q", payload, field)
	}
	return s
}
