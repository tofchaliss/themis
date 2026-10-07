//go:build integration

package store_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
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

// N-M2a (EDR-DELIVERY-01 M2-1): Knowledge publishes knowledge.release_correlation_completed.v1
// ONCE per SBOM, appended to the outbox after every other Knowledge event for that SBOM, with
// the discovery cause carried through from the path that ran correlation.
//
// The ordering is the only reason this event exists rather than a timer, so it is the thing
// this test proves hardest: the outbox is what the relay drains `ORDER BY occurred_at`, and the
// bus assigns `seq` in append order, so "its seq exceeds every other event for that SBOM" is
// exactly "its outbox timestamp exceeds every other row's, and the relay therefore publishes it
// last". Both halves are asserted — the stored order and the delivered order — because an
// assertion on the stored rows alone would not notice a relay that reordered them.
//
// These are UUID ids on purpose: the schema annotates both as `format: uuid`, and the estate
// carries real Registry/Evidence identities here.
const (
	testReleaseA = "8f1b6f2e-5a61-4a2e-9d0e-7c0f1f7a1b11"
	testSBOMA    = "2c7b1f90-3d44-4f0e-8a71-19b2c6d5e4f3"
	testReleaseB = "b4d6c1a8-9f2e-4c7b-8e15-3a0d9c6b2f44"
	testSBOMB    = "6e9a7c25-1b48-4d3a-9f60-8c2e5b7d1a09"
	testReleaseC = "d1c3b5a7-2e49-4f81-9a6b-0c7d8e2f3a51"
	testSBOMC    = "f0a2c4e6-7b19-4d53-8e2a-5c1b9d6f3e82"
	testReleaseD = "3b7e9d41-6c28-4a0f-95d3-7e1a2c8b4f60"
	testVEXD     = "a5c8e1f3-4d72-4b09-86ae-2f9c7b0d5e31"
	testScanD    = "7d4b2f60-8e13-4c95-a0f7-1b6e3d9c2850"
)

func TestEventSchema_Knowledge_ReleaseCorrelationCompletedV1(t *testing.T) {
	// 1 — the schema, the body, and the ordering proof on the upload path.
	t.Run("schema_and_ordering_new_sbom", func(t *testing.T) {
		pool := newPool(t)
		ctx := context.Background()
		// Two components, each carrying a CVE, so the unit of work raises real Knowledge events
		// (faultline_created + faultline_enriched + component_matched per card) BEFORE the
		// completion. An SBOM that raised nothing would make the ordering vacuous.
		disc := newCompletionDiscovery()
		disc.add(t, "pkg:deb/debian/openssl@3.0", "CVE-2024-8001")
		disc.add(t, "pkg:deb/debian/zlib@1.3", "CVE-2024-8002")
		inbox := completionUploadPath(t, pool, completionInventory{
			purls: []string{"pkg:deb/debian/openssl@3.0", "pkg:deb/debian/zlib@1.3"},
		}, disc, nil, nil)

		if err := inbox.Handle(ctx, evidenceRegistered("evt-upload-a", testReleaseA, testSBOMA, "sbom")); err != nil {
			t.Fatalf("upload path: %v", err)
		}

		rows := outboxRows(t, pool)
		if len(rows) < 4 {
			t.Fatalf("outbox rows = %d, want the fold/match events plus the completion: %+v", len(rows), rows)
		}
		if n := count(t, pool, "SELECT count(*) FROM knowledge_outbox WHERE event_type=$1", app.EventReleaseCorrelationCompleted); n != 1 {
			t.Fatalf("completion events = %d, want exactly 1 per SBOM", n)
		}

		// (c) THE ORDERING PROOF, stored half: the completion is the last row by occurred_at,
		// and strictly after the one before it — a tie would leave the relay's order undefined,
		// which is the very guarantee this event is supposed to provide.
		last := rows[len(rows)-1]
		if last.eventType != app.EventReleaseCorrelationCompleted {
			t.Fatalf("last outbox row is %q, want the completion event appended after every other event for this SBOM", last.eventType)
		}
		for _, r := range rows[:len(rows)-1] {
			if !last.occurredAt.After(r.occurredAt) {
				t.Errorf("completion occurred_at %v is not strictly after %q at %v", last.occurredAt, r.eventType, r.occurredAt)
			}
		}

		// (a) + (b): the payload satisfies the checked-in v1 schema and says what it was asked to.
		assertCompletionSchema(t, last.payload)
		body := decodeCompletion(t, last.payload)
		if body.ReleaseID != testReleaseA || body.SBOMID != testSBOMA {
			t.Errorf("body = %+v, want release %s / sbom %s", body, testReleaseA, testSBOMA)
		}
		if body.Cause != domain.CauseNewSBOM {
			t.Errorf("cause = %q, want %q for an upload", body.Cause, domain.CauseNewSBOM)
		}
		if body.OccurredAt.IsZero() || !body.OccurredAt.Equal(last.occurredAt) {
			t.Errorf("body occurred_at %v disagrees with the envelope's %v", body.OccurredAt, last.occurredAt)
		}
		// RFC3339 on the wire, the form the schema's date-time annotation names.
		if _, err := time.Parse(time.RFC3339, rawCompletionField(t, last.payload, "occurred_at")); err != nil {
			t.Errorf("occurred_at is not RFC3339: %v", err)
		}

		// THE ORDERING PROOF, delivered half: the bus numbers rows in append order, so the
		// relay's publish order IS the seq order. The completion must be published last.
		pub := &fakePublisher{}
		delivered, err := store.NewRelay(pool, pub, 100).DeliverPending(ctx)
		if err != nil || delivered != len(rows) {
			t.Fatalf("relay delivered (%d, %v), want %d/nil", delivered, err, len(rows))
		}
		for i, env := range pub.delivered {
			if env.Type == app.EventReleaseCorrelationCompleted && i != len(pub.delivered)-1 {
				t.Fatalf("completion published at position %d of %d — its bus seq must exceed every other event for this SBOM",
					i, len(pub.delivered))
			}
		}
		if got := pub.delivered[len(pub.delivered)-1]; got.Type != app.EventReleaseCorrelationCompleted || got.Subject != testReleaseA {
			t.Errorf("last delivered = %q/%q, want the completion event subjected to the release", got.Type, got.Subject)
		}
	})

	// 2 — an SBOM with nothing to report still publishes. Silence must mean a fault, never
	// "evaluated, clean": a subscriber cannot tell those apart, and the rebuild loop's stop
	// condition is literally "the targeted set is empty".
	t.Run("zero_match_publishes", func(t *testing.T) {
		pool := newPool(t)
		ctx := context.Background()
		inbox := completionUploadPath(t, pool, completionInventory{purls: []string{"pkg:pypi/quiet@1"}},
			newCompletionDiscovery(), nil, nil)

		if err := inbox.Handle(ctx, evidenceRegistered("evt-upload-b", testReleaseB, testSBOMB, "sbom")); err != nil {
			t.Fatalf("upload path: %v", err)
		}

		rows := outboxRows(t, pool)
		if len(rows) != 1 || rows[0].eventType != app.EventReleaseCorrelationCompleted {
			t.Fatalf("outbox = %+v, want exactly the completion event for a zero-match SBOM", rows)
		}
		assertCompletionSchema(t, rows[0].payload)
		body := decodeCompletion(t, rows[0].payload)
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
		corr := completionCorrelation(t, pool, service(pool),
			completionInventory{purls: []string{"pkg:rpm/rocky/openssl@3.0.7"}}, disc)
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

		rows := outboxRows(t, pool)
		completions := make([]outboxRow, 0, 2)
		for _, r := range rows {
			if r.eventType == app.EventReleaseCorrelationCompleted {
				completions = append(completions, r)
			}
		}
		if len(completions) != 2 {
			t.Fatalf("completion events = %d, want one per correlation run (the upload and the sweep)", len(completions))
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
		// The sweep's completion is last overall: ordered after the match it just raised.
		if rows[len(rows)-1].payload == nil || !completions[1].occurredAt.Equal(rows[len(rows)-1].occurredAt) {
			t.Errorf("the sweep's completion is not the last outbox row: %+v", rows)
		}
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

// completionInventory is the Evidence inventory read phase, reduced to a PURL list.
type completionInventory struct{ purls []string }

func (c completionInventory) GetInventory(_ context.Context, _ string) (app.Inventory, error) {
	inv := app.Inventory{}
	for _, p := range c.purls {
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
// production wiring assembles it.
// fold is shared by every path a test wires: one FaultlineService means one id generator, so
// two paths in the same test cannot mint the same Faultline id.
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
	eventType  string
	schemaRef  string
	subject    string
	payload    []byte
	occurredAt time.Time
}

// outboxRows reads the outbox in the order the relay drains it.
func outboxRows(t *testing.T, pool *pgxpool.Pool) []outboxRow {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT event_type, schema_ref, subject, payload, occurred_at FROM knowledge_outbox ORDER BY occurred_at`)
	if err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	defer rows.Close()
	var out []outboxRow
	for rows.Next() {
		var r outboxRow
		if err := rows.Scan(&r.eventType, &r.schemaRef, &r.subject, &r.payload, &r.occurredAt); err != nil {
			t.Fatalf("scan outbox: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("outbox rows: %v", err)
	}
	return out
}

// assertCompletionSchema validates a payload against the CHECKED-IN v1 schema file — the same
// artifact a consumer is handed, read from disk rather than restated here.
func assertCompletionSchema(t *testing.T, payload []byte) {
	t.Helper()
	const name = "knowledge.release_correlation_completed.v1.schema.json"
	raw, err := os.ReadFile("schemas/" + name)
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
