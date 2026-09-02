package store

import (
	"bytes"
	"embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// Integration-contract v1 guard (M5 EB-03 / D9 / BCK-0046). Each published event type's
// marshaled payload must satisfy the schema pinned by its schema_ref, so a domain refactor
// that reshapes the wire (rename/retype/drop a field) fails here rather than silently
// breaking a consumer.

//go:embed schemas/*.schema.json
var schemaFS embed.FS

func compileContract(t *testing.T, schemaRef string) *jsonschema.Schema {
	t.Helper()
	name := schemaRef + ".schema.json"
	raw, err := schemaFS.ReadFile("schemas/" + name)
	if err != nil {
		t.Fatalf("read schema %s: %v", name, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unmarshal schema %s: %v", name, err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(name, doc); err != nil {
		t.Fatalf("add resource %s: %v", name, err)
	}
	sch, err := c.Compile(name)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return sch
}

func assertValidContract(t *testing.T, schemaRef string, raw []byte) {
	t.Helper()
	sch := compileContract(t, schemaRef)
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Errorf("payload fails %s:\npayload=%s\nerror=%v", schemaRef, raw, err)
	}
}

func TestIntegrationContractV1_KnowledgeEvents(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cases := []struct {
		eventType string
		event     any
	}{
		{app.EventFaultlineCreated, domain.FaultlineCreated{FaultlineID: "fl-1", CVE: "CVE-2024-1", OccurredAt: now}},
		{app.EventFaultlineEnriched, domain.FaultlineEnriched{
			FaultlineID: "fl-1", CVE: "CVE-2024-1", Severity: value.SeverityHigh, KEV: true, ExploitPublic: false,
			Applicabilities: []domain.Applicability{{Package: "pkg:rpm/openssl", Status: "not_affected", Justification: "vulnerable_code_not_present"}},
			HeadlineTrust:   value.TrustObserved,
			RangeTrust:      value.TrustAsserted,
			SignalTrust:     value.TrustObserved,
			OccurredAt:      now,
		}},
		{app.EventFaultlineMatured, domain.FaultlineMatured{FaultlineID: "fl-1", CVE: "CVE-2024-1", OccurredAt: now}},
		{app.EventFaultlineSuperseded, domain.FaultlineSuperseded{FaultlineID: "fl-1", CVE: "CVE-2024-1", OccurredAt: now}},
		{app.EventComponentMatched, domain.ComponentMatched{
			FaultlineID: "fl-1", CVE: "CVE-2024-1", ReleaseID: "rel-1",
			// Every additive field is set so the schema actually validates it — a sample that
			// leaves an omitempty field empty removes that field from the contract guard.
			Components: []domain.MatchedComponent{{
				PURL: "pkg:deb/debian/openssl@3.0.11", Name: "openssl", Version: "3.0.11", Ecosystem: "deb",
				Source: "openssl", ClaimClass: domain.ClaimCarrier, DetectionOrigin: "scanner/trivy",
				VerdictState: domain.VerdictClearedVendorFix, VerdictGrade: domain.VerdictGradeObserved,
				VerdictReason: "vendor fix 3.0.12 present",
			}},
			Score: 72, Priority: "high",
			Fixes:      []domain.FixedVersion{{Package: "openssl", Version: "3.0.12", Ecosystem: "deb"}},
			OccurredAt: now,
		}},
		{app.EventComponentVerdictChanged, domain.ComponentVerdictChanged{
			FaultlineID: "fl-1", CVE: "CVE-2024-1", ReleaseID: "rel-1",
			Component: domain.MatchedComponent{
				PURL: "pkg:rpm/rocky/python3-setuptools@39.2.0-9.el8_10", Name: "python3-setuptools",
				Version: "39.2.0-9.el8_10", Ecosystem: "rpm", Source: "python-setuptools",
				ClaimClass: domain.ClaimCarrier, DetectionOrigin: "discovery",
				VerdictState: domain.VerdictClearedVendorFix, VerdictGrade: domain.VerdictGradeObserved,
				VerdictReason: "vendor fix 0:39.2.0-9.el8_10 present: installed 39.2.0-9.el8_10 is at/above the same-stream bound for python-setuptools",
			},
			OccurredAt: now,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.eventType, func(t *testing.T) {
			raw, err := json.Marshal(tc.event)
			if err != nil {
				t.Fatalf("marshal %s: %v", tc.eventType, err)
			}
			assertValidContract(t, schemaRefFor(tc.eventType), raw)
		})
	}

	// Completeness: every mapped type is exercised above, and the number of checked-in
	// schema files matches the number of frozen event types (no orphan / missing schema).
	if len(cases) != len(schemaRefByEventType) {
		t.Errorf("cases=%d but schemaRefByEventType=%d; freeze every published event type", len(cases), len(schemaRefByEventType))
	}
	files, err := schemaFS.ReadDir("schemas")
	if err != nil {
		t.Fatalf("read schemas dir: %v", err)
	}
	if len(files) != len(schemaRefByEventType) {
		t.Errorf("schema files=%d but frozen event types=%d", len(files), len(schemaRefByEventType))
	}
}

// The trust classes are an ADDITIVE change to the frozen v1 contract, not a v2 — the same
// treatment Score and Applicabilities got (EVENTBUS D9). Two things must hold for that to be
// legitimate, and both are asserted here: a card with no trust yet marshals byte-identically
// to the pre-change wire (omitempty, so the keys are simply absent), and a card with trust
// still validates against v1. If either broke, this would need a v2 + a new schema_ref.
func TestIntegrationContractV1_FaultlineEnrichedTrustIsAdditive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	ref := schemaRefFor(app.EventFaultlineEnriched)

	withoutTrust, err := json.Marshal(domain.FaultlineEnriched{
		FaultlineID: "fl-1", CVE: "CVE-2024-1", Severity: value.SeverityHigh, OccurredAt: now,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	assertValidContract(t, ref, withoutTrust)
	for _, key := range []string{"HeadlineTrust", "RangeTrust", "SignalTrust"} {
		if bytes.Contains(withoutTrust, []byte(key)) {
			t.Errorf("unset trust must be omitted from the wire, found %q in %s", key, withoutTrust)
		}
	}

	withTrust, err := json.Marshal(domain.FaultlineEnriched{
		FaultlineID: "fl-1", CVE: "CVE-2024-1", Severity: value.SeverityHigh, OccurredAt: now,
		HeadlineTrust: value.TrustObserved, RangeTrust: value.TrustAsserted, SignalTrust: value.TrustInferred,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	assertValidContract(t, ref, withTrust)
}

// The schema pins the class vocabulary, so a typo or a renamed class fails the contract
// rather than reaching Governance as an unrecognized string.
func TestIntegrationContractV1_RejectsUnknownTrustClass(t *testing.T) {
	raw := []byte(`{"FaultlineID":"fl-1","CVE":"CVE-2024-1","Severity":"high","KEV":false,` +
		`"ExploitPublic":false,"HeadlineTrust":"probably-fine","OccurredAt":"2023-11-14T22:13:20Z"}`)
	sch := compileContract(t, schemaRefFor(app.EventFaultlineEnriched))
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if err := sch.Validate(doc); err == nil {
		t.Fatal("expected an unknown trust class to fail the contract")
	}
}

func TestSchemaRefFor_UnmappedFallsBackToRawType(t *testing.T) {
	if got := schemaRefFor("knowledge.unknown_event"); got != "knowledge.unknown_event" {
		t.Errorf("unmapped schemaRefFor = %q, want raw type", got)
	}
}
