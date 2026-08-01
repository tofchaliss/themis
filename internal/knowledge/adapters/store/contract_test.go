package store

import (
	"bytes"
	"embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
	"github.com/themis-project/themis/internal/kernel/value"
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
			OccurredAt:      now,
		}},
		{app.EventFaultlineMatured, domain.FaultlineMatured{FaultlineID: "fl-1", CVE: "CVE-2024-1", OccurredAt: now}},
		{app.EventFaultlineSuperseded, domain.FaultlineSuperseded{FaultlineID: "fl-1", CVE: "CVE-2024-1", OccurredAt: now}},
		{app.EventComponentMatched, domain.ComponentMatched{
			FaultlineID: "fl-1", CVE: "CVE-2024-1", ReleaseID: "rel-1",
			Components: []domain.MatchedComponent{{PURL: "pkg:deb/debian/openssl@3.0.11", Name: "openssl", Version: "3.0.11", Ecosystem: "deb"}},
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

func TestSchemaRefFor_UnmappedFallsBackToRawType(t *testing.T) {
	if got := schemaRefFor("knowledge.unknown_event"); got != "knowledge.unknown_event" {
		t.Errorf("unmapped schemaRefFor = %q, want raw type", got)
	}
}
