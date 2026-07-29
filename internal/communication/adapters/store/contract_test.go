package store

import (
	"bytes"
	"embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
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

func TestIntegrationContractV1_CommunicationEvents(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	cases := []struct {
		eventType string
		event     any
	}{
		{app.EventPublicationCreated, domain.PublicationCreated{PublicationID: "pub-1", Type: domain.ArtifactVEX, Stance: domain.StanceAffected, ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-2024-1", OccurredAt: now}},
		{app.EventPublicationDelivered, domain.PublicationDelivered{PublicationID: "pub-1", Channel: "vex-feed", OccurredAt: now}},
		{app.EventPublicationSuperseded, domain.PublicationSuperseded{PublicationID: "pub-1", SupersededByID: "pub-2", OccurredAt: now}},
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
	if got := schemaRefFor("communication.unknown_event"); got != "communication.unknown_event" {
		t.Errorf("unmapped schemaRefFor = %q, want raw type", got)
	}
}
