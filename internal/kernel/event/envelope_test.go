package event_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/themis-project/themis/internal/kernel/event"
)

var occurred = time.Unix(1_700_000_000, 0)

func TestNewEnvelope_Valid(t *testing.T) {
	e, err := event.NewEnvelope("evt-1", "evidence.registered", "evidence", "rel-1",
		"evidence.registered.v1", "corr-1", occurred, json.RawMessage(`{"k":"v"}`))
	if err != nil {
		t.Fatalf("valid envelope: %v", err)
	}
	if e.OccurredAt.Location() != time.UTC {
		t.Errorf("occurred-at not normalized to UTC: %v", e.OccurredAt.Location())
	}
	if e.ID != "evt-1" || e.Type != "evidence.registered" || e.CorrelationID != "corr-1" {
		t.Errorf("envelope = %+v", e)
	}
}

func TestNewEnvelope_Invalid(t *testing.T) {
	// Each case blanks exactly one required field (or zeroes the time).
	for name, tc := range map[string]struct {
		id, typ, source, subject, schemaRef, corr string
		at                                        time.Time
	}{
		"emptyID":       {"", "t", "evidence", "rel-1", "s", "c", occurred},
		"emptyType":     {"e", "", "evidence", "rel-1", "s", "c", occurred},
		"emptySource":   {"e", "t", "", "rel-1", "s", "c", occurred},
		"emptySubject":  {"e", "t", "evidence", "", "s", "c", occurred},
		"emptySchema":   {"e", "t", "evidence", "rel-1", "", "c", occurred},
		"emptyCorr":     {"e", "t", "evidence", "rel-1", "s", "", occurred},
		"zeroOccurred":  {"e", "t", "evidence", "rel-1", "s", "c", time.Time{}},
		"whitespaceID":  {"   ", "t", "evidence", "rel-1", "s", "c", occurred},
	} {
		if _, err := event.NewEnvelope(tc.id, tc.typ, tc.source, tc.subject, tc.schemaRef, tc.corr, tc.at, nil); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestEnvelopeSchema_GoldenFixtures(t *testing.T) {
	sch := compileSchema(t)

	// A constructed envelope's wire form must satisfy the schema.
	e, _ := event.NewEnvelope("evt-1", "evidence.registered", "evidence", "rel-1",
		"evidence.registered.v1", "corr-1", occurred, json.RawMessage(`{"k":"v"}`))
	raw, _ := json.Marshal(e)
	if err := validateJSON(t, sch, raw); err != nil {
		t.Errorf("marshaled envelope fails its own schema: %v", err)
	}

	// A thin envelope (no payload) is valid.
	valid := `{"id":"evt-2","type":"faultline.enriched","occurred_at":"2024-01-02T03:04:05Z",` +
		`"source_context":"knowledge","subject":"CVE-2024-1","schema_ref":"faultline.enriched.v1","correlation_id":"c2"}`
	if err := validateJSON(t, sch, []byte(valid)); err != nil {
		t.Errorf("valid thin fixture rejected: %v", err)
	}

	for name, fixture := range map[string]string{
		"missingCorrelation": `{"id":"e","type":"t","occurred_at":"2024-01-02T03:04:05Z","source_context":"s","subject":"x","schema_ref":"r"}`,
		"emptyID":            `{"id":"","type":"t","occurred_at":"2024-01-02T03:04:05Z","source_context":"s","subject":"x","schema_ref":"r","correlation_id":"c"}`,
		"additionalProperty": `{"id":"e","type":"t","occurred_at":"2024-01-02T03:04:05Z","source_context":"s","subject":"x","schema_ref":"r","correlation_id":"c","bogus":1}`,
	} {
		if err := validateJSON(t, sch, []byte(fixture)); err == nil {
			t.Errorf("%s: invalid fixture accepted by schema", name)
		}
	}
}

func compileSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(event.Schema()))
	if err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("envelope.schema.json", doc); err != nil {
		t.Fatalf("add resource: %v", err)
	}
	sch, err := c.Compile("envelope.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	return sch
}

func validateJSON(t *testing.T, sch *jsonschema.Schema, raw []byte) error {
	t.Helper()
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unmarshal instance: %v", err)
	}
	return sch.Validate(inst)
}
