package store

import (
	"bytes"
	"embed"
	"encoding/json"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/themis-project/themis/internal/evidence/domain"
)

// Integration-contract v1 guard (M5 EB-03 / D9 / BCK-0046). The payload the store
// marshals onto the outbox must satisfy the checked-in schema pinned by its schema_ref.
// A domain refactor that reshapes the wire (rename/retype/drop a field) fails here
// rather than silently breaking a consumer.

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

// assertValidContract marshals nothing itself: callers pass the exact bytes the store
// would write to the outbox, so the guard tracks the real wire shape.
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

func TestIntegrationContractV1_EvidenceRegistered(t *testing.T) {
	ev := domain.EvidenceRegistered{
		EvidenceID:       "ev-1",
		Kind:             domain.KindSBOM,
		SubjectReleaseID: "rel-1",
		Fingerprint:      "sha256:abc",
		OccurredAt:       time.Unix(1_700_000_000, 0).UTC(),
	}
	raw, err := json.Marshal(newEventPayload(ev))
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	assertValidContract(t, schemaRefEvidenceRegistered, raw)
}
