package domain

import (
	"errors"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func validRaw() []byte {
	return []byte(`{"finding_id":"F1","recommended_stance":"affected","confidence":0.8,` +
		`"evidence":[{"kind":"faultline","ref":"FL1"}],"reasoning":"grounded"}`)
}

func groundedContext() AssembledContext {
	return AssembledContext{
		Finding:   FindingView{ID: "F1", FaultlineID: "FL1", CVE: "CVE-1"},
		Faultline: FaultlineView{ID: "FL1", CVE: "CVE-1"},
	}
}

func TestNewValidatorErrors(t *testing.T) {
	if _, err := NewValidator(Capability{OutputSchema: "{not json"}); err == nil {
		t.Error("invalid schema JSON should error")
	}
	if _, err := NewValidator(Capability{OutputSchema: `{"type": 5}`}); err == nil {
		t.Error("invalid schema (bad type) should fail to compile")
	}

	orig := addResource
	addResource = func(_ *jsonschema.Compiler, _ string, _ any) error { return errors.New("forced") }
	defer func() { addResource = orig }()
	if _, err := NewValidator(RecommendPositionV1()); err == nil {
		t.Error("forced add-resource error expected")
	}
}

func TestValidateSchema(t *testing.T) {
	v, err := NewValidator(RecommendPositionV1())
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	if err := v.ValidateSchema(validRaw()); err != nil {
		t.Errorf("valid output should pass schema: %v", err)
	}
	if err := v.ValidateSchema([]byte("{not json")); !errors.Is(err, ErrSchemaInvalid) {
		t.Errorf("malformed JSON → ErrSchemaInvalid, got %v", err)
	}
	// Structurally wrong (stance not in enum, missing required fields).
	if err := v.ValidateSchema([]byte(`{"finding_id":"F1","recommended_stance":"deferred","confidence":2}`)); !errors.Is(err, ErrSchemaInvalid) {
		t.Errorf("schema mismatch → ErrSchemaInvalid, got %v", err)
	}
}

func TestValidateBusiness(t *testing.T) {
	v, _ := NewValidator(RecommendPositionV1())
	ac := groundedContext()

	out, err := ParseOutput(validRaw())
	if err != nil {
		t.Fatalf("ParseOutput: %v", err)
	}
	if err := v.ValidateBusiness(out, "F1", ac); err != nil {
		t.Errorf("grounded output should pass business validation: %v", err)
	}

	// finding_id mismatch
	if err := v.ValidateBusiness(out, "OTHER", ac); !errors.Is(err, ErrBusinessInvalid) {
		t.Errorf("finding mismatch → ErrBusinessInvalid, got %v", err)
	}
	// confidence out of range
	bad := out
	bad.Confidence = 1.5
	if err := v.ValidateBusiness(bad, "F1", ac); !errors.Is(err, ErrBusinessInvalid) {
		t.Errorf("confidence out of range → ErrBusinessInvalid, got %v", err)
	}
	// disallowed stance
	bad = out
	bad.RecommendedStance = "deferred"
	if err := v.ValidateBusiness(bad, "F1", ac); !errors.Is(err, ErrBusinessInvalid) {
		t.Errorf("disallowed stance → ErrBusinessInvalid, got %v", err)
	}
	// ungrounded evidence
	bad = out
	bad.Evidence = []RawEvidence{{Kind: "cve", Ref: "CVE-9999-9999"}}
	if err := v.ValidateBusiness(bad, "F1", ac); !errors.Is(err, ErrBusinessInvalid) {
		t.Errorf("ungrounded evidence → ErrBusinessInvalid, got %v", err)
	}
}

func TestStanceAllowedFallThrough(t *testing.T) {
	// A recommendable stance that the capability does not allow must be rejected
	// (covers stanceAllowed's loop-falls-through path).
	v, _ := NewValidator(Capability{
		OutputSchema:   recommendPositionSchema,
		AllowedStances: []Stance{StanceAffected}, // mitigated is recommendable but not allowed here
	})
	out := RawOutput{FindingID: "F1", RecommendedStance: string(StanceMitigated), Confidence: 0.5}
	if err := v.ValidateBusiness(out, "F1", groundedContext()); !errors.Is(err, ErrBusinessInvalid) {
		t.Errorf("recommendable-but-not-allowed stance → ErrBusinessInvalid, got %v", err)
	}
}

func TestParseOutputError(t *testing.T) {
	if _, err := ParseOutput([]byte("{nope")); !errors.Is(err, ErrSchemaInvalid) {
		t.Errorf("bad JSON → ErrSchemaInvalid, got %v", err)
	}
}

func TestBuildProposal(t *testing.T) {
	out, _ := ParseOutput(validRaw())
	meta := Metadata{CorrelationID: "corr-1", Provider: "fake", Model: "fake", TokensUsed: 3}
	p := BuildProposal(out, RecommendPositionV1(), meta)
	if p.Capability != "recommend_position@v1" {
		t.Errorf("capability ref = %q", p.Capability)
	}
	if p.Recommendation.FindingID != "F1" || p.Recommendation.Stance != StanceAffected {
		t.Errorf("recommendation = %+v", p.Recommendation)
	}
	if p.Confidence != 0.8 || len(p.Evidence) != 1 || p.Evidence[0].Ref != "FL1" {
		t.Errorf("unexpected proposal %+v", p)
	}
	if p.Metadata.CorrelationID != "corr-1" {
		t.Errorf("metadata not carried: %+v", p.Metadata)
	}
}
