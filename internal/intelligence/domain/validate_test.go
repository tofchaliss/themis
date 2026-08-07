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
	return AssembledContext{Projection: FindingAssessment{Finding: FindingView{ID: "F1", FaultlineID: "FL1", CVE: "CVE-1"}, Knowledge: FaultlineView{ID: "FL1", CVE: "CVE-1"}}}
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

// realisticContext uses ids of the shapes a deployment actually carries — the label-tolerance
// works by extracting identifier-shaped tokens, so a fixture using "FL1" would prove nothing.
func realisticContext() AssembledContext {
	const (
		fid  = "48f6d9fd-dee5-4edd-b04a-59edcfb0ddfc"
		flid = "b1be6f86-2ecd-451f-9411-95f1f32fd501"
	)
	return AssembledContext{Projection: FindingAssessment{
		Finding:   FindingView{ID: fid, FaultlineID: flid, CVE: "CVE-2025-14087"},
		Knowledge: FaultlineView{ID: flid, CVE: "CVE-2025-14087"},
	}}
}

func mustValidator(t *testing.T) *Validator {
	t.Helper()
	v, err := NewValidator(RecommendPositionV1())
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

// A model asked to cite a reference frequently LABELS it. Observed on a live model 2026-08-07:
// a recommendation cited the correct faultline id as `faultline <uuid>` and was refused as
// ungrounded. The answer was right and only the formatting was not — a false refusal, which
// inflates the AI seam's apparent failure rate and hides the real refusals among cosmetic ones.
func TestValidateBusiness_AcceptsALabelledButCorrectRef(t *testing.T) {
	out := RawOutput{
		FindingID: "48f6d9fd-dee5-4edd-b04a-59edcfb0ddfc", RecommendedStance: "affected", Confidence: 0.9,
		Evidence: []RawEvidence{{Kind: "faultline", Ref: "faultline b1be6f86-2ecd-451f-9411-95f1f32fd501"}},
	}
	if err := mustValidator(t).ValidateBusiness(out, out.FindingID, realisticContext()); err != nil {
		t.Fatalf("ValidateBusiness: %v — a labelled but correct id must not be refused", err)
	}
}

// The tolerance is narrow: every identifier the ref names must still be one the model was
// given. A label around a WRONG id is still ungrounded.
func TestValidateBusiness_StillRefusesALabelledWrongRef(t *testing.T) {
	out := RawOutput{
		FindingID: "48f6d9fd-dee5-4edd-b04a-59edcfb0ddfc", RecommendedStance: "affected", Confidence: 0.9,
		Evidence: []RawEvidence{{Kind: "faultline", Ref: "faultline 11111111-2222-3333-4444-555555555555"}},
	}
	if err := mustValidator(t).ValidateBusiness(out, out.FindingID, realisticContext()); err == nil {
		t.Fatal("a labelled but UNGROUNDED id must still be refused")
	}
}

// A ref carrying no identifier at all grounds nothing — extraction must not become a way to
// pass verification with prose.
func TestValidateBusiness_RefusesARefWithNoIdentifier(t *testing.T) {
	out := RawOutput{
		FindingID: "48f6d9fd-dee5-4edd-b04a-59edcfb0ddfc", RecommendedStance: "affected", Confidence: 0.9,
		Evidence: []RawEvidence{{Kind: "note", Ref: "the vulnerability record"}},
	}
	if err := mustValidator(t).ValidateBusiness(out, out.FindingID, realisticContext()); err == nil {
		t.Fatal("a ref naming no identifier must be refused")
	}
}

// ValidateGrounding is Grounding Verification standing alone, because an Information Response has
// no Governance stage behind it — this is its ONLY gate (T8), and it therefore must be callable
// without dragging in the stance/confidence checks that only a Decision Proposal has.
func TestValidateGrounding(t *testing.T) {
	v := mustValidator(t)
	ac := realisticContext()
	grounded := RawOutput{Evidence: []RawEvidence{{Kind: "cve", Ref: "CVE-2025-14087"}}}
	if err := v.ValidateGrounding(grounded, ac); err != nil {
		t.Errorf("a grounded citation must pass: %v", err)
	}
	// No evidence at all is not a grounding failure — there is nothing ungrounded about
	// citing nothing. Whether a capability REQUIRES citations is its schema's business.
	if err := v.ValidateGrounding(RawOutput{}, ac); err != nil {
		t.Errorf("no citations should pass grounding: %v", err)
	}
	bad := RawOutput{Evidence: []RawEvidence{{Kind: "cve", Ref: "CVE-9999-9999"}}}
	if err := v.ValidateGrounding(bad, ac); !errors.Is(err, ErrBusinessInvalid) {
		t.Errorf("ungrounded citation → ErrBusinessInvalid, got %v", err)
	}
}

// AssembledContext.Grounds routes to whichever projection the capability's Selection Type
// produced. Getting this wrong would ground a release plan against an empty Finding projection —
// which refuses everything — or, worse, the reverse.
func TestAssembledContext_GroundsRoutesToTheRightProjection(t *testing.T) {
	release := AssembledContext{Release: ReleasePosture{
		ReleaseID: "rel-1",
		Entries:   []PostureEntry{{FindingID: "f1", CVE: "CVE-1"}},
	}}
	if !release.Grounds("CVE-1") || !release.Grounds("rel-1") {
		t.Error("a release context must ground against the release posture")
	}
	if release.Grounds("48f6d9fd-dee5-4edd-b04a-59edcfb0ddfc") {
		t.Error("a release context must not ground against a Finding projection it does not hold")
	}

	finding := groundedContext()
	if !finding.Grounds("FL1") {
		t.Error("a finding context must ground against the FindingAssessment")
	}
	if finding.Grounds("rel-1") {
		t.Error("a finding context must not ground against a release it does not hold")
	}
}
