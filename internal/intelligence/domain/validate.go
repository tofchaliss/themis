package domain

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ErrSchemaInvalid (stage 1) and ErrBusinessInvalid (stage 2) mark validation
// failures. The Gateway may retry once on a schema failure; a business failure is a
// grounded semantic error that won't self-correct, so it becomes a no-proposal.
var (
	ErrSchemaInvalid   = errors.New("intelligence: schema validation failed")
	ErrBusinessInvalid = errors.New("intelligence: business validation failed")
)

// addResource wraps compiler.AddResource so tests can force its (otherwise
// unreachable) error branch — the same idiom used by the Evidence trust gate.
var addResource = func(c *jsonschema.Compiler, url string, doc any) error {
	return c.AddResource(url, doc)
}

// RawOutput is the parsed model output for recommend_position — the wire shape the
// Gateway prompt asks the model to emit. BuildProposal maps it onto the Proposal
// envelope.
type RawOutput struct {
	FindingID         string        `json:"finding_id"`
	RecommendedStance string        `json:"recommended_stance"`
	Confidence        float64       `json:"confidence"`
	Evidence          []RawEvidence `json:"evidence"`
	Reasoning         string        `json:"reasoning"`
}

// RawEvidence is one cited fact in the model output.
type RawEvidence struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
}

// Validator runs the per-capability 3-stage validation (D7). It precompiles the
// capability's output schema once at construction.
type Validator struct {
	capb   Capability
	schema *jsonschema.Schema
}

// NewValidator compiles a capability's output schema. A capability with an invalid
// schema is a programming error surfaced at startup.
func NewValidator(capb Capability) (*Validator, error) {
	compiler := jsonschema.NewCompiler()
	var doc any
	if err := json.Unmarshal([]byte(capb.OutputSchema), &doc); err != nil {
		return nil, fmt.Errorf("intelligence: parse schema for %s: %w", capb.Ref(), err)
	}
	if err := addResource(compiler, "output.json", doc); err != nil {
		return nil, fmt.Errorf("intelligence: add schema for %s: %w", capb.Ref(), err)
	}
	sch, err := compiler.Compile("output.json")
	if err != nil {
		return nil, fmt.Errorf("intelligence: compile schema for %s: %w", capb.Ref(), err)
	}
	return &Validator{capb: capb, schema: sch}, nil
}

// ValidateSchema (stage 1) checks raw model output against the capability's JSON
// Schema. Malformed output → ErrSchemaInvalid.
func (v *Validator) ValidateSchema(raw []byte) error {
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return fmt.Errorf("%w: parse output: %v", ErrSchemaInvalid, err)
	}
	if err := v.schema.Validate(payload); err != nil {
		return fmt.Errorf("%w: %v", ErrSchemaInvalid, err)
	}
	return nil
}

// ValidateBusiness (stage 2) is the anti-hallucination gate: the output must name the
// subject Finding, cite only grounded evidence, carry an in-range confidence, and
// propose only a recommendable stance the capability allows.
func (v *Validator) ValidateBusiness(out RawOutput, subjectFindingID string, ac AssembledContext) error {
	if out.FindingID != subjectFindingID {
		return fmt.Errorf("%w: finding_id %q != subject %q", ErrBusinessInvalid, out.FindingID, subjectFindingID)
	}
	if out.Confidence < 0 || out.Confidence > 1 {
		return fmt.Errorf("%w: confidence %v out of [0,1]", ErrBusinessInvalid, out.Confidence)
	}
	if !stanceAllowed(Stance(out.RecommendedStance), v.capb.AllowedStances) {
		return fmt.Errorf("%w: stance %q not allowed", ErrBusinessInvalid, out.RecommendedStance)
	}
	for _, ev := range out.Evidence {
		if !ac.Grounds(ev.Ref) {
			return fmt.Errorf("%w: ungrounded evidence %q", ErrBusinessInvalid, ev.Ref)
		}
	}
	return nil
}

func stanceAllowed(s Stance, allowed []Stance) bool {
	if !s.Recommendable() {
		return false
	}
	for _, a := range allowed {
		if a == s {
			return true
		}
	}
	return false
}

// ParseOutput unmarshals validated raw output into RawOutput.
func ParseOutput(raw []byte) (RawOutput, error) {
	var out RawOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return RawOutput{}, fmt.Errorf("%w: %v", ErrSchemaInvalid, err)
	}
	return out, nil
}

// BuildProposal (stage 3) constructs the advisory Proposal envelope from validated
// output. Only reachable after stages 1 + 2 pass.
func BuildProposal(out RawOutput, capb Capability, meta Metadata) Proposal {
	ev := make([]Evidence, 0, len(out.Evidence))
	for _, e := range out.Evidence {
		ev = append(ev, Evidence(e))
	}
	return Proposal{
		Capability:     capb.Ref(),
		Recommendation: Recommendation{FindingID: out.FindingID, Stance: Stance(out.RecommendedStance)},
		Confidence:     out.Confidence,
		Evidence:       ev,
		Reasoning:      out.Reasoning,
		Metadata:       meta,
	}
}
