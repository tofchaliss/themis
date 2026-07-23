package app

import (
	"context"
	"fmt"
	"time"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// maxAttempts is the schema-validation retry budget (D7): one initial attempt plus
// one retry on a structural failure. A business (semantic) failure is not retried.
const maxAttempts = 2

// Outcome-reason constants describe how an invocation ended — recorded as telemetry
// by the caller (D9). Every reason but ReasonUnknownCapability is a graceful
// "no proposal" that never blocks the pipeline (D13 disabled ≡ unavailable).
const (
	ReasonOK              = "ok"
	ReasonUnknownCap      = "unknown_capability"
	ReasonNoGrounding     = "no_grounding"
	ReasonPromptError     = "prompt_error"
	ReasonProviderError   = "provider_error"
	ReasonSchemaInvalid   = "schema_invalid"
	ReasonBusinessInvalid = "business_invalid"
)

// Outcome is the per-invocation telemetry record (D9). It carries no sensitive
// prompt content (D10) — only provenance and the terminal reason.
type Outcome struct {
	CapabilityID  string
	CorrelationID string
	Provider      string
	Model         string
	TokensUsed    int
	Duration      time.Duration
	Produced      bool
	Reason        string
}

// Gateway is the reactive Intelligence Gateway pipeline (D5–D8): given a capability
// id and a subject identifier it assembles grounding, renders a prompt, runs the
// engine, validates in three stages, and returns an advisory Proposal — or a
// first-class "no proposal" Outcome. It owns no truth and writes nothing (D1).
type Gateway struct {
	registry   *domain.Registry
	validators map[string]*domain.Validator
	finding    FindingReader
	faultline  FaultlineReader
	prompt     PromptRenderer
	engine     Engine
	now        func() time.Time
}

// GatewayConfig wires the Gateway's ports.
type GatewayConfig struct {
	Registry  *domain.Registry
	Finding   FindingReader
	Faultline FaultlineReader
	Prompt    PromptRenderer
	Engine    Engine
	Now       func() time.Time // defaults to time.Now
}

// NewGateway precompiles a validator per registered capability. A capability with an
// invalid output schema is a programming error surfaced here at startup.
func NewGateway(cfg GatewayConfig) (*Gateway, error) {
	validators := make(map[string]*domain.Validator)
	for _, capb := range cfg.Registry.All() {
		v, err := domain.NewValidator(capb)
		if err != nil {
			return nil, fmt.Errorf("gateway: %w", err)
		}
		validators[capb.ID] = v
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Gateway{
		registry:   cfg.Registry,
		validators: validators,
		finding:    cfg.Finding,
		faultline:  cfg.Faultline,
		prompt:     cfg.Prompt,
		engine:     cfg.Engine,
		now:        now,
	}, nil
}

// Invoke runs the reactive pipeline for a capability against a subject Finding.
// produced=false means "no proposal" (a safe outcome); Outcome carries the telemetry.
func (g *Gateway) Invoke(ctx context.Context, capabilityID, subjectFindingID, correlationID string) (domain.Proposal, Outcome) {
	oc := Outcome{CapabilityID: capabilityID, CorrelationID: correlationID}

	capb, ok := g.registry.Lookup(capabilityID)
	if !ok {
		oc.Reason = ReasonUnknownCap
		return domain.Proposal{}, oc
	}
	validator := g.validators[capabilityID]

	ac, err := AssembleContext(ctx, g.finding, g.faultline, capb.Needs, subjectFindingID)
	if err != nil {
		oc.Reason = ReasonNoGrounding
		return domain.Proposal{}, oc
	}

	prompt, err := g.prompt.Render(capabilityID, ac)
	if err != nil {
		oc.Reason = ReasonPromptError
		return domain.Proposal{}, oc
	}

	in := ExecInput{Prompt: prompt, JSONSchema: capb.OutputSchema, Temperature: 0, Routing: capb.Routing}
	start := g.now()

	var out domain.RawOutput
	schemaOK := false
	for attempt := 0; attempt < maxAttempts; attempt++ {
		res, err := g.engine.Execute(ctx, in)
		if err != nil {
			oc.Duration = g.now().Sub(start)
			oc.Reason = ReasonProviderError
			return domain.Proposal{}, oc
		}
		oc.Provider, oc.Model, oc.TokensUsed = res.Provider, res.Model, res.TokensUsed
		parsed, perr := domain.ParseOutput([]byte(res.Raw))
		if perr != nil {
			continue // malformed JSON — retry
		}
		if serr := validator.ValidateSchema([]byte(res.Raw)); serr != nil {
			continue // structural violation — retry
		}
		out = parsed
		schemaOK = true
		break
	}
	oc.Duration = g.now().Sub(start)
	if !schemaOK {
		oc.Reason = ReasonSchemaInvalid
		return domain.Proposal{}, oc
	}

	if err := validator.ValidateBusiness(out, subjectFindingID, ac); err != nil {
		oc.Reason = ReasonBusinessInvalid
		return domain.Proposal{}, oc
	}

	proposal := domain.BuildProposal(out, capb, domain.Metadata{
		CorrelationID: correlationID,
		Provider:      oc.Provider,
		Model:         oc.Model,
		TokensUsed:    oc.TokensUsed,
		Duration:      oc.Duration,
	})
	oc.Produced = true
	oc.Reason = ReasonOK
	return proposal, oc
}
