package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// Δ2 admission-gate defaults (measure now, enforce lightly — C5). Real multi-scope budget
// enforcement + degrade-not-fail model routing is deferred (G-AI-4).
const (
	defaultMaxPromptBytes  = 200_000          // runaway-prompt guard (~100× a normal prompt)
	defaultProviderTimeout = 60 * time.Second // per-invocation deadline around provider I/O
)

// maxAttempts is the schema-validation retry budget (D7): one initial attempt plus one
// retry on a structural failure. A business (semantic) failure is not retried.
const maxAttempts = 2

// Outcome-reason constants describe how an invocation ended — recorded as telemetry by
// the caller (D9). Every reason but ReasonUnknownCap is a graceful "no proposal" that
// never blocks the pipeline (D13 disabled ≡ unavailable).
const (
	ReasonOK              = "ok"
	ReasonUnknownCap      = "unknown_capability"
	ReasonNoGrounding     = "no_grounding"
	ReasonPromptError     = "prompt_error"
	ReasonProviderError   = "provider_error"
	ReasonSchemaInvalid   = "schema_invalid"
	ReasonBusinessInvalid = "business_invalid"
	ReasonUnauthorized    = "unauthorized" // admission denied the caller before any provider call (C7)
	// ReasonSelectionMismatch: the Selection's type or cardinality is not what the capability
	// declared (T9). Rejected at the door — before any grounding is assembled or any provider
	// is called — so a release id sent to a Finding-scoped capability surfaces as exactly that,
	// rather than as a confusing grounding failure further in.
	ReasonSelectionMismatch = "selection_mismatch"
	// ReasonInsufficient is the honest "can't determine — no recommendation" outcome
	// (Δ2): the LLM declined, or the whole plan deferred without producing. It is
	// produced=false but NOT an error, and is distinct from AI being switched off.
	ReasonInsufficient = "insufficient"
)

// Outcome is the per-invocation telemetry record (D9). It carries no sensitive prompt
// content (D10) — only provenance and the terminal reason.
type Outcome struct {
	CapabilityID   string
	CorrelationID  string
	Provider       string
	Model          string
	TokensUsed     int
	InputBytes     int // rendered prompt size — a metered cost input (C5); 0 on a rule short-circuit
	Duration       time.Duration
	Produced       bool
	Reason         string
	DecidedBy      string             // "llm:<stance>" / "guard:<reason>" — what decided
	Selection      domain.Selection   // what the invocation was about (T9 provenance)
	OutputClass    domain.OutputClass // which branch ran (T7): information or decision
	PrecedentsUsed int                // precedents (semantic + exact-CVE) that grounded the LLM step (Δ3a provenance)
	// Information is the ephemeral answer produced by an Information capability. It is NEVER
	// recorded as enterprise truth and never reaches Governance — a human reads it and it is
	// discarded. Empty for a Decision capability.
	Information string
}

// Gateway is the reactive Intelligence Gateway pipeline (D5–D8): given a capability id
// and a subject identifier it assembles grounding, has the Engine Dispatcher walk the
// capability's execution plan, validates, and returns an advisory Proposal — or a
// first-class "no proposal" Outcome. It owns no truth and writes nothing (D1).
type Gateway struct {
	registry        *domain.Registry
	validators      map[string]*domain.Validator
	projection      ProjectionReader
	precedent       PrecedentReader // optional (nil = no precedent grounding)
	authorizer      Authorizer      // optional (nil = allow-all)
	redactor        Redactor        // optional (nil = no redaction)
	prompt          PromptRenderer
	dispatcher      *Dispatcher
	maxPromptBytes  int
	providerTimeout time.Duration
	now             func() time.Time
}

// GatewayConfig wires the Gateway's ports. Engines are indexed by kind into the
// Dispatcher; Δ2 wires the Rule engine and the LLM engine.
type GatewayConfig struct {
	Registry        *domain.Registry
	Projection      ProjectionReader
	Precedent       PrecedentReader // optional richer grounding (Δ2 C6); nil disables it
	Authorizer      Authorizer      // optional pre-invocation authz (Δ2 C7); nil = allow-all
	Redactor        Redactor        // optional secret/PII scrub of the prompt (Δ2 C7); nil = none
	Prompt          PromptRenderer
	Engines         []Engine
	MaxPromptBytes  int              // runaway-prompt cap (0 → default); over-cap → insufficient
	ProviderTimeout time.Duration    // per-invocation deadline (0 → default)
	Now             func() time.Time // defaults to time.Now
}

// NewGateway precompiles a validator per registered capability and indexes the engines
// into the Dispatcher. A capability with an invalid output schema is a programming error
// surfaced here at startup.
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
	maxPrompt := cfg.MaxPromptBytes
	if maxPrompt <= 0 {
		maxPrompt = defaultMaxPromptBytes
	}
	timeout := cfg.ProviderTimeout
	if timeout <= 0 {
		timeout = defaultProviderTimeout
	}
	return &Gateway{
		registry:        cfg.Registry,
		validators:      validators,
		projection:      cfg.Projection,
		precedent:       cfg.Precedent,
		authorizer:      cfg.Authorizer,
		redactor:        cfg.Redactor,
		prompt:          cfg.Prompt,
		dispatcher:      NewDispatcher(cfg.Engines...),
		maxPromptBytes:  maxPrompt,
		providerTimeout: timeout,
		now:             now,
	}, nil
}

// Invoke runs the reactive pipeline for a capability against a Selection. It
// assembles grounding once, then the Engine Dispatcher walks the capability's execution
// plan: a deterministic (Rule) step that decides short-circuits the plan; a Knowledge step
// enriches the grounding with semantically similar past Positions (best-effort precedent,
// Δ3a); a step that defers passes to the next; the LLM step renders a prompt, runs with a
// schema retry, and validates in stages. produced=false is a safe "no proposal"; Outcome
// carries the telemetry, including which step decided and how much precedent grounded it.
func (g *Gateway) Invoke(
	ctx context.Context, capabilityID string, sel domain.Selection, correlationID string,
) (domain.Proposal, Outcome) {
	oc := Outcome{CapabilityID: capabilityID, CorrelationID: correlationID, Selection: sel}

	capb, ok := g.registry.Lookup(capabilityID)
	if !ok {
		oc.Reason = ReasonUnknownCap
		return domain.Proposal{}, oc
	}
	// The Selection contract (T9), checked before anything is fetched or spent.
	if !capb.Accepts(sel) {
		oc.Reason = ReasonSelectionMismatch
		return domain.Proposal{}, oc
	}
	subjectFindingID := sel.First()
	oc.OutputClass = capb.Output
	validator := g.validators[capabilityID]

	// Pre-invocation authorization (C7): reject BEFORE any grounding or provider call.
	if g.authorizer != nil {
		if aerr := g.authorizer.Authorize(ctx, capabilityID, subjectFindingID); aerr != nil {
			oc.Reason = ReasonUnauthorized
			return domain.Proposal{}, oc
		}
	}

	// Per-invocation deadline (runaway guard, C5). A provider that hangs past it surfaces
	// as context.DeadlineExceeded → an honest "insufficient", never a blocked pipeline.
	if g.providerTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, g.providerTimeout)
		defer cancel()
	}

	// Receive the Domain Projection — one read, no composition (T10).
	proj, err := g.projection.GetAssessment(ctx, subjectFindingID)
	if err != nil || proj.Finding.ID == "" {
		oc.Reason = ReasonNoGrounding
		return domain.Proposal{}, oc
	}
	ac := domain.AssembledContext{Projection: proj}

	start := g.now()
	for _, step := range capb.Plan {
		// Knowledge (retrieval) step (Δ3a): best-effort semantic precedent grounding. Unlike
		// Rule/LLM, precedent is OPTIONAL — a missing or failing Knowledge engine degrades to no
		// precedent and never blocks the recommendation, so it is handled before the generic
		// dispatcher lookup (an unwired index is a graceful skip, not a fatal ProviderError).
		if step.Engine == domain.EngineKnowledge {
			if eng, ok := g.dispatcher.For(step.Engine); ok {
				if res, kerr := eng.Execute(ctx, ExecInput{Context: ac}); kerr == nil && len(res.Precedents) > 0 {
					ac.Precedents = res.Precedents
				}
			}
			continue
		}

		eng, ok := g.dispatcher.For(step.Engine)
		if !ok {
			oc.Duration = g.now().Sub(start)
			oc.Reason = ReasonProviderError
			return domain.Proposal{}, oc
		}

		// LLM step (the generative fallback). Semantic precedent from the Knowledge step already
		// rides ac.Precedents; fall back to the Δ2 exact-CVE blast-radius pull ONLY when that
		// found none (a cold or incomplete index) — so a rule short-circuit still costs no read,
		// and a read failure degrades to no precedent, never blocks (C6).
		if len(ac.Precedents) == 0 && g.precedent != nil {
			if prec, prErr := g.precedent.GetPrecedents(ctx, ac.Finding().FaultlineID, ac.Finding().ReleaseID); prErr == nil {
				ac.Precedents = prec
			}
		}
		oc.PrecedentsUsed = len(ac.Precedents)
		// Render a prompt per step, run with a bounded schema retry, then business-validate.
		prompt, perr := g.prompt.Render(capabilityID, ac)
		if perr != nil {
			oc.Duration = g.now().Sub(start)
			oc.Reason = ReasonPromptError
			return domain.Proposal{}, oc
		}
		// Meter the request cost (C5) and apply the runaway-prompt guard BEFORE any provider
		// call: an oversize prompt is an honest "insufficient", never sent to a model.
		oc.InputBytes = len(prompt)
		if len(prompt) > g.maxPromptBytes {
			oc.Duration = g.now().Sub(start)
			oc.DecidedBy, oc.Reason = "guard:oversize", ReasonInsufficient
			return domain.Proposal{}, oc
		}
		// Scrub secrets/PII before the provider sees the prompt (C7). Δ2 is local-only —
		// the ExecInput carries the capability's LocalOnly routing so the (trivial) router
		// binds a local provider; a non-local binding is refused later (G-AI-5).
		if g.redactor != nil {
			prompt = g.redactor.Redact(prompt)
		}
		in := ExecInput{Prompt: prompt, JSONSchema: capb.OutputSchema, Temperature: 0, Routing: capb.Routing, Context: ac}

		var out domain.RawOutput
		schemaOK := false
		for attempt := 0; attempt < maxAttempts; attempt++ {
			res, eerr := eng.Execute(ctx, in)
			if eerr != nil {
				oc.Duration = g.now().Sub(start)
				if errors.Is(eerr, context.DeadlineExceeded) {
					// runaway-timeout guard → honest insufficient, not a hard error.
					oc.DecidedBy, oc.Reason = "guard:timeout", ReasonInsufficient
				} else {
					oc.Reason = ReasonProviderError
				}
				return domain.Proposal{}, oc
			}
			oc.Provider, oc.Model, oc.TokensUsed = res.Provider, res.Model, res.TokensUsed
			parsed, parseErr := domain.ParseOutput([]byte(res.Raw))
			if parseErr != nil {
				continue // malformed JSON — retry
			}
			if serr := validator.ValidateSchema([]byte(res.Raw)); serr != nil {
				continue // structural violation — retry
			}
			out = parsed
			schemaOK = true
			break
		}
		if !schemaOK {
			oc.Duration = g.now().Sub(start)
			oc.Reason = ReasonSchemaInvalid
			return domain.Proposal{}, oc
		}
		// Information capabilities stop here (T7). The answer is rendered for a human and
		// discarded; BuildProposal is not reachable on this path, so an Information Response
		// has no route to enterprise truth even if a future edit forgot the rule.
		if capb.Output == domain.OutputInformation {
			oc.Duration = g.now().Sub(start)
			oc.Information = out.Reasoning
			oc.DecidedBy = "llm:information"
			oc.Reason = ReasonOK
			return domain.Proposal{}, oc // produced stays FALSE: there is no proposal to record
		}
		if out.RecommendedStance == string(domain.StanceInsufficient) {
			// The model honestly declined — a first-class "no recommendation", not an
			// error and not a disposition (so it skips business validation + BuildProposal).
			oc.Duration = g.now().Sub(start)
			oc.DecidedBy = "llm:" + string(domain.StanceInsufficient)
			oc.Reason = ReasonInsufficient
			return domain.Proposal{}, oc
		}
		if verr := validator.ValidateBusiness(out, subjectFindingID, ac); verr != nil {
			oc.Duration = g.now().Sub(start)
			oc.Reason = ReasonBusinessInvalid
			return domain.Proposal{}, oc
		}
		oc.Duration = g.now().Sub(start)
		oc.DecidedBy = "llm:" + out.RecommendedStance
		oc.Produced, oc.Reason = true, ReasonOK
		return g.buildProposal(out, capb, oc), oc
	}

	// Every plan step deferred without producing — the honest "insufficient" outcome.
	oc.Duration = g.now().Sub(start)
	oc.DecidedBy = "insufficient"
	oc.Reason = ReasonInsufficient
	return domain.Proposal{}, oc
}

// buildProposal assembles the advisory Proposal from validated output, stamping the
// execution provenance (including which step decided) onto the metadata.
func (g *Gateway) buildProposal(out domain.RawOutput, capb domain.Capability, oc Outcome) domain.Proposal {
	return domain.BuildProposal(out, capb, domain.Metadata{
		CorrelationID: oc.CorrelationID,
		Provider:      oc.Provider,
		Model:         oc.Model,
		TokensUsed:    oc.TokensUsed,
		Duration:      oc.Duration,
		DecidedBy:     oc.DecidedBy,
	})
}
