package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
	// ReasonBudgetExhausted — the capability's spend ceiling for this window is used up (D4).
	// A distinct reason because the operator response is unlike every other no-proposal: nothing
	// is broken, nothing declined on the merits, and it will resolve by itself when the window
	// rolls. Folding it into `insufficient` would send someone to debug a model that behaved.
	ReasonBudgetExhausted = "budget_exhausted"
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
	// Detail is WHY the outcome ended as it did, in the words of the check that ended it —
	// telemetry only, never returned to the caller (TRUST-6).
	//
	// Reason alone is a constant, and four very different failures collapse into
	// ReasonBusinessInvalid: a wrong finding_id echo, a confidence outside [0,1], a
	// disallowed stance, and an ungrounded evidence ref. They call for opposite fixes — a
	// stricter response schema, a prompt change, or a thicker projection — and on a live VM
	// the missing distinction made a real 204 undiagnosable from logs.
	//
	// It stays out of the HTTP response deliberately. A 204 must remain opaque: "AI disabled",
	// "AI unreachable" and "AI declined" are one outcome by design, because the pipeline is
	// correct in all three. Leaking which one occurred would put the Gateway's operational
	// state into a business API that treats AI as optional.
	Detail string
}

// redact scrubs a diagnostic string with the same discipline as the prompt (R1 / D10). It is
// applied to every Outcome.Detail because those messages quote model output verbatim, and a
// model that hallucinated a secret into its response must not have it copied into telemetry
// on the way out.
func (g *Gateway) redact(s string) string {
	if g.redactor == nil {
		return s
	}
	return g.redactor.Redact(s)
}

// Gateway is the reactive Intelligence Gateway pipeline (D5–D8): given a capability id
// and a subject identifier it assembles grounding, has the Engine Dispatcher walk the
// capability's execution plan, validates, and returns an advisory Proposal — or a
// first-class "no proposal" Outcome. It owns no truth and writes nothing (D1).
type Gateway struct {
	registry   *domain.Registry
	validators map[string]*domain.Validator
	projection ProjectionReader
	// precedents is the shared retrieval seam (Δ3a). The read API serves engineers from this
	// same service, so a human and the model see one retrieval result. Optional: nil = no
	// precedent grounding, which is the supported stateless-Gateway deployment.
	precedents      *PrecedentService
	authorizer      Authorizer // optional (nil = allow-all)
	redactor        Redactor   // optional (nil = no redaction)
	prompt          PromptRenderer
	dispatcher      *Dispatcher
	maxPromptBytes  int
	providerTimeout time.Duration
	budget          *Budget // nil or unconfigured = unlimited (the default)
	now             func() time.Time
}

// GatewayConfig wires the Gateway's ports. Engines are indexed by kind into the
// Dispatcher; Δ2 wires the Rule engine and the LLM engine.
type GatewayConfig struct {
	Registry   *domain.Registry
	Projection ProjectionReader
	// Precedents is the shared retrieval seam — build it once with NewPrecedentService and pass
	// the SAME instance to the read handler, so the model and the engineer cannot be served
	// different answers to "what resembles this?". nil disables precedent grounding.
	Precedents *PrecedentService
	Authorizer Authorizer // optional pre-invocation authz (Δ2 C7); nil = allow-all
	Redactor   Redactor   // optional secret/PII scrub of the prompt (Δ2 C7); nil = none
	// BudgetTokens / BudgetWindow enforce D4's per-capability spend ceiling. Both must be > 0 to
	// enforce anything; unset = unlimited, which is today's behaviour and the safe default —
	// a budget switched on by accident refuses recommendations, and a refusal is indistinguishable
	// from the AI being unavailable to everyone downstream (D13).
	BudgetTokens    int
	BudgetWindow    time.Duration
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
		precedents:      cfg.Precedents,
		authorizer:      cfg.Authorizer,
		redactor:        cfg.Redactor,
		prompt:          cfg.Prompt,
		dispatcher:      NewDispatcher(cfg.Engines...),
		maxPromptBytes:  maxPrompt,
		providerTimeout: timeout,
		budget:          NewBudget(cfg.BudgetTokens, cfg.BudgetWindow),
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
	// The subject id, whatever its Selection Type — a Finding for recommend_position, a Release
	// for a release-scoped capability (T9).
	subjectID := sel.First()
	oc.OutputClass = capb.Output
	validator := g.validators[capabilityID]

	// Pre-invocation authorization (C7): reject BEFORE any grounding or provider call.
	if g.authorizer != nil {
		if aerr := g.authorizer.Authorize(ctx, capabilityID, subjectID); aerr != nil {
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

	start := g.now()

	// Receive the Domain Projection — one read, no composition (T10). WHICH projection is
	// decided by the capability's Selection Type, not by the runtime knowing any topology: it
	// asks the reader for the projection of the type it declared and is handed an authoritative
	// one back.
	var ac domain.AssembledContext
	switch capb.SelectionType {
	case domain.SelectionRelease:
		posture, perr := g.projection.GetReleasePosture(ctx, subjectID)
		if perr != nil || posture.ReleaseID == "" {
			oc.Reason = ReasonNoGrounding
			return domain.Proposal{}, oc
		}
		// A release with nothing outstanding is not a grounding failure — it is a real answer,
		// and one worth giving without spending a model call on it.
		if posture.OutstandingCount() == 0 {
			oc.Duration = g.now().Sub(start)
			oc.Information = "No outstanding Findings on this release: every Finding has a recorded decision."
			oc.DecidedBy = "rule:nothing-outstanding"
			oc.Reason = ReasonOK
			return domain.Proposal{}, oc
		}
		ac = domain.AssembledContext{Release: posture}
	default:
		proj, perr := g.projection.GetAssessment(ctx, subjectID)
		if perr != nil || proj.Finding.ID == "" {
			oc.Reason = ReasonNoGrounding
			return domain.Proposal{}, oc
		}
		ac = domain.AssembledContext{Projection: proj}
	}

	for _, step := range capb.Plan {
		// Knowledge (retrieval) step (Δ3a): best-effort precedent grounding, delegated whole to
		// the PrecedentService — the same seam the read API serves engineers from, so the model
		// and the human are shown the same retrieval result. Unlike Rule/LLM this step is
		// OPTIONAL: an unwired service degrades to no precedent rather than failing the plan.
		//
		// The service owns BOTH sources and the order between them (semantic first, exact-CVE
		// only when semantic found nothing). That rule used to live here, split across this
		// branch and the LLM step below, where a second consumer could not reuse it.
		if step.Engine == domain.EngineKnowledge {
			if g.precedents != nil {
				ac.Precedents = g.precedents.Retrieve(ctx, QueryFromAssessment(ac.Projection))
			}
			continue
		}

		eng, ok := g.dispatcher.For(step.Engine)
		if !ok {
			oc.Duration = g.now().Sub(start)
			oc.Reason = ReasonProviderError
			return domain.Proposal{}, oc
		}

		// LLM step (the generative fallback). Precedent — semantic AND the exact-CVE fallback —
		// was settled by the Knowledge step above, so nothing is fetched here.
		//
		// The exact-CVE pull used to live at THIS line, which meant a capability with no
		// Knowledge step in its plan still issued it: plan_remediation is Release-scoped, so
		// ac.Finding() is the zero value and every invocation asked for the precedents of an
		// empty Faultline id. A read whose result the capability has no use for.
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
		// D4 per-capability window ceiling, checked immediately before the provider call — after
		// the free deterministic steps, so a Rule short-circuit never spends budget it did not use.
		if !g.budget.Allow(g.now()) {
			oc.Duration = g.now().Sub(start)
			oc.DecidedBy, oc.Reason = "guard:budget", ReasonBudgetExhausted
			return domain.Proposal{}, oc
		}
		in := ExecInput{Prompt: prompt, JSONSchema: capb.OutputSchema, Temperature: 0, Routing: capb.Routing, Context: ac}

		var out domain.RawOutput
		schemaOK := false
		// The last structural complaint across attempts, kept so an exhausted retry budget can
		// say WHAT was wrong instead of only that something was (TRUST-6). Unparseable JSON and
		// a schema violation call for different fixes — the response-format mode versus the
		// prompt — and both look identical in ReasonSchemaInvalid alone.
		var lastSchemaErr error
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
			// Debit what the call ACTUALLY cost, not an estimate. Every attempt debits, including
			// one whose output fails schema validation: a retry consumes the model exactly as a
			// successful call does, and a ledger that only counts successes would let a
			// schema-thrashing capability spend without limit.
			g.budget.Debit(g.now(), res.TokensUsed)
			parsed, parseErr := domain.ParseOutput([]byte(res.Raw))
			if parseErr != nil {
				lastSchemaErr = parseErr
				continue // malformed JSON — retry
			}
			if serr := validator.ValidateSchema([]byte(res.Raw)); serr != nil {
				lastSchemaErr = serr
				continue // structural violation — retry
			}
			out = parsed
			schemaOK = true
			break
		}
		if !schemaOK {
			oc.Duration = g.now().Sub(start)
			oc.Reason = ReasonSchemaInvalid
			if lastSchemaErr != nil {
				oc.Detail = g.redact(lastSchemaErr.Error())
			}
			return domain.Proposal{}, oc
		}
		// Information capabilities stop here (T7). The answer is rendered for a human and
		// discarded; BuildProposal is not reachable on this path, so an Information Response
		// has no route to enterprise truth even if a future edit forgot the rule.
		if capb.Output == domain.OutputInformation {
			// Grounding Verification runs HERE too, and is the ONLY gate on this path (T8): no
			// Governance stage follows an Information Response, so a citation naming something
			// the projection never contained has nothing downstream to catch it.
			//
			// This check was missing: the branch returned as soon as the schema validated, which
			// left the one load-bearing gate on this output class unexecuted. A schema says the
			// answer is well-SHAPED; only grounding says it is about anything real.
			if gerr := validator.ValidateGrounding(out, ac); gerr != nil {
				oc.Duration = g.now().Sub(start)
				oc.Reason = ReasonBusinessInvalid
				oc.Detail = g.redact(gerr.Error())
				return domain.Proposal{}, oc
			}
			oc.Duration = g.now().Sub(start)
			// The same rationale scan the Decision path applies (TRUST-8): prose cannot be
			// schema-checked, and an Information Response is read by a human AS-IS, so an
			// invented identifier inside it must be flagged rather than presented plainly.
			//
			// The caveat is embedded in the text rather than carried beside it, for the reason
			// TRUST-8 gives: anything stored elsewhere is something a reviewer can miss, and this
			// answer has no structured fields for a UI to render warnings next to — it IS prose.
			oc.Information = out.Reasoning
			if warn := domain.UngroundedMentions(out.Reasoning, ac); len(warn) > 0 {
				oc.Information += fmt.Sprintf(" [UNVERIFIED MENTIONS — the plan above names identifiers "+
					"that were not in its grounding, so treat those specifics as unreliable: %s]",
					strings.Join(warn, ", "))
			}
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
		if verr := validator.ValidateBusiness(out, subjectID, ac); verr != nil {
			oc.Duration = g.now().Sub(start)
			oc.Reason = ReasonBusinessInvalid
			// Which of the four checks refused it (TRUST-6). Redacted with the same discipline
			// as the prompt, because the message quotes model output back verbatim.
			oc.Detail = g.redact(verr.Error())
			return domain.Proposal{}, oc
		}
		oc.Duration = g.now().Sub(start)
		oc.DecidedBy = "llm:" + out.RecommendedStance
		oc.Produced, oc.Reason = true, ReasonOK
		// The proposal is valid — its structured evidence is grounded. Scan the free-text
		// rationale for identifiers nobody supplied and carry them as a warning (TRUST-8). This
		// never blocks: prose cannot be verified, so a hallucinated id in the narrative is a
		// caveat for the human who decides, not grounds for refusing a well-formed proposal.
		warn := domain.UngroundedMentions(out.Reasoning, ac)
		if len(warn) > 0 {
			oc.Detail = g.redact("ungrounded rationale mentions: " + strings.Join(warn, ", "))
		}
		return g.buildProposal(out, capb, oc, warn...), oc
	}

	// Every plan step deferred without producing — the honest "insufficient" outcome.
	oc.Duration = g.now().Sub(start)
	oc.DecidedBy = "insufficient"
	oc.Reason = ReasonInsufficient
	return domain.Proposal{}, oc
}

// buildProposal assembles the advisory Proposal from validated output, stamping the
// execution provenance (including which step decided) onto the metadata.
func (g *Gateway) buildProposal(out domain.RawOutput, capb domain.Capability, oc Outcome, rationaleWarnings ...string) domain.Proposal {
	return domain.BuildProposal(out, capb, domain.Metadata{
		CorrelationID:  oc.CorrelationID,
		Provider:       oc.Provider,
		Model:          oc.Model,
		TokensUsed:     oc.TokensUsed,
		Duration:       oc.Duration,
		DecidedBy:      oc.DecidedBy,
		PrecedentsUsed: oc.PrecedentsUsed,
	}, rationaleWarnings...)
}
