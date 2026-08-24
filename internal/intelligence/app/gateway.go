package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// Admission-gate defaults (C5). The per-capability window ceiling and degrade-not-fail
// tier routing are live; the remaining D4 scopes (per-run cost ceiling, autonomous pool,
// global enterprise ceiling) wait for the planes that give them meaning.
const (
	defaultMaxPromptBytes  = 200_000          // runaway-prompt guard (~100× a normal prompt)
	defaultProviderTimeout = 60 * time.Second // per-invocation deadline around provider I/O
	// defaultDegradeFraction is degrade-not-fail's low-water mark (G-AI-4): below this
	// fraction of the window ceiling, invocations route to the economy tier when one exists.
	defaultDegradeFraction = 0.20

	// DeclineThinGrounding / DeclineModelUndetermined are the G-AI-2c decline classes.
	DeclineThinGrounding     = "thin_grounding"
	DeclineModelUndetermined = "model_undetermined"
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
	CapabilityID  string
	CorrelationID string
	Provider      string
	Model         string
	TokensUsed    int
	InputBytes    int // rendered prompt size — a metered cost input (C5); 0 on a rule short-circuit
	Duration      time.Duration
	Produced      bool
	Reason        string
	DecidedBy     string // "llm:<stance>" / "guard:<reason>" — what decided
	// Tier is the model tier that produced the terminal LLM outcome ("primary" /
	// "escalation" / "economy"; empty when no LLM step ran). Telemetry, not semantics:
	// an escalated decline is still `insufficient` — but "the bigger model could not
	// tell either" versus "we never tried a bigger model" is exactly the distinction
	// G-AI-2 needs observable.
	Tier string
	// PromptVersion is the content hash of the capability's prompt template (Δ4a D-Δ4a-3):
	// attribution, so every telemetry / invocation-log / eval row names the exact prompt that
	// ran. Empty when no LLM step ran or the renderer tracks no versions.
	PromptVersion  string
	Selection      domain.Selection   // what the invocation was about (T9 provenance)
	OutputClass    domain.OutputClass // which branch ran (T7): information or decision
	PrecedentsUsed int                // precedents (semantic + exact-CVE) that grounded the LLM step (Δ3a provenance)
	// Information is the ephemeral answer produced by an Information capability. It is NEVER
	// recorded as enterprise truth and never reaches Governance — a human reads it and it is
	// discarded. Empty for a Decision capability.
	Information string
	// DeclineClass classifies an honest `insufficient` for the eval loop (G-AI-2c):
	// `thin_grounding` — the backend knew the grounding could not support a stance before any
	// model ran (AI-204-2's taxonomy) — versus `model_undetermined` — the grounding was fine
	// and the model still could not tell. Different problems, different fixes: the first is a
	// projection/correlation gap, the second a model/prompt question. Empty unless the
	// terminal reason is insufficient.
	DeclineClass string
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

// captureInvocation records the completed invocation for the Δ4a replay harness (D-Δ4a-5). It
// marshals the assembled context and REDACTS it before it leaves the process — capture is
// downstream of the same scrub the prompt gets. Best-effort by contract: any marshal or capture
// failure is swallowed, because a replay-harness concern must never affect an invocation. The
// context is captured only once grounding was assembled (an early Selection/auth reject has an
// empty ac, which is fine — those cases are not replay material anyway).
func (g *Gateway) captureInvocation(ctx context.Context, oc Outcome, ac domain.AssembledContext) {
	var contextJSON []byte
	if raw, err := json.Marshal(ac); err == nil {
		contextJSON = []byte(g.redact(string(raw)))
	} else {
		contextJSON = []byte("null")
	}
	g.capturer.Capture(ctx, CapturedInvocation{
		CorrelationID: oc.CorrelationID,
		Capability:    oc.CapabilityID,
		PromptVersion: oc.PromptVersion,
		Model:         oc.Model,
		Tier:          oc.Tier,
		ContextJSON:   contextJSON,
		Reason:        oc.Reason,
		DeclineClass:  oc.DeclineClass,
		Tokens:        oc.TokensUsed,
	})
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
	authorizer      Authorizer         // optional (nil = allow-all)
	redactor        Redactor           // optional (nil = no redaction)
	capturer        InvocationCapturer // optional (nil = no Δ4a capture)
	prompt          PromptRenderer
	dispatcher      *Dispatcher
	maxPromptBytes  int
	maxRunTokens    int // per-run ceiling (G-AI-4): 0 = unlimited
	providerTimeout time.Duration
	budget          *Budget // nil or unconfigured = unlimited (the default)
	// router, when set, enables the tier decisions (phase3-intelligence-router): escalation
	// on an honest decline (G-AI-2b) and degrade-not-fail on a low budget (G-AI-4). nil =
	// single-model deployment; both behaviours simply never fire.
	router      Router
	degradeFrac float64
	now         func() time.Time
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
	Capturer   InvocationCapturer // optional Δ4a replay-harness capture (D-Δ4a-5); nil = no capture
	// BudgetTokens / BudgetWindow enforce D4's per-capability spend ceiling. Both must be > 0 to
	// enforce anything; unset = unlimited, which is today's behaviour and the safe default —
	// a budget switched on by accident refuses recommendations, and a refusal is indistinguishable
	// from the AI being unavailable to everyone downstream (D13).
	BudgetTokens int
	BudgetWindow time.Duration
	// Router enables the tier decisions (escalation + degrade-not-fail). Optional: nil is
	// the single-model deployment and disables both. It is the SAME router the LLM engine
	// selects through — the Gateway only asks it what is Available; the engine does the
	// selecting, so there is exactly one place a model is ever chosen (INT-0062).
	Router Router
	// BudgetDegradeFraction is the low-water mark for degrade-not-fail: when the window's
	// remaining tokens fall below limit×fraction and an economy model exists, the invocation
	// routes there instead of spending the primary's rate. 0 → default 0.20; it only means
	// anything when the budget is enforced and an economy tier is configured.
	BudgetDegradeFraction float64
	Prompt                PromptRenderer
	Engines               []Engine
	MaxPromptBytes        int // runaway-prompt cap (0 → default); over-cap → insufficient
	// MaxRunTokens is G-AI-4's per-run cost ceiling: once ONE invocation's accumulated spend
	// reaches it, no further attempt (schema retry or escalation) is made — the run ends as
	// `budget_exhausted` with DecidedBy "guard:run-budget". 0 = unlimited, matching the window
	// budget's load-bearing default: a ceiling nobody set must never fire.
	MaxRunTokens    int
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
	degrade := cfg.BudgetDegradeFraction
	if degrade <= 0 {
		degrade = defaultDegradeFraction
	}
	return &Gateway{
		registry:        cfg.Registry,
		validators:      validators,
		projection:      cfg.Projection,
		precedents:      cfg.Precedents,
		authorizer:      cfg.Authorizer,
		redactor:        cfg.Redactor,
		capturer:        cfg.Capturer,
		prompt:          cfg.Prompt,
		dispatcher:      NewDispatcher(cfg.Engines...),
		maxPromptBytes:  maxPrompt,
		providerTimeout: timeout,
		budget:          NewBudget(cfg.BudgetTokens, cfg.BudgetWindow),
		maxRunTokens:    cfg.MaxRunTokens,
		router:          cfg.Router,
		degradeFrac:     degrade,
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

	// Δ4a capture (D-Δ4a-5): record the invocation for the replay harness, best-effort, at the
	// single terminal point. ac fills in once grounding is assembled; the closure reads the
	// final oc + ac by reference so every return path is captured without touching the hot path.
	// The context is marshaled then REDACTED before it leaves — capture is downstream of the
	// same scrub the prompt gets, so a golden entry can never durably hold a secret.
	var ac domain.AssembledContext
	if g.capturer != nil {
		defer func() { g.captureInvocation(ctx, oc, ac) }()
	}

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
	oc.PromptVersion = g.prompt.Version(capabilityID) // attribution stamp (Δ4a); harmless if no LLM step runs
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
	// one back. (ac is declared at the top of Invoke so the capture defer can read it.)
	switch {
	case capb.HasNeed(domain.NeedReleaseComparison):
		// Two ordered releases: [baseline, candidate] (AI-CMP-1). Accepts() already enforced
		// the cardinality, so the indexes are safe. The read carries Governance's honesty guard
		// with it — an evidence-less side refuses there, and that refusal is a grounding
		// failure here, never something to narrate around.
		cmp, cerr := g.projection.GetReleaseComparison(ctx, sel.IDs[0], sel.IDs[1])
		if cerr != nil || cmp.CandidateID == "" {
			oc.Reason = ReasonNoGrounding
			return domain.Proposal{}, oc
		}
		// Nothing in any bucket means both postures are empty — a real answer, given
		// deterministically rather than spending a model call to say "no difference".
		if cmp.Empty() {
			oc.Duration = g.now().Sub(start)
			oc.Information = "Both releases have empty postures — nothing fixed, nothing new, nothing persisting. There is no security difference to narrate."
			oc.DecidedBy = "rule:empty-comparison"
			oc.Reason = ReasonOK
			return domain.Proposal{}, oc
		}
		ac = domain.AssembledContext{Comparison: cmp}
	case capb.SelectionType == domain.SelectionRelease:
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
	// AI-204-2: name the deterministic thinness NOW, before any model runs, so a later honest
	// decline carries its why in telemetry (the 204 header stays opaque per AI-204-1). Computed
	// once here; applied only on the insufficient exits below — an error's own detail wins.
	thinGrounding := domain.GroundingThinness(ac.Projection)

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
		// Degrade-not-fail (G-AI-4): with the window nearly spent and a distinct economy model
		// configured, route there instead of the primary — spend shrinks before it stops. The
		// Allow gate above is untouched: full exhaustion still refuses, because the economy
		// model's tokens are real tokens too.
		tier, degraded := TierPrimary, false
		if g.router != nil && g.router.Available(TierEconomy) {
			if lim := g.budget.Limit(); lim > 0 {
				if rem := g.budget.Remaining(g.now()); rem >= 0 && float64(rem) < float64(lim)*g.degradeFrac {
					tier, degraded = TierEconomy, true
				}
			}
		}

		var out domain.RawOutput
		// The tier loop (G-AI-2b): primary once — plus, when the model honestly declines a
		// Decision capability, ONE escalation pass on the larger model (appended below). All
		// other terminal outcomes return from inside the loop exactly as before.
		tiers := []ModelTier{tier}
		for ti := 0; ti < len(tiers); ti++ {
			oc.Tier = string(tiers[ti])
			in := ExecInput{Prompt: prompt, JSONSchema: capb.OutputSchema, Temperature: 0,
				Routing: capb.Routing, Tier: tiers[ti], Context: ac}

			schemaOK := false
			// The last structural complaint across attempts, kept so an exhausted retry budget can
			// say WHAT was wrong instead of only that something was (TRUST-6). Unparseable JSON and
			// a schema violation call for different fixes — the response-format mode versus the
			// prompt — and both look identical in ReasonSchemaInvalid alone.
			var lastSchemaErr error
			for attempt := 0; attempt < maxAttempts; attempt++ {
				// The per-run ceiling (G-AI-4): a run that has already spent its cap makes no
				// further call — a schema-thrashing invocation stops mid-run instead of riding
				// every retry to the window's edge. First attempts always run (spend is 0).
				if g.maxRunTokens > 0 && oc.TokensUsed >= g.maxRunTokens {
					oc.Duration = g.now().Sub(start)
					oc.DecidedBy, oc.Reason = "guard:run-budget", ReasonBudgetExhausted
					return domain.Proposal{}, oc
				}
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
				oc.Provider, oc.Model = res.Provider, res.Model
				// ACCUMULATE across attempts and tiers (AI-TEL-1): a schema retry or an
				// escalation is real spend, and telemetry that reports only the final call
				// under-states an invocation's cost (measured: ~1900+2116 logged as 2116).
				// The budget already debits every attempt; this makes the journal agree.
				// The proposal metadata inherits the same number — the invocation TOTAL is
				// the honest figure for both.
				oc.TokensUsed += res.TokensUsed
				// Debit what the call ACTUALLY cost, not an estimate. Every attempt debits, including
				// one whose output fails schema validation — and including an escalation pass: a
				// retry consumes the model exactly as a successful call does, and a ledger that
				// only counts successes would let a schema-thrashing capability spend without limit.
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
			// Escalation fires ONLY on the honest decline of a Decision capability (below) —
			// never on schema/business failures (those are contract problems; a bigger model
			// would mask which lever to pull) and never on timeouts (a slower model times out
			// worse). Anything but `insufficient` on the primary ends the loop here.
			if out.RecommendedStance == string(domain.StanceInsufficient) &&
				capb.Output == domain.OutputDecision && tiers[ti] == TierPrimary && !degraded &&
				g.router != nil && g.router.Available(TierEscalation) && g.budget.Allow(g.now()) &&
				(g.maxRunTokens == 0 || oc.TokensUsed < g.maxRunTokens) {
				// The upgrade counterpart of degrade-not-fail (G-AI-2b): the larger model may
				// extract more from the SAME grounding — the prompt is identical by design, so
				// a different answer can only come from the model. Skipped while degraded:
				// escalating out of a low-budget window would defeat why we degraded.
				tiers = append(tiers, TierEscalation)
				continue
			}
			break
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
			// The G-AI-2c classification: was there anything to reason about?
			if thinGrounding != "" {
				oc.DeclineClass = DeclineThinGrounding
			} else {
				oc.DeclineClass = DeclineModelUndetermined
			}
			// AI-204-2: when the grounding was deterministically thin, the journal line says
			// so beside the decline — no operator re-derives by hand what the backend knew.
			if oc.Detail == "" && thinGrounding != "" {
				oc.Detail = thinGrounding
			}
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
	if thinGrounding != "" {
		oc.DeclineClass = DeclineThinGrounding
	} else {
		oc.DeclineClass = DeclineModelUndetermined
	}
	if oc.Detail == "" && thinGrounding != "" {
		oc.Detail = thinGrounding // AI-204-2, same as the model's decline above
	}
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
