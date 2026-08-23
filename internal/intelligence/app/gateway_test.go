package app

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

type fixedPrompt struct{ s string }

const okRaw = `{"finding_id":"F1","recommended_stance":"affected","confidence":0.8,` +
	`"evidence":[{"kind":"faultline","ref":"FL1"}],"reasoning":"x"}`

func (p fixedPrompt) Render(_ string, _ domain.AssembledContext) (string, error) { return p.s, nil }

type fakePrompt struct{ err error }

func (p fakePrompt) Render(_ string, _ domain.AssembledContext) (string, error) {
	if p.err != nil {
		return "", p.err
	}
	return "PROMPT", nil
}

// fakeEngine is a stub LLM engine returning canned raw replies (one per attempt). It
// records the last prompt + routing it saw so tests can assert redaction + local-only.
type fakeEngine struct {
	replies       []engineReply
	calls         int
	lastPrompt    string
	lastLocalOnly bool
}

type engineReply struct {
	raw string
	err error
	// tokens lets a test drive the D4 budget ledger; 0 falls back to the default cost below.
	tokens int
}

func (e *fakeEngine) Kind() domain.EngineKind { return domain.EngineLLM }

func (e *fakeEngine) Execute(_ context.Context, in ExecInput) (EngineResult, error) {
	e.lastPrompt = in.Prompt
	e.lastLocalOnly = in.Routing.LocalOnly
	i := e.calls
	e.calls++
	if i >= len(e.replies) {
		i = len(e.replies) - 1 // repeat the last reply
	}
	r := e.replies[i]
	if r.err != nil {
		return EngineResult{}, r.err
	}
	tokens := r.tokens
	if tokens == 0 {
		tokens = 5
	}
	return EngineResult{Raw: r.raw, Provider: "fakeprov", Model: "fakemodel", TokensUsed: tokens}, nil
}

// fakeProjection stands in for Governance's FindingAssessment Domain Projection. The runtime
// receives it whole — there is nothing here for the gateway to compose.
type fakeProjection struct {
	proj       domain.FindingAssessment
	err        error
	comparison domain.ReleaseComparison
	cmpErr     error
}

func (f fakeProjection) GetAssessment(context.Context, string) (domain.FindingAssessment, error) {
	return f.proj, f.err
}

func (f fakeProjection) GetReleasePosture(context.Context, string) (domain.ReleasePosture, error) {
	return domain.ReleasePosture{}, nil
}

func (f fakeProjection) GetReleaseComparison(context.Context, string, string) (domain.ReleaseComparison, error) {
	return f.comparison, f.cmpErr
}

func groundedProjection() fakeProjection {
	return fakeProjection{proj: domain.FindingAssessment{
		Finding:   domain.FindingView{ID: "F1", FaultlineID: "FL1"},
		Knowledge: domain.FaultlineView{ID: "FL1", CVE: "CVE-1"},
	}}
}

// customCap builds a valid ad-hoc capability (minimal schema, grounded needs) for
// exercising plan shapes the default catalog does not cover.
func customCap(id string, plan domain.ExecutionPlan) domain.Capability {
	return domain.Capability{
		ID:             id,
		Version:        "v1",
		SelectionType:  domain.SelectionFinding,
		MinSelection:   1,
		MaxSelection:   1,
		Needs:          []domain.ContextNeed{domain.NeedFinding, domain.NeedFaultline},
		Plan:           plan,
		OutputSchema:   `{"type":"object"}`,
		AllowedStances: []domain.Stance{domain.StanceNotAffected, domain.StanceAffected, domain.StanceMitigated},
	}
}

func gatewayWith(t *testing.T, reg *domain.Registry, engines ...Engine) *Gateway {
	t.Helper()
	proj := groundedProjection()
	g, err := NewGateway(GatewayConfig{Registry: reg, Projection: proj, Prompt: fakePrompt{}, Engines: engines})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return g
}

// newTestGateway wires a defer-only Rule engine ahead of the given LLM engine, so the
// default [Rule → LLM] plan falls through to the LLM (the Δ1 behaviour under test).
func newTestGateway(t *testing.T, prompt PromptRenderer, llm Engine) *Gateway {
	t.Helper()
	proj := groundedProjection()
	g, err := NewGateway(GatewayConfig{
		Registry: domain.DefaultRegistry(), Projection: proj,
		Prompt: prompt, Engines: []Engine{llm},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return g
}

func TestNewGatewayInvalidSchema(t *testing.T) {
	reg := domain.NewRegistry(domain.Capability{ID: "bad", OutputSchema: "{not json"})
	if _, err := NewGateway(GatewayConfig{Registry: reg}); err == nil {
		t.Error("capability with invalid schema should fail NewGateway")
	}
}

func TestNewGatewayCustomClock(t *testing.T) {
	proj := groundedProjection()
	fixed := time.Unix(0, 0)
	_, err := NewGateway(GatewayConfig{
		Registry: domain.DefaultRegistry(), Projection: proj,
		Prompt: fakePrompt{}, Engines: []Engine{&fakeEngine{replies: []engineReply{{raw: okRaw}}}},
		Now: func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
}

func TestInvokeUnknownCapability(t *testing.T) {
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: okRaw}}})
	_, oc := g.Invoke(context.Background(), "does_not_exist", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if oc.Produced || oc.Reason != ReasonUnknownCap {
		t.Errorf("outcome = %+v, want unknown_capability/false", oc)
	}
}

func TestInvokeNoGrounding(t *testing.T) {
	g, err := NewGateway(GatewayConfig{
		Registry:   domain.DefaultRegistry(),
		Projection: fakeProjection{}, // empty projection = not found
		Prompt:     fakePrompt{},
		Engines:    []Engine{&fakeEngine{replies: []engineReply{{raw: okRaw}}}},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if oc.Produced || oc.Reason != ReasonNoGrounding {
		t.Errorf("outcome = %+v, want no_grounding/false", oc)
	}
}

func TestInvokePromptError(t *testing.T) {
	g := newTestGateway(t, fakePrompt{err: errors.New("boom")}, &fakeEngine{replies: []engineReply{{raw: okRaw}}})
	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if oc.Reason != ReasonPromptError {
		t.Errorf("reason = %s, want prompt_error", oc.Reason)
	}
}

func TestInvokeProviderError(t *testing.T) {
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{err: errors.New("model down")}}})
	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if oc.Reason != ReasonProviderError {
		t.Errorf("reason = %s, want provider_error", oc.Reason)
	}
}

func TestInvokeSchemaInvalidMalformed(t *testing.T) {
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: "{not json"}}})
	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if oc.Produced || oc.Reason != ReasonSchemaInvalid {
		t.Errorf("outcome = %+v, want schema_invalid/false", oc)
	}
}

func TestInvokeRetryAfterMalformedThenOK(t *testing.T) {
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: "{bad"}, {raw: okRaw}}})
	p, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if !oc.Produced || oc.Reason != ReasonOK {
		t.Fatalf("outcome = %+v, want ok/true", oc)
	}
	if p.Recommendation.Stance != domain.StanceAffected {
		t.Errorf("stance = %s", p.Recommendation.Stance)
	}
}

func TestInvokeRetryAfterSchemaViolationThenOK(t *testing.T) {
	// Valid JSON but a stance outside the schema enum → ValidateSchema fails, retry.
	badEnum := `{"finding_id":"F1","recommended_stance":"deferred","confidence":0.5,"evidence":[],"reasoning":"x"}`
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: badEnum}, {raw: okRaw}}})
	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if !oc.Produced || oc.Reason != ReasonOK {
		t.Errorf("outcome = %+v, want ok/true", oc)
	}
}

func TestInvokeBusinessInvalid(t *testing.T) {
	ungrounded := `{"finding_id":"F1","recommended_stance":"affected","confidence":0.8,` +
		`"evidence":[{"kind":"cve","ref":"CVE-9999-9999"}],"reasoning":"x"}`
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: ungrounded}}})
	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if oc.Produced || oc.Reason != ReasonBusinessInvalid {
		t.Errorf("outcome = %+v, want business_invalid/false", oc)
	}
}

func TestInvokeHappy(t *testing.T) {
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: okRaw}}})
	p, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr-9")
	if !oc.Produced || oc.Reason != ReasonOK {
		t.Fatalf("outcome = %+v, want ok/true", oc)
	}
	if oc.Provider != "fakeprov" || oc.Model != "fakemodel" || oc.TokensUsed != 5 {
		t.Errorf("telemetry = %+v", oc)
	}
	if p.Capability != "recommend_position@v1" || p.Recommendation.FindingID != "F1" {
		t.Errorf("proposal = %+v", p)
	}
	if p.Metadata.CorrelationID != "corr-9" {
		t.Errorf("metadata correlation = %s", p.Metadata.CorrelationID)
	}
}

func TestInvokeRunawayPromptGuard(t *testing.T) {
	proj := groundedProjection()
	llm := &fakeEngine{replies: []engineReply{{raw: okRaw}}}
	g, err := NewGateway(GatewayConfig{
		Registry: domain.DefaultRegistry(), Projection: proj,
		Prompt: fixedPrompt{s: strings.Repeat("x", 100)}, Engines: []Engine{llm},
		MaxPromptBytes: 10,
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if oc.Produced || oc.Reason != ReasonInsufficient || oc.DecidedBy != "guard:oversize" {
		t.Errorf("outcome = %+v, want insufficient/guard:oversize", oc)
	}
	if llm.calls != 0 {
		t.Errorf("an oversize prompt must not reach the provider; calls=%d", llm.calls)
	}
	if oc.InputBytes != 100 {
		t.Errorf("InputBytes = %d, want 100 (metered before the guard trips)", oc.InputBytes)
	}
}

func TestInvokeProviderTimeoutInsufficient(t *testing.T) {
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{err: context.DeadlineExceeded}}})
	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if oc.Produced || oc.Reason != ReasonInsufficient || oc.DecidedBy != "guard:timeout" {
		t.Errorf("outcome = %+v, want insufficient/guard:timeout (never a hard error)", oc)
	}
}

func TestInvokeUnwiredEngineKind(t *testing.T) {
	// A required (non-optional) engine kind that is not wired is a fatal ProviderError. (The
	// Knowledge kind is exempt — it is best-effort and skips when unwired; see the Δ3a tests.)
	reg := domain.NewRegistry(customCap("needs_mystery", domain.ExecutionPlan{{Engine: domain.EngineKind("mystery")}}))
	g := gatewayWith(t, reg, &fakeEngine{replies: []engineReply{{raw: okRaw}}}) // only an LLM engine wired
	_, oc := g.Invoke(context.Background(), "needs_mystery", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if oc.Produced || oc.Reason != ReasonProviderError {
		t.Errorf("outcome = %+v, want provider_error/false (unwired non-optional engine kind)", oc)
	}
}

func TestInvokeLLMDeclinesInsufficient(t *testing.T) {
	decline := `{"finding_id":"F1","recommended_stance":"insufficient","confidence":0,"evidence":[],"reasoning":"not enough data"}`
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: decline}}})
	p, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if oc.Produced {
		t.Fatalf("insufficient must not produce a proposal: %+v", oc)
	}
	if oc.Reason != ReasonInsufficient || oc.DecidedBy != "llm:insufficient" {
		t.Errorf("outcome = %+v, want insufficient / llm:insufficient (non-error)", oc)
	}
	if p.Capability != "" {
		t.Errorf("proposal must be zero for insufficient, got %+v", p)
	}
}

// --- Δ2 precedent grounding (C6) ---------------------------------------------

type capturePrompt struct{ got domain.AssembledContext }

func (p *capturePrompt) Render(_ string, ac domain.AssembledContext) (string, error) {
	p.got = ac
	return "PROMPT", nil
}

type fakePrecedent struct {
	positions []domain.PrecedentPosition
	err       error
	calls     int
	gotFL     string
	gotExcl   string
}

func (p *fakePrecedent) GetPrecedents(_ context.Context, fl, excl string) ([]domain.PrecedentPosition, error) {
	p.calls++
	p.gotFL, p.gotExcl = fl, excl
	return p.positions, p.err
}

func gatewayWithPrecedent(t *testing.T, prompt PromptRenderer, prec PrecedentReader, engines ...Engine) *Gateway {
	t.Helper()
	proj := groundedProjection()
	g, err := NewGateway(GatewayConfig{
		Registry: domain.DefaultRegistry(), Projection: proj,
		// No embedder/index: the exact-CVE fallback alone, which is what these tests cover.
		Precedents: NewPrecedentService(nil, nil, prec, 0),
		Prompt:     prompt, Engines: engines,
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return g
}

func TestInvokePullsPrecedentForLLM(t *testing.T) {
	prec := &fakePrecedent{positions: []domain.PrecedentPosition{{ReleaseID: "R2", Stance: "not_affected", Rationale: "backport"}}}
	cp := &capturePrompt{}
	g := gatewayWithPrecedent(t, cp, prec, &fakeEngine{replies: []engineReply{{raw: okRaw}}})

	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if !oc.Produced {
		t.Fatalf("outcome = %+v, want produced", oc)
	}
	if prec.calls != 1 || prec.gotFL != "FL1" {
		t.Errorf("precedent read = calls %d, fl %q; want 1 call keyed by the Faultline FL1", prec.calls, prec.gotFL)
	}
	if len(cp.got.Precedents) != 1 || cp.got.Precedents[0].ReleaseID != "R2" {
		t.Errorf("precedents in assembled context = %+v, want [R2] (labeled context)", cp.got.Precedents)
	}
}

func TestInvokePrecedentErrorDegrades(t *testing.T) {
	prec := &fakePrecedent{err: errors.New("governance down")}
	cp := &capturePrompt{}
	g := gatewayWithPrecedent(t, cp, prec, &fakeEngine{replies: []engineReply{{raw: okRaw}}})

	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if !oc.Produced {
		t.Errorf("a precedent-read failure must degrade, not block: %+v", oc)
	}
	if len(cp.got.Precedents) != 0 {
		t.Errorf("precedents must be empty on read error, got %+v", cp.got.Precedents)
	}
}

// --- Δ3a Knowledge step: semantic precedent + exact-CVE fallback -------------

// fakeSemantic stands in for the embedder + vector index behind a PrecedentService: it returns
// canned semantic precedents, or fails the embed to exercise the degrade path. `calls` counts
// index searches, so a test can still assert the retrieval ran exactly once.
type fakeSemantic struct {
	precedents []domain.PrecedentPosition
	embedErr   error
	calls      int
}

func (f *fakeSemantic) Embed(context.Context, string) ([]float32, error) {
	if f.embedErr != nil {
		return nil, f.embedErr
	}
	return []float32{1, 0}, nil
}

func (f *fakeSemantic) Model() string { return "fake" }

func (f *fakeSemantic) Search(_ []float32, _ int, _ string) []domain.PrecedentPosition {
	f.calls++
	return f.precedents
}

// knowledgeGateway builds a Gateway whose Knowledge step is served by a real PrecedentService
// over the fakes — the same service the read API uses, so these tests cover both consumers'
// retrieval behaviour rather than a stub of it.
// The projection MUST carry components and severity: they are what domain.SubjectText embeds,
// and a subject that composes to "" is correctly skipped before the embedder is called. The
// previous stub-engine version of these tests passed without them, because a stub above the
// rule cannot exercise the rule.
func knowledgeGateway(t *testing.T, prompt PromptRenderer, sem *fakeSemantic, prec PrecedentReader, llm Engine) *Gateway {
	t.Helper()
	proj := fakeProjection{proj: domain.FindingAssessment{
		Finding: domain.FindingView{
			ID: "F1", FaultlineID: "FL1", ReleaseID: "R1",
			Components: []string{"pkg:golang/openssl"},
		},
		Knowledge: domain.FaultlineView{ID: "FL1", CVE: "CVE-1", Severity: "high"},
	}}
	g, err := NewGateway(GatewayConfig{
		Registry: domain.DefaultRegistry(), Projection: proj,
		Precedents: NewPrecedentService(sem, sem, prec, 5),
		Prompt:     prompt, Engines: []Engine{llm},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return g
}

func TestKnowledgeStepFillsSemanticPrecedents(t *testing.T) {
	know := &fakeSemantic{precedents: []domain.PrecedentPosition{
		{ReleaseID: "R2", SourceCVE: "CVE-2", Component: "pkg:golang/openssl", Stance: "not_affected", Rationale: "unreachable", Score: 0.91},
		{ReleaseID: "R3", SourceCVE: "CVE-3", Stance: "affected", Rationale: "reachable", Score: 0.77},
	}}
	cp := &capturePrompt{}
	g := knowledgeGateway(t, cp, know, nil, &fakeEngine{replies: []engineReply{{raw: okRaw}}})

	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if !oc.Produced {
		t.Fatalf("outcome = %+v, want produced", oc)
	}
	if know.calls != 1 {
		t.Errorf("index searches = %d, want 1", know.calls)
	}
	if oc.PrecedentsUsed != 2 {
		t.Errorf("PrecedentsUsed = %d, want 2 (provenance)", oc.PrecedentsUsed)
	}
	if len(cp.got.Precedents) != 2 || cp.got.Precedents[0].SourceCVE != "CVE-2" {
		t.Errorf("LLM grounding = %+v, want the 2 semantic precedents", cp.got.Precedents)
	}
}

func TestKnowledgeStepPreemptsExactCVEFallback(t *testing.T) {
	know := &fakeSemantic{precedents: []domain.PrecedentPosition{{ReleaseID: "R2", SourceCVE: "CVE-2", Stance: "not_affected", Score: 0.9}}}
	prec := &fakePrecedent{positions: []domain.PrecedentPosition{{ReleaseID: "R9", Stance: "affected"}}}
	cp := &capturePrompt{}
	g := knowledgeGateway(t, cp, know, prec, &fakeEngine{replies: []engineReply{{raw: okRaw}}})

	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if !oc.Produced {
		t.Fatalf("outcome = %+v", oc)
	}
	if prec.calls != 0 {
		t.Errorf("the exact-CVE fallback must NOT run when semantic retrieval found precedent; calls=%d", prec.calls)
	}
	if len(cp.got.Precedents) != 1 || cp.got.Precedents[0].ReleaseID != "R2" {
		t.Errorf("grounding = %+v, want the semantic precedent R2", cp.got.Precedents)
	}
}

func TestKnowledgeEmptyFallsBackToExactCVE(t *testing.T) {
	know := &fakeSemantic{precedents: nil} // cold / incomplete index
	prec := &fakePrecedent{positions: []domain.PrecedentPosition{{ReleaseID: "R9", Stance: "affected", Rationale: "same cve elsewhere"}}}
	cp := &capturePrompt{}
	g := knowledgeGateway(t, cp, know, prec, &fakeEngine{replies: []engineReply{{raw: okRaw}}})

	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if !oc.Produced {
		t.Fatalf("outcome = %+v", oc)
	}
	if prec.calls != 1 {
		t.Errorf("the exact-CVE fallback must run when semantic retrieval found none; calls=%d", prec.calls)
	}
	if len(cp.got.Precedents) != 1 || cp.got.Precedents[0].ReleaseID != "R9" {
		t.Errorf("grounding = %+v, want the exact-CVE fallback R9", cp.got.Precedents)
	}
	if oc.PrecedentsUsed != 1 {
		t.Errorf("PrecedentsUsed = %d, want 1", oc.PrecedentsUsed)
	}
}

func TestKnowledgeStepErrorDegrades(t *testing.T) {
	know := &fakeSemantic{embedErr: errors.New("embedder down")}
	cp := &capturePrompt{}
	g := knowledgeGateway(t, cp, know, nil, &fakeEngine{replies: []engineReply{{raw: okRaw}}})

	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if !oc.Produced {
		t.Errorf("a Knowledge-engine failure must degrade, not block: %+v", oc)
	}
	// The embed failed, so the index is never searched — the degrade happens as early as it can.
	if know.calls != 0 {
		t.Errorf("index searches = %d, want 0 (embed failed first)", know.calls)
	}
	if len(cp.got.Precedents) != 0 || oc.PrecedentsUsed != 0 {
		t.Errorf("expected no precedent on knowledge error, got %+v / used=%d", cp.got.Precedents, oc.PrecedentsUsed)
	}
}

// --- Δ2 admission: authorize + redact + local-only (C7) ----------------------

type denyAuthorizer struct{ err error }

func (a denyAuthorizer) Authorize(context.Context, string, string) error { return a.err }

type tagRedactor struct{}

func (tagRedactor) Redact(s string) string { return "REDACTED:" + s }

func TestInvokeUnauthorized(t *testing.T) {
	proj := groundedProjection()
	llm := &fakeEngine{replies: []engineReply{{raw: okRaw}}}
	g, err := NewGateway(GatewayConfig{
		Registry: domain.DefaultRegistry(), Projection: proj,
		Prompt: fakePrompt{}, Engines: []Engine{llm},
		Authorizer: denyAuthorizer{err: errors.New("forbidden")},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if oc.Produced || oc.Reason != ReasonUnauthorized {
		t.Errorf("outcome = %+v, want unauthorized/false", oc)
	}
	if llm.calls != 0 {
		t.Errorf("an unauthorized request must be rejected before any provider call; calls=%d", llm.calls)
	}
}

func TestInvokeAuthorizedAllows(t *testing.T) {
	proj := groundedProjection()
	g, err := NewGateway(GatewayConfig{
		Registry: domain.DefaultRegistry(), Projection: proj,
		Prompt: fakePrompt{}, Engines: []Engine{&fakeEngine{replies: []engineReply{{raw: okRaw}}}},
		Authorizer: denyAuthorizer{err: nil}, // allows
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	if _, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr"); !oc.Produced {
		t.Errorf("an allowing authorizer must not block: %+v", oc)
	}
}

func TestInvokeRedactsPromptAndBindsLocalOnly(t *testing.T) {
	proj := groundedProjection()
	llm := &fakeEngine{replies: []engineReply{{raw: okRaw}}}
	g, err := NewGateway(GatewayConfig{
		Registry: domain.DefaultRegistry(), Projection: proj,
		Prompt: fakePrompt{}, Engines: []Engine{llm},
		Redactor: tagRedactor{},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	if _, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr"); !oc.Produced {
		t.Fatalf("outcome = %+v", oc)
	}
	if !strings.HasPrefix(llm.lastPrompt, "REDACTED:") {
		t.Errorf("prompt sent to provider = %q, want it redacted before the provider (C7)", llm.lastPrompt)
	}
	if !llm.lastLocalOnly {
		t.Error("the provider binding must carry LocalOnly=true (C7 local-only)")
	}
}

// A plan that walks to the end without producing must return the honest "insufficient"
// outcome — not a hang, and not a false success. A retrieval-only plan is the reachable
// case: the Knowledge step enriches grounding and never decides, so the loop exhausts.
//
// This replaces the rule-only-plan test deleted with the Rule engine (EDR-TRUST-01 T5). The
// property it guards is about the PLAN WALK, not about rules, so it must outlive them.
func TestInvokeRetrievalOnlyPlanExhaustsToInsufficient(t *testing.T) {
	reg := domain.NewRegistry(customCap("retrieval_only", domain.ExecutionPlan{{Engine: domain.EngineKnowledge}}))
	g := gatewayWith(t, reg, &fakeEngine{replies: []engineReply{{raw: okRaw}}})

	p, oc := g.Invoke(context.Background(), "retrieval_only", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if oc.Produced {
		t.Fatalf("a plan that never decides must not produce a proposal, got %+v", p)
	}
	if oc.Reason != ReasonInsufficient || oc.DecidedBy != "insufficient" {
		t.Errorf("outcome = %q/%q, want insufficient — an honest no-answer, never an error",
			oc.Reason, oc.DecidedBy)
	}
}

// A Selection the capability does not accept is rejected at the door — before grounding is
// assembled and before any provider is touched. The engines here would panic if reached.
func TestInvokeSelectionMismatchRejectedBeforeAnyWork(t *testing.T) {
	cases := []struct {
		name string
		sel  domain.Selection
	}{
		{"wrong type", domain.NewSelection(domain.SelectionRelease, "R1")},
		{"too many for a single-Finding capability", domain.NewSelection(domain.SelectionFinding, "F1", "F2")},
		{"empty", domain.NewSelection(domain.SelectionFinding)},
		{"unknown type", domain.NewSelection(domain.SelectionType("position"), "P1")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := gatewayWith(t, domain.DefaultRegistry(), &fakeEngine{replies: []engineReply{{raw: okRaw}}})
			p, oc := g.Invoke(context.Background(), "recommend_position", c.sel, "corr")
			if oc.Produced {
				t.Fatalf("must not produce a proposal, got %+v", p)
			}
			if oc.Reason != ReasonSelectionMismatch {
				t.Errorf("reason = %q, want %q", oc.Reason, ReasonSelectionMismatch)
			}
			// Nothing was spent: no provider was called, so no provenance was recorded.
			if oc.Provider != "" || oc.TokensUsed != 0 || oc.InputBytes != 0 {
				t.Errorf("rejection must cost nothing, got %+v", oc)
			}
		})
	}
}

// The Selection travels onto the telemetry record, so an invocation's provenance says what
// it was about and not merely which capability ran (T9).
func TestInvokeOutcomeCarriesTheSelection(t *testing.T) {
	g := gatewayWith(t, domain.DefaultRegistry(), &fakeEngine{replies: []engineReply{{raw: okRaw}}})
	sel := domain.NewSelection(domain.SelectionFinding, "F1")

	_, oc := g.Invoke(context.Background(), "recommend_position", sel, "corr")
	if oc.Selection.Type != domain.SelectionFinding || oc.Selection.First() != "F1" {
		t.Errorf("outcome selection = %+v, want finding/F1", oc.Selection)
	}
}

// --- Capability classes (EDR-TRUST-01 T7) -----------------------------------------------

// An Information capability produces an EPHEMERAL response and NO proposal. This is the
// structural half of "an Information Response may never become enterprise truth": the
// Gateway returns before BuildProposal is reachable, so there is nothing for a caller to
// record even if a future edit forgot the rule.
func TestInvokeInformationCapabilityProducesNoProposal(t *testing.T) {
	info := customCap("explain_vulnerability", domain.ExecutionPlan{{Engine: domain.EngineLLM, Prompt: "p"}})
	info.Output = domain.OutputInformation
	reasoning := `{"finding_id":"F1","recommended_stance":"affected","confidence":0.9,` +
		`"evidence":[],"reasoning":"Log4Shell lets an attacker..."}`
	g := gatewayWith(t, domain.NewRegistry(info), &fakeEngine{replies: []engineReply{{raw: reasoning}}})

	p, oc := g.Invoke(context.Background(), "explain_vulnerability",
		domain.NewSelection(domain.SelectionFinding, "F1"), "corr")

	if oc.Produced {
		t.Fatal("an Information capability must never produce a proposal")
	}
	if p.Recommendation.Stance != "" || p.Recommendation.FindingID != "" || p.Capability != "" {
		t.Errorf("proposal must be zero-valued, got %+v", p)
	}
	if oc.OutputClass != domain.OutputInformation {
		t.Errorf("OutputClass = %q, want %q", oc.OutputClass, domain.OutputInformation)
	}
	if oc.Information == "" {
		t.Error("the ephemeral answer should be returned for a human to read")
	}
	// Not an error and not a decline — the capability did exactly its job.
	if oc.Reason != ReasonOK {
		t.Errorf("reason = %q, want %q", oc.Reason, ReasonOK)
	}
}

// The control: the same plan on a Decision capability DOES produce a proposal, so the test
// above cannot pass merely because the pipeline is broken.
func TestInvokeDecisionCapabilityStillProducesAProposal(t *testing.T) {
	g := gatewayWith(t, domain.DefaultRegistry(), &fakeEngine{replies: []engineReply{{raw: okRaw}}})
	p, oc := g.Invoke(context.Background(), "recommend_position",
		domain.NewSelection(domain.SelectionFinding, "F1"), "corr")

	if !oc.Produced || oc.OutputClass != domain.OutputDecision {
		t.Fatalf("outcome = %+v, want produced/decision", oc)
	}
	if p.Recommendation.Stance == "" {
		t.Error("a Decision capability must produce a recordable claim")
	}
	if oc.Information != "" {
		t.Error("a Decision capability produces no ephemeral answer")
	}
}

// The shipped capability is a Decision — its stance aspires to become an Enterprise Position.
// Pinned so a later edit cannot silently reclassify it and route a governed claim down the
// ephemeral path, where nothing would ever record it.
func TestRecommendPositionIsADecisionCapability(t *testing.T) {
	if got := domain.RecommendPositionV1().Output; got != domain.OutputDecision {
		t.Fatalf("output class = %q, want %q", got, domain.OutputDecision)
	}
}

// --- TRUST-6: the outcome says WHICH check refused, not merely that one did ------------

// Four checks collapse into ReasonBusinessInvalid, and they call for opposite fixes — a
// stricter response schema, a prompt change, or a thicker projection. On a live VM the missing
// distinction made a real 204 undiagnosable from logs.
//
// Only TWO are reachable here, and that is worth knowing rather than working around: the output
// JSON schema bounds `confidence` to [0,1] and constrains `recommended_stance` to an enum, so
// those two ValidateBusiness checks are defence-in-depth behind ValidateSchema and surface as
// schema_invalid instead. They stay in the validator because the schema is per-capability
// configuration and the invariants are not.
func TestInvokeBusinessInvalid_DetailNamesTheFailedCheck(t *testing.T) {
	for _, tc := range []struct{ name, raw, want string }{
		{"wrong finding_id echo",
			`{"finding_id":"NOPE","recommended_stance":"affected","confidence":0.8,"evidence":[],"reasoning":"x"}`,
			"finding_id"},
		{"ungrounded evidence ref",
			`{"finding_id":"F1","recommended_stance":"affected","confidence":0.8,` +
				`"evidence":[{"kind":"cve","ref":"CVE-9999-9999"}],"reasoning":"x"}`,
			"ungrounded evidence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: tc.raw}}})
			_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
			if oc.Reason != ReasonBusinessInvalid {
				t.Fatalf("reason = %q, want %q", oc.Reason, ReasonBusinessInvalid)
			}
			if !strings.Contains(oc.Detail, tc.want) {
				t.Fatalf("detail = %q, want it to name %q — the reason constant alone cannot", oc.Detail, tc.want)
			}
		})
	}
}

// An exhausted schema-retry budget must also say what was wrong. Unparseable JSON and a schema
// violation point at different fixes (the response-format mode versus the prompt) and are
// identical in ReasonSchemaInvalid alone.
func TestInvokeSchemaInvalid_DetailSurvivesTheRetryLoop(t *testing.T) {
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: "not json"}, {raw: "still not json"}}})
	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if oc.Reason != ReasonSchemaInvalid {
		t.Fatalf("reason = %q, want %q", oc.Reason, ReasonSchemaInvalid)
	}
	if oc.Detail == "" {
		t.Fatal("detail is empty — the last structural complaint must survive the retry loop")
	}
}

// Detail quotes model output verbatim, so it goes through the same redaction as the prompt: a
// model that hallucinated a secret into its response must not have it copied into telemetry on
// the way out.
func TestInvokeDetailIsRedacted(t *testing.T) {
	bad := `{"finding_id":"NOPE","recommended_stance":"affected","confidence":0.8,"evidence":[],"reasoning":"x"}`
	g, err := NewGateway(GatewayConfig{
		Registry: domain.DefaultRegistry(), Projection: groundedProjection(),
		Prompt: fakePrompt{}, Engines: []Engine{&fakeEngine{replies: []engineReply{{raw: bad}}}},
		Redactor: tagRedactor{},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	_, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if !strings.HasPrefix(oc.Detail, "REDACTED:") {
		t.Fatalf("detail = %q, want it redacted before it reaches telemetry", oc.Detail)
	}
}

// --- TRUST-8: an ungrounded id in the NARRATIVE warns, but never blocks ----------------

// The proposal is valid — its structured evidence passed Grounding Verification — so a
// hallucinated id in the prose is a caveat for the human who decides, not grounds for refusing
// a well-formed proposal. Prose cannot be verified, and pretending otherwise would reject
// correct recommendations for writing style.
func TestInvokeUngroundedRationaleMentionWarnsWithoutBlocking(t *testing.T) {
	raw := `{"finding_id":"F1","recommended_stance":"affected","confidence":0.9,` +
		`"evidence":[{"kind":"cve","ref":"CVE-1"}],` +
		`"reasoning":"Included in release ee006ff7-f278-496e-8b31-ff0aba181db3."}`
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: raw}}})
	p, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")

	if !oc.Produced || oc.Reason != ReasonOK {
		t.Fatalf("outcome = %+v, want ok/true — a warned proposal is still a valid proposal", oc)
	}
	want := "ee006ff7-f278-496e-8b31-ff0aba181db3"
	if len(p.RationaleWarnings) != 1 || p.RationaleWarnings[0] != want {
		t.Fatalf("warnings = %v, want [%s]", p.RationaleWarnings, want)
	}
	if !strings.Contains(oc.Detail, want) {
		t.Fatalf("detail = %q, want the invented id recorded in telemetry too", oc.Detail)
	}
	// The narrative is preserved unedited — the caveat annotates, never rewrites, what the
	// model said. Editing model output would destroy the audit trail it is evidence of.
	if !strings.Contains(p.Reasoning, want) {
		t.Fatalf("reasoning = %q, want the original text intact", p.Reasoning)
	}
}

// A clean rationale carries no warning and no detail: a caveat on every proposal is one a
// reviewer learns to ignore.
func TestInvokeCleanRationaleCarriesNoWarning(t *testing.T) {
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: okRaw}}})
	p, oc := g.Invoke(context.Background(), "recommend_position", domain.NewSelection(domain.SelectionFinding, "F1"), "corr")
	if len(p.RationaleWarnings) != 0 {
		t.Fatalf("warnings = %v, want none", p.RationaleWarnings)
	}
	if oc.Detail != "" {
		t.Fatalf("detail = %q, want empty on a clean run", oc.Detail)
	}
}

// D4 — the per-capability window ceiling refuses BEFORE the provider call, and says so with its
// own reason.
//
// budget_exhausted is deliberately not folded into `insufficient`: nothing is broken, nothing
// declined on the merits, and it resolves by itself when the window rolls. Reporting it as
// insufficient would send an operator to debug a model that behaved perfectly.
func TestInvokeRefusesWhenTheBudgetIsExhausted(t *testing.T) {
	// 1200 against a 1000 ceiling: the first call overshoots, which is the designed behaviour —
	// admission is on remaining > 0 because a call's cost is unknowable until it returns.
	eng := &fakeEngine{replies: []engineReply{{raw: okRaw, tokens: 1200}, {raw: okRaw, tokens: 1200}}}
	g, err := NewGateway(GatewayConfig{
		Registry: domain.DefaultRegistry(), Projection: groundedProjection(),
		Prompt: fakePrompt{}, Engines: []Engine{eng},
		BudgetTokens: 1000, BudgetWindow: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	sel := domain.NewSelection(domain.SelectionFinding, "F1")

	// First call is admitted and spends past the ceiling — admission is on remaining > 0, because
	// a call's cost is unknowable until it returns.
	if _, oc := g.Invoke(context.Background(), "recommend_position", sel, "c1"); !oc.Produced {
		t.Fatalf("first call must be admitted: %+v", oc)
	}
	// Second is refused, and refused BEFORE the provider: the engine must not be called again.
	calls := eng.calls
	_, oc := g.Invoke(context.Background(), "recommend_position", sel, "c2")
	if oc.Produced || oc.Reason != ReasonBudgetExhausted {
		t.Errorf("outcome = %+v, want budget_exhausted/false", oc)
	}
	if oc.DecidedBy != "guard:budget" {
		t.Errorf("DecidedBy = %q, want guard:budget", oc.DecidedBy)
	}
	if eng.calls != calls {
		t.Errorf("engine was called %d extra times — the ceiling must refuse before the provider", eng.calls-calls)
	}
}

// Unset budget = unlimited, which is the default and today's behaviour. Enforcement must be a
// decision, never a side effect of upgrading.
func TestInvokeUnbudgetedIsUnlimited(t *testing.T) {
	eng := &fakeEngine{replies: []engineReply{
		{raw: okRaw, tokens: 100_000}, {raw: okRaw, tokens: 100_000},
	}}
	g := newTestGateway(t, fakePrompt{}, eng)
	sel := domain.NewSelection(domain.SelectionFinding, "F1")
	for i := 0; i < 2; i++ {
		if _, oc := g.Invoke(context.Background(), "recommend_position", sel, "c"); !oc.Produced {
			t.Fatalf("call %d refused with no budget configured: %+v", i, oc)
		}
	}
}
