package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

type fakePrompt struct{ err error }

func (p fakePrompt) Render(_ string, _ domain.AssembledContext) (string, error) {
	if p.err != nil {
		return "", p.err
	}
	return "PROMPT", nil
}

type fakeEngine struct {
	replies []engineReply
	calls   int
}

type engineReply struct {
	raw string
	err error
}

func (e *fakeEngine) Kind() domain.EngineKind { return domain.EngineLLM }

func (e *fakeEngine) Execute(_ context.Context, _ ExecInput) (EngineResult, error) {
	i := e.calls
	e.calls++
	if i >= len(e.replies) {
		i = len(e.replies) - 1 // repeat the last reply
	}
	r := e.replies[i]
	if r.err != nil {
		return EngineResult{}, r.err
	}
	return EngineResult{Raw: r.raw, Provider: "fakeprov", Model: "fakemodel", TokensUsed: 5}, nil
}

const okRaw = `{"finding_id":"F1","recommended_stance":"affected","confidence":0.8,` +
	`"evidence":[{"kind":"faultline","ref":"FL1"}],"reasoning":"x"}`

func groundedReaders() (fakeFindingReader, fakeFaultlineReader) {
	return fakeFindingReader{view: domain.FindingView{ID: "F1", FaultlineID: "FL1"}},
		fakeFaultlineReader{view: domain.FaultlineView{ID: "FL1", CVE: "CVE-1"}}
}

func newTestGateway(t *testing.T, prompt PromptRenderer, engine Engine) *Gateway {
	t.Helper()
	fr, flr := groundedReaders()
	g, err := NewGateway(GatewayConfig{
		Registry:  domain.DefaultRegistry(),
		Finding:   fr,
		Faultline: flr,
		Prompt:    prompt,
		Engine:    engine,
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
	fr, flr := groundedReaders()
	fixed := time.Unix(0, 0)
	_, err := NewGateway(GatewayConfig{
		Registry: domain.DefaultRegistry(), Finding: fr, Faultline: flr,
		Prompt: fakePrompt{}, Engine: &fakeEngine{replies: []engineReply{{raw: okRaw}}},
		Now: func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
}

func TestInvokeUnknownCapability(t *testing.T) {
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: okRaw}}})
	_, oc := g.Invoke(context.Background(), "does_not_exist", "F1", "corr")
	if oc.Produced || oc.Reason != ReasonUnknownCap {
		t.Errorf("outcome = %+v, want unknown_capability/false", oc)
	}
}

func TestInvokeNoGrounding(t *testing.T) {
	g, err := NewGateway(GatewayConfig{
		Registry:  domain.DefaultRegistry(),
		Finding:   fakeFindingReader{view: domain.FindingView{}}, // empty ID = not found
		Faultline: fakeFaultlineReader{},
		Prompt:    fakePrompt{},
		Engine:    &fakeEngine{replies: []engineReply{{raw: okRaw}}},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	_, oc := g.Invoke(context.Background(), "recommend_position", "F1", "corr")
	if oc.Produced || oc.Reason != ReasonNoGrounding {
		t.Errorf("outcome = %+v, want no_grounding/false", oc)
	}
}

func TestInvokePromptError(t *testing.T) {
	g := newTestGateway(t, fakePrompt{err: errors.New("boom")}, &fakeEngine{replies: []engineReply{{raw: okRaw}}})
	_, oc := g.Invoke(context.Background(), "recommend_position", "F1", "corr")
	if oc.Reason != ReasonPromptError {
		t.Errorf("reason = %s, want prompt_error", oc.Reason)
	}
}

func TestInvokeProviderError(t *testing.T) {
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{err: errors.New("model down")}}})
	_, oc := g.Invoke(context.Background(), "recommend_position", "F1", "corr")
	if oc.Reason != ReasonProviderError {
		t.Errorf("reason = %s, want provider_error", oc.Reason)
	}
}

func TestInvokeSchemaInvalidMalformed(t *testing.T) {
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: "{not json"}}})
	_, oc := g.Invoke(context.Background(), "recommend_position", "F1", "corr")
	if oc.Produced || oc.Reason != ReasonSchemaInvalid {
		t.Errorf("outcome = %+v, want schema_invalid/false", oc)
	}
}

func TestInvokeRetryAfterMalformedThenOK(t *testing.T) {
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: "{bad"}, {raw: okRaw}}})
	p, oc := g.Invoke(context.Background(), "recommend_position", "F1", "corr")
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
	_, oc := g.Invoke(context.Background(), "recommend_position", "F1", "corr")
	if !oc.Produced || oc.Reason != ReasonOK {
		t.Errorf("outcome = %+v, want ok/true", oc)
	}
}

func TestInvokeBusinessInvalid(t *testing.T) {
	ungrounded := `{"finding_id":"F1","recommended_stance":"affected","confidence":0.8,` +
		`"evidence":[{"kind":"cve","ref":"CVE-9999-9999"}],"reasoning":"x"}`
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: ungrounded}}})
	_, oc := g.Invoke(context.Background(), "recommend_position", "F1", "corr")
	if oc.Produced || oc.Reason != ReasonBusinessInvalid {
		t.Errorf("outcome = %+v, want business_invalid/false", oc)
	}
}

func TestInvokeHappy(t *testing.T) {
	g := newTestGateway(t, fakePrompt{}, &fakeEngine{replies: []engineReply{{raw: okRaw}}})
	p, oc := g.Invoke(context.Background(), "recommend_position", "F1", "corr-9")
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
