package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/http/gen"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

type fakeInvoker struct {
	proposal domain.Proposal
	outcome  app.Outcome
	gotCorr  string
}

func (f *fakeInvoker) Invoke(_ context.Context, _, _, corr string) (domain.Proposal, app.Outcome) {
	f.gotCorr = corr
	return f.proposal, f.outcome
}

func producedProposal() domain.Proposal {
	return domain.Proposal{
		Capability:     "recommend_position@v1",
		Recommendation: domain.Recommendation{FindingID: "F1", Stance: domain.StanceAffected},
		Confidence:     0.8,
		Evidence:       []domain.Evidence{{Kind: "faultline", Ref: "FL1"}},
		Reasoning:      "grounded",
		Metadata:       domain.Metadata{Provider: "ollama", Model: "llama3.1:8b"},
	}
}

func do(t *testing.T, h *Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/capabilities/recommend_position/invoke", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.Routes().ServeHTTP(rr, req)
	return rr
}

func TestInvokeHappy(t *testing.T) {
	inv := &fakeInvoker{proposal: producedProposal(), outcome: app.Outcome{Produced: true, Reason: app.ReasonOK}}
	h := NewHandler(inv, nil)
	rr := do(t, h, `{"finding_id":"F1","correlation_id":"c1"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var got gen.Proposal
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Stance == nil || *got.Stance != "affected" || got.FindingId == nil || *got.FindingId != "F1" {
		t.Errorf("proposal = %+v", got)
	}
	if got.CorrelationId == nil || *got.CorrelationId != "c1" {
		t.Errorf("correlation not echoed: %+v", got.CorrelationId)
	}
	if inv.gotCorr != "c1" {
		t.Errorf("gateway got correlation %q, want c1", inv.gotCorr)
	}
	if got.Evidence == nil || len(*got.Evidence) != 1 {
		t.Errorf("evidence = %+v", got.Evidence)
	}
}

func TestInvokeGeneratesCorrelation(t *testing.T) {
	inv := &fakeInvoker{proposal: producedProposal(), outcome: app.Outcome{Produced: true, Reason: app.ReasonOK}}
	h := NewHandler(inv, nil)
	rr := do(t, h, `{"finding_id":"F1"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if inv.gotCorr == "" {
		t.Error("a correlation id should be generated when absent")
	}
}

func TestInvokeNoProposal(t *testing.T) {
	inv := &fakeInvoker{outcome: app.Outcome{Produced: false, Reason: app.ReasonBusinessInvalid}}
	h := NewHandler(inv, nil)
	rr := do(t, h, `{"finding_id":"F1"}`)
	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %d, want 204", rr.Code)
	}
}

func TestInvokeUnknownCapability(t *testing.T) {
	inv := &fakeInvoker{outcome: app.Outcome{Produced: false, Reason: app.ReasonUnknownCap}}
	h := NewHandler(inv, nil)
	rr := do(t, h, `{"finding_id":"F1"}`)
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}

func TestInvokeBadBody(t *testing.T) {
	h := NewHandler(&fakeInvoker{}, nil)
	if rr := do(t, h, "{not json"); rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}

func TestInvokeMissingFindingID(t *testing.T) {
	h := NewHandler(&fakeInvoker{}, nil)
	if rr := do(t, h, `{"finding_id":""}`); rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rr.Code)
	}
}
