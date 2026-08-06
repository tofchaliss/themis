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
	gotSel   domain.Selection // what the handler decoded — the alias tests assert on this
}

func (f *fakeInvoker) Invoke(_ context.Context, _ string, sel domain.Selection, corr string) (domain.Proposal, app.Outcome) {
	f.gotCorr, f.gotSel = corr, sel
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

// The wire contract for Selection, including the deprecated alias kept for one release so
// existing callers keep working while they migrate.
func TestInvokeCapability_SelectionOnTheWire(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantCode int
		wantType domain.SelectionType
		wantIDs  []string
	}{
		{
			name: "explicit subject", body: `{"subject":{"type":"finding","ids":["F1"]}}`,
			wantCode: http.StatusOK, wantType: domain.SelectionFinding, wantIDs: []string{"F1"},
		},
		{
			name: "a set of ids", body: `{"subject":{"type":"finding","ids":["F1","F2"]}}`,
			wantCode: http.StatusOK, wantType: domain.SelectionFinding, wantIDs: []string{"F1", "F2"},
		},
		{
			name: "release subject", body: `{"subject":{"type":"release","ids":["R1"]}}`,
			wantCode: http.StatusOK, wantType: domain.SelectionRelease, wantIDs: []string{"R1"},
		},
		{
			name: "deprecated finding_id alias still works", body: `{"finding_id":"F1"}`,
			wantCode: http.StatusOK, wantType: domain.SelectionFinding, wantIDs: []string{"F1"},
		},
		{
			// An explicit Selection is never overridden by the legacy shorthand.
			name: "subject wins when both are present", body: `{"subject":{"type":"release","ids":["R9"]},"finding_id":"F1"}`,
			wantCode: http.StatusOK, wantType: domain.SelectionRelease, wantIDs: []string{"R9"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inv := &fakeInvoker{proposal: producedProposal(), outcome: app.Outcome{Produced: true, Reason: app.ReasonOK}}
			rr := do(t, NewHandler(inv, nil), c.body)
			if rr.Code != c.wantCode {
				t.Fatalf("status = %d, want %d; body=%s", rr.Code, c.wantCode, rr.Body.String())
			}
			if inv.gotSel.Type != c.wantType {
				t.Errorf("selection type = %q, want %q", inv.gotSel.Type, c.wantType)
			}
			if len(inv.gotSel.IDs) != len(c.wantIDs) {
				t.Fatalf("ids = %v, want %v", inv.gotSel.IDs, c.wantIDs)
			}
			for i, want := range c.wantIDs {
				if inv.gotSel.IDs[i] != want {
					t.Errorf("ids[%d] = %q, want %q", i, inv.gotSel.IDs[i], want)
				}
			}
		})
	}
}

// No subject at all is a caller error.
func TestInvokeCapability_MissingSubjectIsBadRequest(t *testing.T) {
	inv := &fakeInvoker{}
	for _, body := range []string{`{}`, `{"finding_id":""}`, `{"subject":{"type":"finding","ids":[]}}`} {
		if rr := do(t, NewHandler(inv, nil), body); rr.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400", body, rr.Code)
		}
	}
}

// A Selection the capability does not accept is a CALLER error, not a declined
// recommendation. Returning 204 would read as "the AI had nothing to say" and hide a bug in
// the caller.
func TestInvokeCapability_SelectionMismatchIsBadRequestNot204(t *testing.T) {
	inv := &fakeInvoker{outcome: app.Outcome{Produced: false, Reason: app.ReasonSelectionMismatch}}
	rr := do(t, NewHandler(inv, nil), `{"subject":{"type":"release","ids":["R1"]}}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
}
