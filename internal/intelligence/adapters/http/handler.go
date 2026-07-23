// Package http is the Intelligence Gateway's spec-first reactive API (D3 · D9): a
// synchronous POST /capabilities/{id}/invoke that grounds, runs, validates, and
// returns a structured advisory Proposal — or 204 No Content ("no proposal"). It
// records per-invocation execution telemetry (D9) and owns no truth.
package http

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/themis-project/themis/internal/intelligence/adapters/http/gen"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

// Invoker is the reactive Gateway the handler drives (*app.Gateway satisfies it).
type Invoker interface {
	Invoke(ctx context.Context, capabilityID, subjectFindingID, correlationID string) (domain.Proposal, app.Outcome)
}

// Handler serves the reactive invoke API and logs execution telemetry.
type Handler struct {
	invoker Invoker
	logger  *observability.Logger
}

// NewHandler builds the handler. A nil logger falls back to a no-op.
func NewHandler(inv Invoker, logger *observability.Logger) *Handler {
	if logger == nil {
		logger = observability.Nop()
	}
	return &Handler{invoker: inv, logger: logger}
}

// Routes returns the chi router serving the invoke API at root paths (the /api/v1
// prefix is added by the composition root).
func (h *Handler) Routes() http.Handler {
	return gen.HandlerFromMux(h, chi.NewRouter())
}

// InvokeCapability handles POST /capabilities/{id}/invoke.
func (h *Handler) InvokeCapability(w http.ResponseWriter, r *http.Request, id string) {
	var req gen.InvokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	if req.FindingId == "" {
		writeProblem(w, http.StatusBadRequest, "finding_id is required", "")
		return
	}

	correlationID := uuid.NewString()
	if req.CorrelationId != nil && *req.CorrelationId != "" {
		correlationID = *req.CorrelationId
	}

	proposal, oc := h.invoker.Invoke(r.Context(), id, req.FindingId, correlationID)
	h.logTelemetry(oc)

	if oc.Reason == app.ReasonUnknownCap {
		writeProblem(w, http.StatusNotFound, "unknown capability", id)
		return
	}
	if !oc.Produced {
		w.WriteHeader(http.StatusNoContent) // no proposal — a safe outcome
		return
	}

	writeJSON(w, http.StatusOK, toGenProposal(proposal, correlationID))
}

// logTelemetry emits the per-invocation execution record (D9), privacy-safe (no
// prompt content).
func (h *Handler) logTelemetry(oc app.Outcome) {
	h.logger.Info("capability invoked",
		observability.String("capability", oc.CapabilityID),
		observability.String("correlation_id", oc.CorrelationID),
		observability.String("provider", oc.Provider),
		observability.String("model", oc.Model),
		observability.Int("tokens", oc.TokensUsed),
		observability.Duration("duration", oc.Duration),
		observability.Bool("produced", oc.Produced),
		observability.String("reason", oc.Reason),
	)
}

func toGenProposal(p domain.Proposal, correlationID string) gen.Proposal {
	evidence := make([]gen.Evidence, 0, len(p.Evidence))
	for _, e := range p.Evidence {
		evidence = append(evidence, gen.Evidence{Kind: strPtr(e.Kind), Ref: strPtr(e.Ref)})
	}
	conf := float32(p.Confidence)
	stance := string(p.Recommendation.Stance)
	return gen.Proposal{
		Capability:    strPtr(p.Capability),
		FindingId:     strPtr(p.Recommendation.FindingID),
		Stance:        &stance,
		Confidence:    &conf,
		Evidence:      &evidence,
		Reasoning:     strPtr(p.Reasoning),
		Provider:      strPtr(p.Metadata.Provider),
		Model:         strPtr(p.Metadata.Model),
		CorrelationId: strPtr(correlationID),
	}
}

func strPtr(s string) *string { return &s }

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeProblem(w http.ResponseWriter, status int, title, detail string) {
	writeJSON(w, status, gen.Problem{Title: strPtr(title), Detail: strPtr(detail)})
}
