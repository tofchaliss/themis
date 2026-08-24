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

// Reason headers carried on a 204 so a caller can tell a declined recommendation from an
// outage or a disabled seam (AI-204-1). They are advisory metadata, never a contract a
// caller must depend on — an absent header means an older node.
const (
	reasonHeader = "X-Themis-AI-Reason"
	detailHeader = "X-Themis-AI-Detail"
)

// Invoker is the reactive Gateway the handler drives (*app.Gateway satisfies it).
type Invoker interface {
	Invoke(ctx context.Context, capabilityID string, sel domain.Selection, correlationID string) (domain.Proposal, app.Outcome)
}

// PrecedentRetriever is the read side of the shared retrieval seam (*app.PrecedentService
// satisfies it). The handler is given the SAME instance the Gateway grounds on — that is the
// whole point of the endpoint, and wiring a second one would quietly defeat it.
type PrecedentRetriever interface {
	RetrieveForFinding(ctx context.Context, findingID string, topK int, includeSameRelease bool) ([]domain.PrecedentPosition, error)
}

// Handler serves the reactive invoke API and logs execution telemetry.
type Handler struct {
	invoker    Invoker
	precedents PrecedentRetriever
	redactor   app.Redactor
	logger     *observability.Logger
}

// NewHandler builds the handler. A nil logger falls back to a no-op.
func NewHandler(inv Invoker, logger *observability.Logger) *Handler {
	if logger == nil {
		logger = observability.Nop()
	}
	return &Handler{invoker: inv, logger: logger}
}

// WithPrecedents enables GET /findings/{id}/similar over the given retrieval seam, scrubbing
// each result through the redactor on the way out (the output-boundary half of the split
// described on app.PrecedentService). Left unset, the route answers 404 — a node wired without
// a retrieval plane has no precedent to show, and saying so is better than an empty list that
// reads as "we looked and found nothing".
func (h *Handler) WithPrecedents(p PrecedentRetriever, r app.Redactor) *Handler {
	h.precedents, h.redactor = p, r
	return h
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
	sel, ok := selectionFrom(req)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "a subject is required",
			"supply subject {type, ids} (or the deprecated finding_id)")
		return
	}

	correlationID := uuid.NewString()
	if req.CorrelationId != nil && *req.CorrelationId != "" {
		correlationID = *req.CorrelationId
	}

	proposal, oc := h.invoker.Invoke(r.Context(), id, sel, correlationID)
	h.logTelemetry(oc)

	if oc.Reason == app.ReasonUnknownCap {
		writeProblem(w, http.StatusNotFound, "unknown capability", id)
		return
	}
	// A Selection this capability does not accept is a caller error, not a declined
	// recommendation — surfacing it as 204 would read as "the AI had nothing to say".
	if oc.Reason == app.ReasonSelectionMismatch {
		writeProblem(w, http.StatusBadRequest, "selection not accepted by this capability",
			"check the subject type and how many ids the capability takes")
		return
	}
	// An Information Response is CONTENT, and returning it as 204 would have thrown the answer
	// away at the last hop — the same class of loss as AI-204-1 one layer up. It is deliberately
	// NOT a Proposal: `produced` stays false, nothing reaches Governance, and there is nothing to
	// accept (T7).
	if !oc.Produced && oc.Reason == app.ReasonOK && oc.Information != "" {
		writeJSON(w, http.StatusOK, gen.InformationResponse{
			Capability:    strptr(oc.CapabilityID),
			SubjectId:     strptr(oc.Selection.First()),
			Information:   strptr(oc.Information),
			DecidedBy:     strptr(oc.DecidedBy),
			CorrelationId: strptr(correlationID),
		})
		return
	}
	if !oc.Produced {
		// Carry WHY on the 204 (AI-204-1). A bare 204 collapses causes that demand opposite
		// responses: AI disabled (fix your config), the provider unreachable or timed out (an
		// outage), and the model correctly declining for want of grounding (`insufficient` —
		// the seam working as designed, and arguably its most valuable behaviour). Diagnosing a
		// caller-side timeout once cost a round-trip through this node's log precisely because
		// the three were indistinguishable at the edge.
		//
		// Headers, not a body: 204 means "no content", and a payload here would be
		// non-conforming. Response headers are legal on a 204 and every HTTP client can read
		// them, so an older caller that ignores them still behaves exactly as before.
		w.Header().Set(reasonHeader, string(oc.Reason))
		if oc.Detail != "" {
			w.Header().Set(detailHeader, oc.Detail)
		}
		w.WriteHeader(http.StatusNoContent) // no proposal — a safe outcome
		return
	}

	writeJSON(w, http.StatusOK, toGenProposal(proposal, correlationID))
}

// strptr returns a pointer to s — the generated wire types use optional (pointer) fields.
func strptr(s string) *string { return &s }

// GetSimilarFindings handles GET /findings/{id}/similar — the retrieval seam served straight to
// a human, with no model in the path.
//
// It is the OUTPUT BOUNDARY for this consumer: the service returns unredacted precedent, and
// every rationale is scrubbed here, on the way out of the process. The stored Position is
// untouched — redaction is a projection, not an edit.
//
// There is no "declined" outcome to represent, so unlike the invoke endpoint this never answers
// 204: either the Finding exists and we report what resembles it (possibly nothing), or it does
// not and that is a 404.
func (h *Handler) GetSimilarFindings(w http.ResponseWriter, r *http.Request, id string, params gen.GetSimilarFindingsParams) {
	if h.precedents == nil {
		writeProblem(w, http.StatusNotFound, "precedent retrieval not enabled",
			"this node runs without a retrieval plane; set THEMIS_DATABASE_DSN on the Intelligence node")
		return
	}
	topK := 0
	if params.K != nil {
		topK = *params.K
	}
	includeSame := params.IncludeSameRelease != nil && *params.IncludeSameRelease

	found, err := h.precedents.RetrieveForFinding(r.Context(), id, topK, includeSame)
	if err != nil {
		writeProblem(w, http.StatusNotFound, "no such finding", "")
		return
	}

	out := gen.SimilarFindings{FindingId: id, Precedents: toGenPrecedents(app.RedactPrecedents(h.redactor, found))}
	writeJSON(w, http.StatusOK, out)
}

// toGenPrecedents maps the domain view to the wire shape. Precedents is built non-nil so an
// empty result serializes as `[]` rather than `null`: a caller distinguishing "no precedent"
// from "field missing" should not have to.
func toGenPrecedents(in []domain.PrecedentPosition) []gen.PrecedentPosition {
	out := make([]gen.PrecedentPosition, 0, len(in))
	for _, p := range in {
		item := gen.PrecedentPosition{ReleaseId: p.ReleaseID, Stance: p.Stance}
		if p.SourceCVE != "" {
			item.SourceCve = strPtr(p.SourceCVE)
		}
		if p.Component != "" {
			item.Component = strPtr(p.Component)
		}
		if p.Rationale != "" {
			item.Rationale = strPtr(p.Rationale)
		}
		score := p.Score
		item.Score = &score
		// Absent (not zero) when the delta could not be computed — 0 would read as "totally
		// different release" when the truth is "we could not ask" (G-AI-3).
		if p.OverlapKnown {
			overlap := p.ReleaseOverlap
			item.ReleaseOverlap = &overlap
		}
		out = append(out, item)
	}
	return out
}

// logTelemetry emits the per-invocation execution record (D9), privacy-safe (no
// prompt content).
func (h *Handler) logTelemetry(oc app.Outcome) {
	fields := []observability.Field{
		observability.String("capability", oc.CapabilityID),
		observability.String("correlation_id", oc.CorrelationID),
		observability.String("provider", oc.Provider),
		observability.String("model", oc.Model),
		observability.Int("tokens", oc.TokensUsed),
		observability.Duration("duration", oc.Duration),
		observability.Bool("produced", oc.Produced),
		observability.String("reason", oc.Reason),
	}
	// `tier` says which model tier produced the terminal LLM outcome (escalation/economy —
	// phase3-intelligence-router). Logged only when the router made a non-primary decision, so
	// the common line is unchanged — and so "the bigger model could not tell either" is
	// observable on a live node, which is the half of G-AI-2b that exists for operators.
	if oc.Tier != "" && oc.Tier != string(app.TierPrimary) {
		fields = append(fields, observability.String("tier", oc.Tier))
	}
	// `prompt_version` attributes the line to the exact prompt template that ran (Δ4a
	// D-Δ4a-3), so an eval's cross-deploy comparison and a live journal agree on which
	// version produced a result. Present only when an LLM step ran.
	if oc.PromptVersion != "" {
		fields = append(fields, observability.String("prompt_version", oc.PromptVersion))
	}
	// `detail` says WHICH check refused the output, and is present only when something did
	// (TRUST-6). Omitted on a clean run so the common line is unchanged, and never echoed in
	// the HTTP response — the 204 stays opaque by design.
	if oc.Detail != "" {
		fields = append(fields, observability.String("detail", oc.Detail))
	}
	if oc.DeclineClass != "" {
		fields = append(fields, observability.String("decline_class", oc.DeclineClass))
	}
	h.logger.Info("capability invoked", fields...)
	// Counted by terminal reason. This is the metric that would have made TRUST-6 a dashboard
	// question rather than a log investigation: "what fraction of invocations are refused, and
	// for which reason" is a rate, and rates do not come from log lines.
	observability.Default().RecordAIInvocation(oc.CapabilityID, oc.Reason, oc.Produced)
	// The decline-class rate (G-AI-2c): "the model can't tell" and "there was nothing to
	// tell from" are different problems with different owners, now separable on a dashboard.
	if oc.DeclineClass != "" {
		observability.Default().RecordAIDecline(oc.CapabilityID, oc.DeclineClass, oc.Tier)
	}
}

// selectionFrom reads the Selection from the request, accepting the deprecated finding_id
// alias so existing callers keep working for one release. `subject` wins when both are
// present — an explicit Selection is never overridden by a legacy shorthand.
func selectionFrom(req gen.InvokeRequest) (domain.Selection, bool) {
	if req.Subject != nil && len(req.Subject.Ids) > 0 {
		return domain.NewSelection(domain.SelectionType(req.Subject.Type), req.Subject.Ids...), true
	}
	if req.FindingId != nil && *req.FindingId != "" {
		return domain.NewSelection(domain.SelectionFinding, *req.FindingId), true
	}
	return domain.Selection{}, false
}

func toGenProposal(p domain.Proposal, correlationID string) gen.Proposal {
	evidence := make([]gen.Evidence, 0, len(p.Evidence))
	for _, e := range p.Evidence {
		evidence = append(evidence, gen.Evidence{Kind: strPtr(e.Kind), Ref: strPtr(e.Ref)})
	}
	conf := float32(p.Confidence)
	stance := string(p.Recommendation.Stance)
	out := gen.Proposal{
		Capability: strPtr(p.Capability),
		FindingId:  strPtr(p.Recommendation.FindingID),
		Stance:     &stance,
		Confidence: &conf,
		Evidence:   &evidence,
		Reasoning:  strPtr(p.Reasoning),
		Provider:   strPtr(p.Metadata.Provider),
		Model:      strPtr(p.Metadata.Model),
		DecidedBy:  strPtr(p.Metadata.DecidedBy),
		// Δ3a provenance: how many past Positions grounded this. It is what makes "our own
		// decision history changed the answer" checkable rather than asserted.
		PrecedentsUsed: intPtr(p.Metadata.PrecedentsUsed),
		CorrelationId:  strPtr(correlationID),
	}
	// Omitted when the rationale invented nothing, so a clean proposal is byte-identical on
	// the wire and an absent field reads as "nothing to caveat".
	if len(p.RationaleWarnings) > 0 {
		w := p.RationaleWarnings
		out.RationaleWarnings = &w
	}
	return out
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

// intPtr returns a pointer to i, for the generated optional response fields.
func intPtr(i int) *int { return &i }
