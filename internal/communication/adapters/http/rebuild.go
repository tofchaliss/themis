package http

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/http/gen"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/platform/auth"
)

// The rebuild cycle surface (EDR-REBUILD-01 step R3): the connector's status call, the read of
// one Release's cycle, and the three things a person may do — settle an uncertain request, make
// a request again, stop a cycle. None of them touches a Finding.

// WithRebuildLoop attaches the loop these routes act through. Without it they answer 503.
func (h *Handler) WithRebuildLoop(loop *app.RebuildLoop) *Handler {
	h.loop = loop
	return h
}

// recordRebuildStatus is the status half of POST /callbacks/ci-rebuild (D28 item 2). The caller
// has already checked the delivery:callback scope.
func (h *Handler) recordRebuildStatus(w http.ResponseWriter, r *http.Request, body gen.CIRebuildCallback, reportedBy string) {
	if h.loop == nil {
		writeProblem(w, http.StatusServiceUnavailable, "rebuild requests not kept", app.ErrRebuildRequestsUnavailable.Error())
		return
	}
	req, err := h.loop.RecordStatus(r.Context(), app.RebuildStatus{
		IntentID: body.IntentId, Status: string(*body.Status), Reason: deref(body.Reason), BuildRef: deref(body.BuildRef),
		ExecutionStarted: body.ExecutionStarted != nil && *body.ExecutionStarted, ReportedBy: reportedBy,
	})
	if err != nil {
		writeRebuildErr(w, "cannot record status", err)
		return
	}
	writeJSON(w, http.StatusAccepted, gen.CIRebuildCallbackAck{IntentId: req.IntentID, State: &req.State, ReceivedAt: req.StatusAt})
}

// GetReleaseRebuildCycle handles GET /releases/{id}/rebuild-cycle.
func (h *Handler) GetReleaseRebuildCycle(w http.ResponseWriter, r *http.Request, id string) {
	if h.loop == nil {
		writeProblem(w, http.StatusServiceUnavailable, "rebuild requests not kept", app.ErrRebuildRequestsUnavailable.Error())
		return
	}
	view, err := h.loop.View(r.Context(), id)
	if err != nil {
		writeRebuildErr(w, "cannot read rebuild cycle", err)
		return
	}
	out := gen.RebuildCycleView{ReleaseId: id, Requests: make([]gen.RebuildRequest, 0, len(view.Requests))}
	if view.Cycle != nil {
		c := toRebuildCycle(*view.Cycle, h.loop.MaxAttempts())
		out.Cycle = &c
	}
	for _, req := range view.Requests {
		out.Requests = append(out.Requests, toRebuildRequest(req))
	}
	if view.Hold != nil {
		out.Hold = &gen.RebuildHold{DecisionId: view.Hold.DecisionID, Reason: gen.RebuildHoldReason(view.Hold.Reason),
			HeldUntil: timePtr(view.Hold.Until), RecordedAt: view.Hold.RecordedAt}
	}
	writeJSON(w, http.StatusOK, out)
}

// SettleRebuildRequest handles POST /rebuild-requests/{intent_id}/settle (D24).
func (h *Handler) SettleRebuildRequest(w http.ResponseWriter, r *http.Request, intentID string) {
	var body gen.RebuildSettleRequest
	if h.loop == nil {
		writeProblem(w, http.StatusServiceUnavailable, "rebuild requests not kept", app.ErrRebuildRequestsUnavailable.Error())
		return
	}
	if !decode(w, r, &body) {
		return
	}
	product, err := h.loop.ProductOfRequest(r.Context(), intentID)
	if err != nil {
		writeRebuildErr(w, "cannot settle", err)
		return
	}
	if !mayActOnProduct(w, r, product) {
		return
	}
	req, err := h.loop.Settle(r.Context(), intentID, string(body.Answer), body.Actor, deref(body.Note))
	if err != nil {
		writeRebuildErr(w, "cannot settle", err)
		return
	}
	writeJSON(w, http.StatusOK, toRebuildRequest(req))
}

// RequestRebuildAgain handles POST /releases/{id}/rebuild-cycle/request-again (D20 item 3).
func (h *Handler) RequestRebuildAgain(w http.ResponseWriter, r *http.Request, id string) {
	body, ok := h.actorOnOpenCycle(w, r, id)
	if !ok {
		return
	}
	req, err := h.loop.RequestAgain(r.Context(), id, body.Actor)
	if err != nil {
		writeRebuildErr(w, "cannot request again", err)
		return
	}
	writeJSON(w, http.StatusCreated, toRebuildRequest(req))
}

// StopRebuildCycle handles POST /releases/{id}/rebuild-cycle/stop.
func (h *Handler) StopRebuildCycle(w http.ResponseWriter, r *http.Request, id string) {
	body, ok := h.actorOnOpenCycle(w, r, id)
	if !ok {
		return
	}
	cycle, err := h.loop.Stop(r.Context(), id, body.Actor, deref(body.Note))
	if err != nil {
		writeRebuildErr(w, "cannot stop", err)
		return
	}
	writeJSON(w, http.StatusOK, toRebuildCycle(cycle, h.loop.MaxAttempts()))
}

// actorOnOpenCycle is the shared front of the two person actions on a Release's cycle: the loop
// is wired, the body reads, and the key may act on the Product of the newest cycle.
func (h *Handler) actorOnOpenCycle(w http.ResponseWriter, r *http.Request, releaseID string) (gen.RebuildActorRequest, bool) {
	var body gen.RebuildActorRequest
	if h.loop == nil {
		writeProblem(w, http.StatusServiceUnavailable, "rebuild requests not kept", app.ErrRebuildRequestsUnavailable.Error())
		return body, false
	}
	if !decode(w, r, &body) {
		return body, false
	}
	view, err := h.loop.View(r.Context(), releaseID)
	if err != nil {
		writeRebuildErr(w, "cannot read rebuild cycle", err)
		return body, false
	}
	if view.Cycle == nil {
		writeRebuildErr(w, "no rebuild cycle", app.ErrNoOpenCycle)
		return body, false
	}
	return body, mayActOnProduct(w, r, view.Cycle.ProductID)
}

// mayActOnProduct applies D22 to a person's action: an admin key, or the key of that Product.
// With auth off there is no principal and the route is open, like every other. A cycle that
// names no Product (one the posture opened) is an admin's alone.
func mayActOnProduct(w http.ResponseWriter, r *http.Request, productID string) bool {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.IsAdmin() || p.HasProductScope(strings.TrimSpace(productID)) {
		return true
	}
	writeProblem(w, http.StatusForbidden, "not allowed for this product",
		"this action needs an admin key or the key of the release's product")
	return false
}

func writeRebuildErr(w http.ResponseWriter, title string, err error) {
	switch {
	case errors.Is(err, app.ErrStatusIncomplete), errors.Is(err, app.ErrStatusUnknown),
		errors.Is(err, app.ErrActorRequired), errors.Is(err, app.ErrSettleAnswer):
		writeProblem(w, http.StatusBadRequest, title, err.Error())
	case errors.Is(err, app.ErrRebuildRequestNotFound), errors.Is(err, app.ErrNoOpenCycle):
		writeProblem(w, http.StatusNotFound, title, err.Error())
	case errors.Is(err, app.ErrStatusConflict), errors.Is(err, app.ErrNotUncertain),
		errors.Is(err, app.ErrRequestInFlight), errors.Is(err, app.ErrRebuildHeld):
		writeProblem(w, http.StatusConflict, title, err.Error())
	case errors.Is(err, app.ErrRebuildRequestsUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, title, err.Error())
	default:
		writeProblem(w, http.StatusInternalServerError, title, err.Error())
	}
}

func toRebuildRequest(r app.RebuildRequest) gen.RebuildRequest {
	return gen.RebuildRequest{
		IntentId: r.IntentID, CycleId: r.CycleID, ReleaseId: r.ReleaseID, DecisionId: r.DecisionID,
		Attempt: r.Attempt, Try: r.Try, Channel: r.Channel, State: gen.RebuildRequestState(r.State),
		Reason: strPtr(r.Reason), BuildRef: strPtr(r.BuildRef), RequestedAt: r.RequestedAt,
		DeliveredAt: timePtr(r.DeliveredAt), StatusAt: timePtr(r.StatusAt), ExecutionStartedAt: timePtr(r.ExecutionStartedAt),
		ReportedBy: strPtr(r.ReportedBy), SettledAnswer: strPtr(r.SettledAnswer), SettledBy: strPtr(r.SettledBy),
		SettledAt: timePtr(r.SettledAt), SettleNote: strPtr(r.SettleNote),
	}
}

func toRebuildCycle(c app.RebuildCycle, maxAttempts int) gen.RebuildCycle {
	origin := c.Origin
	if origin == "" {
		origin = app.CycleOriginEvaluation
	}
	targeted, joined := c.Targeted, c.Joined
	if targeted == nil {
		targeted = []string{}
	}
	return gen.RebuildCycle{
		Id: c.ID, ReleaseId: c.ReleaseID, Origin: gen.RebuildCycleOrigin(origin), DecisionId: strPtr(c.DecisionID),
		State: gen.RebuildCycleState(c.State), Attempts: c.Attempts, MaxAttempts: &maxAttempts, Refusals: c.Refusals,
		Targeted: targeted, JoinedDecisionIds: &joined, BaselineSbomId: strPtr(c.BaselineSBOMID), LastSbomId: strPtr(c.LastSBOMID),
		ClosedBy: strPtr(c.ClosedBy), ClosedNote: strPtr(c.ClosedNote), OpenedAt: c.OpenedAt, UpdatedAt: c.UpdatedAt,
	}
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
