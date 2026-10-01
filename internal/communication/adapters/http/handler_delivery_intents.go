package http

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/http/gen"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/platform/observability"
)

// The outward-actions operator surface (EDR-DELIVERY-01 N-M1a): see what Themis decided to
// send outside the estate, and re-drive or withdraw the ones that failed.
//
// WHY ALL FOUR ROUTES ARE ADMIN-ONLY, READS INCLUDED. The other Communication routes take
// the node's method floor (`RequireWriteScope`: any authenticated key may read, a
// write-capable one may mutate). These do not, for two reasons that both point the same way.
// A mutation here re-drives an action against a system OUTSIDE the estate, and the only
// non-admin write grant in the closed vocabulary is `product:<id>` — which this context
// cannot confine, because a delivery intent's lineage does not always reach a product (a
// proposal_accepted event names a Finding and nothing else). D4's rule for an indeterminate
// product is to refuse, not to guess. And the list itself is a cross-product view of the
// estate's outward traffic, so serving it to a product-scoped key would hand over exactly
// the estate detail D5a exists to withhold.
//
// When inbound auth is DISABLED on the node there is no principal at all and the whole
// /api/v1 surface is open (dev, and the node says so loudly at startup). The gate then adds
// nothing, exactly like every other route.
//
// WHY ONE GUARD LINE PER ROUTE AND NOT A MIDDLEWARE ON THE GROUP. This follows the precedent
// EDR-DELIVERY-01 D7 set for Governance's write gate, for the same reason: the generated chi
// router owns the routing table, so a middleware mounted on a path PREFIX would be a second
// table that can silently disagree with it — and the failure mode of that disagreement is a
// route that looks gated and is not. The completeness guarantee lives in the test instead:
// `TestDeliveryIntents_AdminOnly` enumerates all four routes × three refused principals, so a
// fifth route added without this call fails the matrix. That is the only place completeness can
// be checked mechanically.
//
// A 401 never comes from here. An unauthenticated request is refused upstream by the node's
// `auth.RequireAPIKey` middleware and never reaches a handler; what this function decides is the
// 403, i.e. an authenticated principal that is not admin.
func (h *Handler) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		return true // auth disabled on this node — the open surface is the node's decision
	}
	if !p.IsAdmin() {
		writeProblem(w, http.StatusForbidden, "Forbidden",
			"the delivery-intent surface requires an admin key")
		return false
	}
	return true
}

// intentSurfaceUnavailable answers the four /delivery routes when this node does not serve them,
// which at N-M1a has ONE cause worth stating: the operator surface is OFF BY DEFAULT because the
// API addition is an outstanding must-ask (EDR-DELIVERY-01 D15). An operator who hits this needs
// to know it is a switch and which switch, not that something is broken — so the refusal names
// the variable. Recording, sending, retrying and dead-lettering all run regardless; only this
// read/mutate surface is gated, which is why the detail says where the counts still are.
func intentSurfaceUnavailable(w http.ResponseWriter) {
	writeProblem(w, http.StatusNotImplemented, "delivery-intent operator API not enabled",
		"this node does not serve /delivery/intents: set THEMIS_DELIVERY_OPERATOR_API=1 to enable it. "+
			"It is off by default while the API addition awaits owner approval (EDR-DELIVERY-01 D15). "+
			"Delivery intents are still recorded, sent and dead-lettered; see the node log and "+
			"scripts/vm-verify.sh for their counts.")
}

// ListDeliveryIntents handles GET /delivery/intents?status=&kind=&limit=&offset=.
func (h *Handler) ListDeliveryIntents(w http.ResponseWriter, r *http.Request, params gen.ListDeliveryIntentsParams) {
	if !h.requireAdmin(w, r) {
		return
	}
	if h.intents == nil {
		intentSurfaceUnavailable(w)
		return
	}
	// The OpenAPI declares `limit` with `default: 50`, and oapi-codegen does NOT bind a
	// declared default — an omitted `limit` arrives as a nil pointer, and a nil pointer
	// dereferenced to 0 would mean `LIMIT 0` to Postgres: an empty page, which an operator
	// asking "what failed?" would read as "nothing failed". So the edge applies the contract
	// it publishes, from the same constant the app's floor uses. Both ends, one number.
	filter := app.IntentFilter{Limit: app.DefaultIntentPageSize, Offset: derefInt(params.Offset)}
	if params.Limit != nil && *params.Limit > 0 {
		// REFUSE a page past the cap rather than silently clamping it. Both bound the query
		// equally, but a clamp lets the caller believe they received everything there was —
		// which, on the one endpoint whose job is "show me every failure", is the worst
		// possible way to be wrong. The app's clamp stays underneath as the floor for callers
		// that are not this edge.
		if *params.Limit > app.MaxIntentPageSize {
			writeProblem(w, http.StatusBadRequest, "limit too large",
				fmt.Sprintf("limit must be at most %d (got %d); page with offset instead",
					app.MaxIntentPageSize, *params.Limit))
			return
		}
		filter.Limit = *params.Limit
	}
	if params.Status != nil && *params.Status != "" {
		// Accept `dead_letter` as readily as `DEAD_LETTER`: the status is upper-case in the
		// record and lower-case in every query string a person actually types.
		status := domain.IntentStatus(strings.ToUpper(strings.TrimSpace(*params.Status)))
		if !status.Valid() {
			writeProblem(w, http.StatusBadRequest, "invalid status", "unknown delivery-intent status "+*params.Status)
			return
		}
		filter.Status = status
	}
	if params.Kind != nil && *params.Kind != "" {
		kind := domain.DeliveryKind(strings.ToLower(strings.TrimSpace(*params.Kind)))
		if !kind.Valid() {
			writeProblem(w, http.StatusBadRequest, "invalid kind", "unknown delivery kind "+*params.Kind)
			return
		}
		filter.Kind = kind
	}

	intents, err := h.intents.ListIntents(r.Context(), filter)
	if err != nil {
		h.writeIntentFault(w, r, "cannot list delivery intents", err)
		return
	}
	out := make([]gen.DeliveryIntent, 0, len(intents))
	for _, in := range intents {
		out = append(out, toDeliveryIntentView(in, nil)) // the list omits the history
	}
	writeJSON(w, http.StatusOK, out)
}

// GetDeliveryIntent handles GET /delivery/intents/{id} — the intent plus its full history.
func (h *Handler) GetDeliveryIntent(w http.ResponseWriter, r *http.Request, id string) {
	if !h.requireAdmin(w, r) {
		return
	}
	if h.intents == nil {
		intentSurfaceUnavailable(w)
		return
	}
	intent, attempts, err := h.intents.GetIntent(r.Context(), id)
	if err != nil {
		h.writeIntentErr(w, r, "cannot read delivery intent", err)
		return
	}
	writeJSON(w, http.StatusOK, toDeliveryIntentView(intent, attempts))
}

// RetryDeliveryIntent handles POST /delivery/intents/{id}/retry.
func (h *Handler) RetryDeliveryIntent(w http.ResponseWriter, r *http.Request, id string) {
	h.transitionIntent(w, r, id, "cannot retry delivery intent", h.retry)
}

// CancelDeliveryIntent handles POST /delivery/intents/{id}/cancel.
func (h *Handler) CancelDeliveryIntent(w http.ResponseWriter, r *http.Request, id string) {
	h.transitionIntent(w, r, id, "cannot cancel delivery intent", h.cancel)
}

func (h *Handler) retry(r *http.Request, id string) (domain.DeliveryIntent, error) {
	return h.intents.RetryIntent(r.Context(), id)
}

func (h *Handler) cancel(r *http.Request, id string) (domain.DeliveryIntent, error) {
	return h.intents.CancelIntent(r.Context(), id)
}

// transitionIntent runs the shared shape of the two operator mutations: the same gate, the
// same not-configured refusal, the same error mapping. Only the transition differs, so only
// the transition is a parameter — two copies of this would be two places for the 403 to
// drift out of step.
func (h *Handler) transitionIntent(w http.ResponseWriter, r *http.Request, id, title string,
	apply func(*http.Request, string) (domain.DeliveryIntent, error)) {
	if !h.requireAdmin(w, r) {
		return
	}
	if h.intents == nil {
		intentSurfaceUnavailable(w)
		return
	}
	intent, err := apply(r, id)
	if err != nil {
		h.writeIntentErr(w, r, title, err)
		return
	}
	writeJSON(w, http.StatusOK, toDeliveryIntentView(intent, nil))
}

// writeIntentErr maps the intent-flow errors onto transport statuses: an unknown intent is a
// 404, a refused transition a 409 (the resource exists and its state says no — not a malformed
// request), anything else a 500.
//
// The 404 and 409 details are the DOMAIN's own sentences — "this intent is not retryable" tells
// the caller exactly what they need and reveals nothing they did not already name. A 500 is the
// opposite case and is handled separately below.
func (h *Handler) writeIntentErr(w http.ResponseWriter, r *http.Request, title string, err error) {
	switch {
	case errors.Is(err, app.ErrIntentNotFound):
		writeProblem(w, http.StatusNotFound, title, err.Error())
	case errors.Is(err, domain.ErrIntentNotRetryable), errors.Is(err, domain.ErrIntentNotCancellable):
		writeProblem(w, http.StatusConflict, title, err.Error())
	default:
		h.writeIntentFault(w, r, title, err)
	}
}

// writeIntentFault answers an infrastructure failure. The caller gets a GENERIC detail and the
// operator gets the real one through the shared logger (R1), which is the same split
// EDR-DELIVERY-01 D5a makes for an authorization refusal and for the same reason: a driver's
// error text is written for whoever runs the database, not for whoever called the API. A pgx
// message can carry the DSN, a host and port, a constraint or column name, or a fragment of the
// statement — estate detail that the response body is the one place guaranteed to be read. The
// routes being admin-only is why this is defence in depth rather than a leak, not a reason to
// skip it: an error body gets pasted into tickets and chat logs that the gate does not cover.
func (h *Handler) writeIntentFault(w http.ResponseWriter, r *http.Request, title string, err error) {
	// The correlation id is read off the RESPONSE header: observability.RequestLogger sets it
	// there before the handler runs (echoing an inbound X-Correlation-ID or minting one), so the
	// log line and the response the caller holds name the same request. That is what makes a
	// generic body actionable — the caller can quote the id and the operator finds the cause.
	cid := w.Header().Get(observability.CorrelationHeader)
	h.logger.Error("delivery-intent request failed",
		observability.String("title", title),
		observability.String("path", r.URL.Path),
		observability.String("correlation_id", cid),
		observability.Err(err))
	writeProblem(w, http.StatusInternalServerError, title,
		"the request could not be completed; the cause is in the node log, under correlation id "+cid)
}

func toDeliveryIntentView(in domain.DeliveryIntent, attempts []domain.DeliveryAttempt) gen.DeliveryIntent {
	o := in.Origin()
	id, kind, dest, status := in.ID(), string(in.Kind()), in.Destination(), string(in.Status())
	att, maxAtt, lastErr, hash := in.Attempts(), in.MaxAttempts(), in.LastError(), in.PayloadHash()
	evtID, evtType := o.EventID, o.EventType
	evtTime := o.EventTime.UTC().Format(time.RFC3339)
	fnd, rel, fl, cve, prop, ver := o.FindingID, o.ReleaseID, o.FaultlineID, o.CVE, o.ProposalID, o.PositionVersion
	next := in.NextAttemptAt().UTC().Format(time.RFC3339)
	created := in.CreatedAt().UTC().Format(time.RFC3339)
	updated := in.UpdatedAt().UTC().Format(time.RFC3339)
	view := gen.DeliveryIntent{
		Id: &id, Kind: &kind, Destination: &dest, Status: &status,
		Attempts: &att, MaxAttempts: &maxAtt, LastError: &lastErr, PayloadHash: &hash,
		OriginEventId: &evtID, OriginEventType: &evtType, OriginEventTime: &evtTime,
		FindingId: &fnd, ReleaseId: &rel, FaultlineId: &fl, Cve: &cve, ProposalId: &prop,
		PositionVersion: &ver,
		NextAttemptAt:   &next, CreatedAt: &created, UpdatedAt: &updated,
	}
	// The payload bytes themselves are NOT exposed: the operator needs to know what was
	// decided and how it went, and the hash already pins which bytes that was.
	if attempts != nil {
		history := make([]gen.DeliveryAttempt, 0, len(attempts))
		for _, a := range attempts {
			no, ok, errStr := a.AttemptNo, a.OK, a.Error
			at := a.At.UTC().Format(time.RFC3339)
			history = append(history, gen.DeliveryAttempt{AttemptNo: &no, Ok: &ok, Error: &errStr, AttemptedAt: &at})
		}
		view.AttemptsHistory = &history
	}
	return view
}

func derefInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}
