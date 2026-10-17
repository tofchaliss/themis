package http

import (
	"errors"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/communication/adapters/http/gen"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/platform/auth"
)

// CallbackRoutePath is the CI rebuild callback's path under the API mount (EDR-DELIVERY-01
// M2-7 / N-M2h). It is named here because the composition root mounts it OUTSIDE the
// method-based write floor: the floor refuses every POST from a key that cannot write, and the
// callback key must never be able to write — so the floor would refuse the one caller the
// route exists for. The handler enforces the route's own rule instead: `delivery:callback`
// and no other scope.
const CallbackRoutePath = "/callbacks/ci-rebuild"

// WriteFloorExcept applies floor to every request except the one mounted callback route, which
// goes through to the handler's own scope check. `mounted` is the route's full path as the
// router sees it (mount prefix included). Only that exact path is exempt — a prefix match
// would widen the hole to anything spelled under it.
func WriteFloorExcept(mounted string, floor func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		floored := floor(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == mounted {
				next.ServeHTTP(w, r)
				return
			}
			floored.ServeHTTP(w, r)
		})
	}
}

// WithRebuildCallbacks attaches the delivery-intent service the callback is recorded through.
// Without it the route answers 503: a node with outward delivery off has no intent a build
// could be reporting on.
func (h *Handler) WithRebuildCallbacks(intents *app.DeliveryIntentService) *Handler {
	h.intents = intents
	return h
}

// RecordCIRebuildCallback handles POST /callbacks/ci-rebuild (M2-7). With auth on, the
// principal must hold `delivery:callback` — admin and product keys are refused too, because a
// key that can write Governance must not also be the key a build system presents (two keys,
// not one). With auth off there is no principal and the route is open, like every other.
// The callback is recorded as evidence on the intent and nothing else happens here: no intent
// is created, nothing is sent, no Finding is touched.
func (h *Handler) RecordCIRebuildCallback(w http.ResponseWriter, r *http.Request) {
	if p, ok := auth.PrincipalFrom(r.Context()); ok && !p.IsDeliveryCallback() {
		writeProblem(w, http.StatusForbidden, "callback key required",
			"this route accepts only a key holding the delivery:callback scope — a build system reports with its own credential, never with a write-capable one")
		return
	}
	if h.intents == nil {
		writeProblem(w, http.StatusServiceUnavailable, "callbacks not recorded", app.ErrCallbacksUnavailable.Error())
		return
	}
	var body gen.CIRebuildCallback
	if !decode(w, r, &body) {
		return
	}
	cb := app.RebuildCallback{
		IntentID: body.IntentId, SBOMID: body.SbomId, ImageDigest: body.ImageDigest,
		BuildID: deref(body.BuildId), GitRef: deref(body.GitRef),
	}
	if p, ok := auth.PrincipalFrom(r.Context()); ok {
		cb.ReportedBy = "key:" + strings.TrimSpace(p.KeyID)
	}
	stored, err := h.intents.RecordRebuildCallback(r.Context(), cb)
	switch {
	case err == nil:
	case errors.Is(err, app.ErrCallbackIncomplete):
		writeProblem(w, http.StatusBadRequest, "callback incomplete", err.Error())
		return
	case errors.Is(err, app.ErrIntentNotFound):
		writeProblem(w, http.StatusNotFound, "intent not found", err.Error())
		return
	case errors.Is(err, app.ErrNotRebuildIntent):
		writeProblem(w, http.StatusConflict, "not a rebuild intent", err.Error())
		return
	case errors.Is(err, app.ErrCallbacksUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, "callbacks not recorded", err.Error())
		return
	default:
		writeProblem(w, http.StatusInternalServerError, "cannot record callback", err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, gen.CIRebuildCallbackAck{IntentId: stored.IntentID, SbomId: stored.SBOMID, ReceivedAt: stored.ReceivedAt})
}
