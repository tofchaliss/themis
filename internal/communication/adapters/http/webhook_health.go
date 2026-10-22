package http

import (
	"net/http"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/http/gen"
)

// GetWebhookHealth lists every webhook destination's recorded health (EDR-REMEDIATION-01 D4).
// Destinations are audience names: a URL never leaves the node, since an incoming-webhook URL
// is itself a credential.
func (h *Handler) GetWebhookHealth(w http.ResponseWriter, r *http.Request) {
	if h.health == nil {
		writeProblem(w, http.StatusServiceUnavailable, "webhook health unavailable", "outward delivery is not enabled on this node")
		return
	}
	hs, err := h.health.ListWebhookHealth(r.Context())
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "read webhook health", err.Error())
		return
	}
	out := make([]gen.WebhookHealth, 0, len(hs))
	for _, x := range hs {
		v := gen.WebhookHealth{Destination: x.Destination, State: gen.WebhookHealthState(x.State), ConsecutiveFailures: x.ConsecutiveFailures,
			PausedUntil: timeOrNil(x.PausedUntil), LastSuccessAt: timeOrNil(x.LastSuccessAt), LastFailureAt: timeOrNil(x.LastFailureAt)}
		if x.LastError != "" {
			e := x.LastError
			v.LastError = &e
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
