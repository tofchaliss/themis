package domain

import "time"

// Webhook destination health (EDR-REMEDIATION-01 D4), DefectDojo's four states. It is RECORDED
// per destination so an operator can see a broken receiver beside feed health, and it decides
// one thing only: whether the next send may be attempted.
//
//	active             — the last send succeeded
//	active_tmp         — a send failed; retrying normally
//	inactive_tmp       — repeated failures; paused until PausedUntil, then tried again
//	inactive_permanent — paused too often; an operator must re-enable it

// WebhookHealthState is one of the four states.
type WebhookHealthState string

const (
	WebhookActive            WebhookHealthState = "active"
	WebhookActiveTmp         WebhookHealthState = "active_tmp"
	WebhookInactiveTmp       WebhookHealthState = "inactive_tmp"
	WebhookInactivePermanent WebhookHealthState = "inactive_permanent"
)

// Thresholds of the health ladder.
const (
	// WebhookFailuresBeforePause is how many consecutive failures move a destination to inactive_tmp.
	WebhookFailuresBeforePause = 3
	// WebhookPausesBeforeDisable is how many pauses in a row end in inactive_permanent.
	WebhookPausesBeforeDisable = 3
	// WebhookPause is how long an inactive_tmp destination waits before the next try.
	WebhookPause = time.Hour
)

// WebhookHealth is one destination's recorded health.
type WebhookHealth struct {
	Destination         string
	State               WebhookHealthState
	ConsecutiveFailures int
	Pauses              int
	PausedUntil         time.Time
	LastSuccessAt       time.Time
	LastFailureAt       time.Time
	LastError           string
}

// NewWebhookHealth is a destination never sent to: active, nothing recorded.
func NewWebhookHealth(destination string) WebhookHealth {
	return WebhookHealth{Destination: destination, State: WebhookActive}
}

// MaySend reports whether a send may be attempted at now.
func (h WebhookHealth) MaySend(now time.Time) bool {
	switch h.State {
	case WebhookInactivePermanent:
		return false
	case WebhookInactiveTmp:
		return !now.Before(h.PausedUntil)
	default:
		return true
	}
}

// Succeeded records a successful send: back to active, the failure run cleared.
func (h WebhookHealth) Succeeded(now time.Time) WebhookHealth {
	h.State, h.ConsecutiveFailures, h.Pauses, h.PausedUntil = WebhookActive, 0, 0, time.Time{}
	h.LastSuccessAt, h.LastError = now, ""
	return h
}

// Failed records a failed send and moves the destination down the ladder.
func (h WebhookHealth) Failed(now time.Time, reason string) WebhookHealth {
	h.ConsecutiveFailures++
	h.LastFailureAt, h.LastError = now, reason
	switch {
	case h.State == WebhookInactiveTmp:
		// The try after a pause failed too.
		h.Pauses++
		if h.Pauses >= WebhookPausesBeforeDisable {
			h.State, h.PausedUntil = WebhookInactivePermanent, time.Time{}
		} else {
			h.PausedUntil = now.Add(WebhookPause)
		}
	case h.ConsecutiveFailures >= WebhookFailuresBeforePause:
		h.State, h.Pauses, h.PausedUntil = WebhookInactiveTmp, 1, now.Add(WebhookPause)
	default:
		h.State = WebhookActiveTmp
	}
	return h
}

// Reenabled is the operator's reset of a destination: active, the history kept.
func (h WebhookHealth) Reenabled() WebhookHealth {
	h.State, h.ConsecutiveFailures, h.Pauses, h.PausedUntil = WebhookActive, 0, 0, time.Time{}
	return h
}

// ValidWebhookHealthState reports whether s is one of the four states.
func ValidWebhookHealthState(s WebhookHealthState) bool {
	switch s {
	case WebhookActive, WebhookActiveTmp, WebhookInactiveTmp, WebhookInactivePermanent:
		return true
	}
	return false
}
