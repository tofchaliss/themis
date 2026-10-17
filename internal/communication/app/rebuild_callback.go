package app

import (
	"context"
	"errors"
	"strings"
	"time"
)

// The CI rebuild callback (EDR-DELIVERY-01 M2-7 / N-M2h). The job that Themis asked to rebuild
// a Release uploads the new SBOM to Evidence and then calls back naming the intent, the new
// SBOM and the image it built. The callback is governed-external evidence ON THE INTENT and
// nothing more: it changes no Finding, no Position and no posture — a build system asserting a
// fix is asserted trust (D-N-4, D-N-7). Only the evaluation of the uploaded SBOM can establish
// that a fault is absent, and that arrives as a release_evaluated event like any other.

var (
	// ErrCallbackIncomplete — a callback missing its intent, its SBOM or its image digest is
	// refused: a rebuild whose output cannot be named gives the loop nothing to compare (RC-3).
	ErrCallbackIncomplete = errors.New("ci-rebuild callback incomplete: intent_id, sbom_id and image_digest are required")
	// ErrNotRebuildIntent — the named intent exists but did not ask for a build.
	ErrNotRebuildIntent = errors.New("ci-rebuild callback names an intent that is not a ci_rebuild")
	// ErrCallbacksUnavailable — this node holds no callback store (outward delivery is off).
	ErrCallbacksUnavailable = errors.New("ci-rebuild callbacks are not recorded on this node (outward delivery is off)")
)

// RebuildCallback is one build system report about one rebuild intent.
type RebuildCallback struct {
	IntentID    string
	SBOMID      string
	ImageDigest string
	BuildID     string
	GitRef      string
	// ReportedBy is the authenticated key id that presented the callback, for the audit trail.
	ReportedBy string
	ReceivedAt time.Time
}

// RebuildCallbacks is the store port for callback evidence.
type RebuildCallbacks interface {
	// RecordCallback persists the callback and returns it as stored. It is idempotent per
	// (intent, sbom): a repeated report returns the first row and records nothing.
	RecordCallback(ctx context.Context, cb RebuildCallback) (RebuildCallback, error)
	// ListCallbacks returns the callbacks recorded for one intent, oldest first.
	ListCallbacks(ctx context.Context, intentID string) ([]RebuildCallback, error)
}

// WithRebuildCallbacks attaches the callback store.
func (s *DeliveryIntentService) WithRebuildCallbacks(cbs RebuildCallbacks) *DeliveryIntentService {
	s.callbacks = cbs
	return s
}

// RecordRebuildCallback validates and records a callback against the intent it names. The
// intent must exist and be a ci_rebuild; the SBOM id and the image digest are required. It
// creates no intent, sends nothing and touches nothing outside the callback table — the whole
// of M2-7's "the callback alone is not news about security".
func (s *DeliveryIntentService) RecordRebuildCallback(ctx context.Context, cb RebuildCallback) (RebuildCallback, error) {
	if s.callbacks == nil {
		return RebuildCallback{}, ErrCallbacksUnavailable
	}
	cb.IntentID, cb.SBOMID, cb.ImageDigest = strings.TrimSpace(cb.IntentID), strings.TrimSpace(cb.SBOMID), strings.TrimSpace(cb.ImageDigest)
	if cb.IntentID == "" || cb.SBOMID == "" || cb.ImageDigest == "" {
		return RebuildCallback{}, ErrCallbackIncomplete
	}
	in, err := s.intents.GetIntent(ctx, cb.IntentID)
	if err != nil {
		return RebuildCallback{}, err
	}
	if in.Type != IntentCIRebuild {
		return RebuildCallback{}, ErrNotRebuildIntent
	}
	if cb.ReceivedAt.IsZero() {
		cb.ReceivedAt = s.clock.Now()
	}
	return s.callbacks.RecordCallback(ctx, cb)
}
