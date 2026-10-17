package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
)

type cbStore struct {
	rows []app.RebuildCallback
	err  error
}

func (c *cbStore) RecordCallback(_ context.Context, cb app.RebuildCallback) (app.RebuildCallback, error) {
	if c.err != nil {
		return app.RebuildCallback{}, c.err
	}
	c.rows = append(c.rows, cb)
	return cb, nil
}
func (c *cbStore) ListCallbacks(context.Context, string) ([]app.RebuildCallback, error) {
	return c.rows, nil
}

// N-M2h: the callback is validated (intent, sbom, digest required; the intent must exist and be a
// rebuild), stamped with the clock when the caller gave no time, and recorded through the port —
// and only through the port. Without a port it refuses.
func TestRecordRebuildCallback(t *testing.T) {
	ctx := context.Background()
	store := newIntentStore()
	cbs := &cbStore{}
	svc := intentSvc(store, app.DeliveryIntentConfig{}).WithRebuildCallbacks(cbs)
	rebuild, err := svc.EnqueueCIRebuild(ctx, lineage(), "", "rel-1", "prod-1", "prj-1", "ev-1", []string{"CVE-2026-1"}, 1, nil)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	mail, err := svc.EnqueueDecisionMail(ctx, lineage(), "", "prop-1", "fnd-1", "rel-1", "", nil)
	if err != nil {
		t.Fatalf("seed mail: %v", err)
	}

	got, err := svc.RecordRebuildCallback(ctx, app.RebuildCallback{IntentID: " " + rebuild.ID + " ", SBOMID: "ev-2", ImageDigest: "sha256:abc", ReportedBy: "key:k-cb"})
	if err != nil {
		t.Fatalf("record: %v", err)
	}
	if got.IntentID != rebuild.ID || got.SBOMID != "ev-2" || !got.ReceivedAt.Equal(intentEpoch) || got.ReportedBy != "key:k-cb" {
		t.Errorf("recorded = %+v", got)
	}
	given := time.Date(2026, 10, 17, 9, 0, 0, 0, time.UTC)
	if got, err := svc.RecordRebuildCallback(ctx, app.RebuildCallback{IntentID: rebuild.ID, SBOMID: "ev-3", ImageDigest: "sha256:def", ReceivedAt: given}); err != nil || !got.ReceivedAt.Equal(given) {
		t.Errorf("a given time is kept: %+v (err %v)", got, err)
	}

	for name, tc := range map[string]struct {
		cb   app.RebuildCallback
		want error
	}{
		"no sbom":        {app.RebuildCallback{IntentID: rebuild.ID, ImageDigest: "sha256:abc"}, app.ErrCallbackIncomplete},
		"no digest":      {app.RebuildCallback{IntentID: rebuild.ID, SBOMID: "ev-2"}, app.ErrCallbackIncomplete},
		"no intent":      {app.RebuildCallback{SBOMID: "ev-2", ImageDigest: "sha256:abc"}, app.ErrCallbackIncomplete},
		"unknown intent": {app.RebuildCallback{IntentID: "int-nope", SBOMID: "ev-2", ImageDigest: "sha256:abc"}, app.ErrIntentNotFound},
		"not a rebuild":  {app.RebuildCallback{IntentID: mail.ID, SBOMID: "ev-2", ImageDigest: "sha256:abc"}, app.ErrNotRebuildIntent},
	} {
		if _, err := svc.RecordRebuildCallback(ctx, tc.cb); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	if len(cbs.rows) != 2 {
		t.Errorf("rows = %d, want the two accepted callbacks only", len(cbs.rows))
	}

	cbs.err = errors.New("db down")
	if _, err := svc.RecordRebuildCallback(ctx, app.RebuildCallback{IntentID: rebuild.ID, SBOMID: "ev-9", ImageDigest: "sha256:abc"}); err == nil {
		t.Error("a store failure must surface")
	}
	if _, err := intentSvc(store, app.DeliveryIntentConfig{}).RecordRebuildCallback(ctx, app.RebuildCallback{IntentID: rebuild.ID, SBOMID: "ev-2", ImageDigest: "x"}); !errors.Is(err, app.ErrCallbacksUnavailable) {
		t.Errorf("unwired err = %v, want ErrCallbacksUnavailable", err)
	}
}
