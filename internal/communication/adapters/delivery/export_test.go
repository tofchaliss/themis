package delivery

import (
	"context"
	"time"
)

// SetTargetForTest replaces one audience's URL after construction, to reach request-build
// failures the configure-time check would otherwise refuse.
func (d *RealWebhookDeliverer) SetTargetForTest(audience, target string) {
	d.cfg.Targets[audience] = target
}

// SweepSilentForTest runs one pass of the silent-request sweep.
func (w *Worker) SweepSilentForTest(ctx context.Context) { w.sweepSilent(ctx) }

// RunSilentSweepForTest runs the sweep loop at the given cadence until ctx is done.
func (w *Worker) RunSilentSweepForTest(ctx context.Context, every time.Duration) {
	w.runSilentSweep(ctx, every)
}

// ConfigForTest returns the worker's configuration after defaults.
func (w *Worker) ConfigForTest() Config { return w.cfg }
