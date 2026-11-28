package http_test

import (
	"context"
	"time"

	"github.com/themis-project/themis/internal/communication/app"
)

// loopCycles and loopRequests are small in-memory stores for the rebuild loop of
// EDR-REBUILD-01 step R3. The loop's own rules are tested in the app package; these only let
// this package drive it.
type loopCycles struct {
	rows []*app.RebuildCycle
	err  error
}

func (c *loopCycles) OpenCycle(_ context.Context, releaseID string) (app.RebuildCycle, bool, error) {
	for _, r := range c.rows {
		if r.ReleaseID == releaseID && r.State == app.CycleOpen {
			return *r, true, c.err
		}
	}
	return app.RebuildCycle{}, false, c.err
}
func (c *loopCycles) CreateCycle(_ context.Context, cy app.RebuildCycle) (app.RebuildCycle, error) {
	cy.ID = int64(len(c.rows) + 1)
	c.rows = append(c.rows, &cy)
	return cy, nil
}
func (c *loopCycles) UpdateCycle(_ context.Context, cy app.RebuildCycle) error {
	for i, r := range c.rows {
		if r.ID == cy.ID {
			c.rows[i] = &cy
		}
	}
	return nil
}
func (c *loopCycles) LatestCycle(_ context.Context, releaseID string) (app.RebuildCycle, bool, error) {
	for i := len(c.rows) - 1; i >= 0; i-- {
		if c.rows[i].ReleaseID == releaseID {
			return *c.rows[i], true, c.err
		}
	}
	return app.RebuildCycle{}, false, c.err
}
func (c *loopCycles) CycleByID(_ context.Context, id int64) (app.RebuildCycle, bool, error) {
	for _, r := range c.rows {
		if r.ID == id {
			return *r, true, nil
		}
	}
	return app.RebuildCycle{}, false, nil
}

type loopRequests struct {
	rows  []*app.RebuildRequest
	holds map[string]app.RebuildHold
	err   error
}

func (m *loopRequests) CreateRequest(_ context.Context, r app.RebuildRequest) error {
	m.rows = append(m.rows, &r)
	return nil
}
func (m *loopRequests) RequestByIntent(_ context.Context, id string) (app.RebuildRequest, error) {
	for _, r := range m.rows {
		if r.IntentID == id {
			return *r, m.err
		}
	}
	if m.err != nil {
		return app.RebuildRequest{}, m.err
	}
	return app.RebuildRequest{}, app.ErrRebuildRequestNotFound
}
func (m *loopRequests) LatestRequest(_ context.Context, cycleID int64) (app.RebuildRequest, bool, error) {
	for i := len(m.rows) - 1; i >= 0; i-- {
		if m.rows[i].CycleID == cycleID {
			return *m.rows[i], true, nil
		}
	}
	return app.RebuildRequest{}, false, nil
}
func (m *loopRequests) ListRequests(_ context.Context, cycleID int64) ([]app.RebuildRequest, error) {
	out := []app.RebuildRequest{}
	for _, r := range m.rows {
		if r.CycleID == cycleID {
			out = append(out, *r)
		}
	}
	return out, nil
}
func (m *loopRequests) UpdateRequest(_ context.Context, r app.RebuildRequest) error {
	for i, old := range m.rows {
		if old.IntentID == r.IntentID {
			m.rows[i] = &r
		}
	}
	return nil
}
func (m *loopRequests) LastDeliveredAt(context.Context, string) (time.Time, bool, error) {
	return time.Time{}, false, nil
}
func (m *loopRequests) SilentRequests(context.Context, time.Time) ([]app.RebuildRequest, error) {
	return nil, nil
}
func (m *loopRequests) SaveHold(_ context.Context, h app.RebuildHold) error {
	if m.holds == nil {
		m.holds = map[string]app.RebuildHold{}
	}
	m.holds[h.ReleaseID] = h
	return nil
}
func (m *loopRequests) ClearHold(_ context.Context, releaseID string) error {
	delete(m.holds, releaseID)
	return nil
}
func (m *loopRequests) Hold(_ context.Context, releaseID string) (app.RebuildHold, bool, error) {
	h, ok := m.holds[releaseID]
	return h, ok, nil
}
func (m *loopRequests) SaveLastSBOM(context.Context, string, string, time.Time) error { return nil }
func (m *loopRequests) LastSBOM(context.Context, string) (string, error)              { return "", nil }
