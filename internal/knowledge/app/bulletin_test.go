package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// memBulletins is an in-memory BulletinStore with the store's contract: one live bulletin per
// bulletin ID and per CVE, a history row per write, tombstones on removal.
type memBulletins struct {
	rows    map[string]domain.Bulletin
	removed map[string]bool
	hist    map[string][]app.BulletinChange
	err     error
}

func newMemBulletins() *memBulletins {
	return &memBulletins{rows: map[string]domain.Bulletin{}, removed: map[string]bool{}, hist: map[string][]app.BulletinChange{}}
}

func (m *memBulletins) clash(b domain.Bulletin) bool {
	for id, o := range m.rows {
		if id != b.ID && !m.removed[id] && (o.BulletinID == b.BulletinID || (b.CVE != "" && o.CVE == b.CVE)) {
			return true
		}
	}
	return false
}

func (m *memBulletins) ListBulletins(context.Context) ([]domain.Bulletin, error) {
	var out []domain.Bulletin
	for id, b := range m.rows {
		if !m.removed[id] {
			out = append(out, b)
		}
	}
	return out, m.err
}

func (m *memBulletins) GetBulletin(_ context.Context, id string) (domain.Bulletin, error) {
	b, ok := m.rows[id]
	if !ok || m.removed[id] {
		return domain.Bulletin{}, app.ErrBulletinNotFound
	}
	return b, m.err
}

func (m *memBulletins) CreateBulletin(_ context.Context, b domain.Bulletin) error {
	if m.clash(b) {
		return app.ErrBulletinConflict
	}
	m.rows[b.ID] = b
	m.hist[b.ID] = append(m.hist[b.ID], app.BulletinChange{At: b.CreatedAt, Actor: b.CreatedBy, Action: app.BulletinCreated, After: &b})
	return nil
}

func (m *memBulletins) UpdateBulletin(_ context.Context, before, after domain.Bulletin) error {
	if m.clash(after) {
		return app.ErrBulletinConflict
	}
	m.rows[after.ID] = after
	m.hist[after.ID] = append(m.hist[after.ID], app.BulletinChange{At: after.UpdatedAt, Actor: after.UpdatedBy, Action: app.BulletinUpdated, Before: &before, After: &after})
	return nil
}

func (m *memBulletins) RemoveBulletin(_ context.Context, b domain.Bulletin, actor string, at time.Time) error {
	m.removed[b.ID] = true
	m.hist[b.ID] = append(m.hist[b.ID], app.BulletinChange{At: at, Actor: actor, Action: app.BulletinRemoved, Before: &b})
	return nil
}

func (m *memBulletins) BulletinHistory(_ context.Context, id string) ([]app.BulletinChange, error) {
	return m.hist[id], m.err
}

type bulletinIDs struct{ n int }

func (g *bulletinIDs) NewID() string { g.n++; return "b" + string(rune('0'+g.n)) }

var admin = domain.BulletinEditor{Admin: true}

// EDR-PSIRT-01 revision 3: create, edit and remove a bulletin as an admin, with every change
// in its history; the report date defaults to the day of creation and is kept on an edit.
func TestBulletinService_Lifecycle(t *testing.T) {
	ctx := context.Background()
	store := newMemBulletins()
	clock := &movingClock{now: time.Date(2026, 11, 24, 9, 30, 0, 0, time.UTC)}
	svc := app.NewBulletinService(store, &bulletinIDs{}, clock)

	b, err := svc.Create(ctx, domain.BulletinInput{BulletinID: "BUL-0001", Title: "A flaw", CVE: "CVE-2026-1"}, admin, "key:a")
	if err != nil {
		t.Fatal(err)
	}
	if b.ID != "b1" || b.CreatedBy != "key:a" || !b.ReportDate.Equal(time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("created = %+v", b)
	}
	given := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	if r, err := svc.Create(ctx, domain.BulletinInput{BulletinID: "BUL-0002", Title: "Key compromise", ReportDate: given}, admin, "key:a"); err != nil || !r.ReportDate.Equal(given) {
		t.Errorf("a given report date is kept: %+v %v", r, err)
	}

	clock.now = clock.now.Add(time.Hour)
	up, err := svc.Update(ctx, "b1", domain.BulletinInput{BulletinID: "BUL-0001", Title: "A worse flaw", CVE: "CVE-2026-1", Note: "patched in 2.1"}, admin, "key:b")
	if err != nil || up.Title != "A worse flaw" || up.UpdatedBy != "key:b" || up.CreatedBy != "key:a" || !up.ReportDate.Equal(b.ReportDate) {
		t.Errorf("updated = %+v %v", up, err)
	}
	if list, _ := svc.List(ctx); len(list) != 2 {
		t.Errorf("list = %d", len(list))
	}
	if err := svc.Remove(ctx, "b1", admin, "key:c"); err != nil {
		t.Fatal(err)
	}
	if list, _ := svc.List(ctx); len(list) != 1 {
		t.Errorf("a removed bulletin leaves the list: %d", len(list))
	}
	h, err := svc.History(ctx, "b1")
	if err != nil || len(h) != 3 || h[0].Action != app.BulletinCreated || h[1].Action != app.BulletinUpdated || h[2].Action != app.BulletinRemoved || h[2].Actor != "key:c" {
		t.Errorf("history = %+v %v", h, err)
	}
}

// Refusals: not an admin, invalid input, an unknown id, a clash, an unwired node.
func TestBulletinService_Refusals(t *testing.T) {
	ctx := context.Background()
	store := newMemBulletins()
	svc := app.NewBulletinService(store, &bulletinIDs{}, &movingClock{now: time.Now()})
	user := domain.BulletinEditor{Products: []string{"p1"}}
	ok := domain.BulletinInput{BulletinID: "BUL-0001", Title: "t", CVE: "CVE-2026-1"}

	if _, err := svc.Create(ctx, ok, user, "k"); !errors.Is(err, app.ErrBulletinForbidden) {
		t.Errorf("create by a non-admin: %v", err)
	}
	if _, err := svc.Update(ctx, "b1", ok, user, "k"); !errors.Is(err, app.ErrBulletinForbidden) {
		t.Errorf("update by a non-admin: %v", err)
	}
	if err := svc.Remove(ctx, "b1", user, "k"); !errors.Is(err, app.ErrBulletinForbidden) {
		t.Errorf("remove by a non-admin: %v", err)
	}
	if _, err := svc.Create(ctx, domain.BulletinInput{Title: "t"}, admin, "k"); !errors.Is(err, domain.ErrBulletinInvalid) {
		t.Errorf("invalid create: %v", err)
	}
	if _, err := svc.Update(ctx, "b1", domain.BulletinInput{Title: "t"}, admin, "k"); !errors.Is(err, domain.ErrBulletinInvalid) {
		t.Errorf("invalid update: %v", err)
	}
	if _, err := svc.Update(ctx, "nope", ok, admin, "k"); !errors.Is(err, app.ErrBulletinNotFound) {
		t.Errorf("update unknown: %v", err)
	}
	if err := svc.Remove(ctx, "nope", admin, "k"); !errors.Is(err, app.ErrBulletinNotFound) {
		t.Errorf("remove unknown: %v", err)
	}
	if _, err := svc.Create(ctx, ok, admin, "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Create(ctx, domain.BulletinInput{BulletinID: "BUL-0002", Title: "t", CVE: "CVE-2026-1"}, admin, "k"); !errors.Is(err, app.ErrBulletinConflict) {
		t.Errorf("same CVE twice: %v", err)
	}
	if _, err := svc.Create(ctx, domain.BulletinInput{BulletinID: "BUL-0002", Title: "t"}, admin, "k"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Update(ctx, "b3", domain.BulletinInput{BulletinID: "BUL-0001", Title: "t"}, admin, "k"); !errors.Is(err, app.ErrBulletinConflict) {
		t.Errorf("update onto another's bulletin ID: %v", err)
	}

	var none *app.BulletinService
	unwired := app.NewBulletinService(nil, nil, nil)
	for name, err := range map[string]error{
		"list nil": func() error { _, e := none.List(ctx); return e }(),
		"list":     func() error { _, e := unwired.List(ctx); return e }(),
		"create":   func() error { _, e := unwired.Create(ctx, ok, admin, "k"); return e }(),
		"update":   func() error { _, e := unwired.Update(ctx, "x", ok, admin, "k"); return e }(),
		"remove":   unwired.Remove(ctx, "x", admin, "k"),
		"history":  func() error { _, e := unwired.History(ctx, "x"); return e }(),
	} {
		if !errors.Is(err, app.ErrBulletinsUnavailable) {
			t.Errorf("%s unwired: %v", name, err)
		}
	}
}
