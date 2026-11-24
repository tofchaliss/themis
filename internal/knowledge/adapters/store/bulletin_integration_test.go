//go:build integration

package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

func bulletin(id, bid, cve string, day int, at time.Time) domain.Bulletin {
	return domain.Bulletin{
		ID: id, BulletinInput: domain.BulletinInput{BulletinID: bid, Title: "title " + bid, BulletinURL: "https://example.com/" + bid,
			Note: "n", CVE: cve, ReportDate: time.Date(2026, 11, day, 0, 0, 0, 0, time.UTC)},
		CreatedAt: at, CreatedBy: "key:a", UpdatedAt: at, UpdatedBy: "key:a",
	}
}

// EDR-PSIRT-01 revision 3: the register round-trips, lists newest report date first, keeps one
// live bulletin per bulletin ID and per CVE, tombstones a removal (which frees both), and keeps
// every change in the history with the bulletin before and after.
func TestBulletinRegister(t *testing.T) {
	pool := newPool(t)
	ctx := context.Background()
	st := store.New(pool)
	at := time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)

	b1 := bulletin("b1", "BUL-0001", "CVE-2026-1", 10, at)
	b2 := bulletin("b2", "BUL-0002", "", 20, at.Add(time.Minute))
	for _, b := range []domain.Bulletin{b1, b2} {
		if err := st.CreateBulletin(ctx, b); err != nil {
			t.Fatal(err)
		}
	}
	list, err := st.ListBulletins(ctx)
	if err != nil || len(list) != 2 || list[0].ID != "b2" || list[1].ID != "b1" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	got, err := st.GetBulletin(ctx, "b1")
	if err != nil || got.BulletinInput != b1.BulletinInput || !got.CreatedAt.Equal(at) || got.CreatedBy != "key:a" {
		t.Errorf("get = %+v, %v", got, err)
	}

	for name, b := range map[string]domain.Bulletin{
		"same bulletin ID": bulletin("b3", "BUL-0001", "", 1, at),
		"same CVE":         bulletin("b3", "BUL-0003", "CVE-2026-1", 1, at),
	} {
		if err := st.CreateBulletin(ctx, b); !errors.Is(err, app.ErrBulletinConflict) {
			t.Errorf("%s: %v", name, err)
		}
	}

	after := b1
	after.Title, after.UpdatedBy, after.UpdatedAt = "edited", "key:b", at.Add(time.Hour)
	if err := st.UpdateBulletin(ctx, b1, after); err != nil {
		t.Fatal(err)
	}
	clash := b2
	clash.CVE = "CVE-2026-1"
	if err := st.UpdateBulletin(ctx, b2, clash); !errors.Is(err, app.ErrBulletinConflict) {
		t.Errorf("update onto a live CVE: %v", err)
	}
	if err := st.RemoveBulletin(ctx, after, "key:c", at.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetBulletin(ctx, "b1"); !errors.Is(err, app.ErrBulletinNotFound) {
		t.Errorf("removed: %v", err)
	}
	if err := st.RemoveBulletin(ctx, after, "key:c", at); !errors.Is(err, app.ErrBulletinNotFound) {
		t.Errorf("removed twice: %v", err)
	}
	if err := st.UpdateBulletin(ctx, after, after); !errors.Is(err, app.ErrBulletinNotFound) {
		t.Errorf("update a removed one: %v", err)
	}
	// The removal frees the bulletin ID and the CVE.
	if err := st.CreateBulletin(ctx, bulletin("b4", "BUL-0001", "CVE-2026-1", 1, at)); err != nil {
		t.Errorf("reuse after removal: %v", err)
	}

	h, err := st.BulletinHistory(ctx, "b1")
	if err != nil || len(h) != 3 {
		t.Fatalf("history = %+v, %v", h, err)
	}
	if h[0].Action != app.BulletinCreated || h[0].Before != nil || h[0].After == nil || h[0].After.Title != "title BUL-0001" ||
		h[1].Action != app.BulletinUpdated || h[1].Before.Title != "title BUL-0001" || h[1].After.Title != "edited" || h[1].Actor != "key:b" ||
		h[2].Action != app.BulletinRemoved || h[2].After != nil || h[2].Actor != "key:c" || !h[2].At.Equal(at.Add(2*time.Hour)) {
		t.Errorf("history = %+v", h)
	}

	// A history row the store cannot read surfaces; so does a failed query.
	if _, err := pool.Exec(ctx, `UPDATE psirt_bulletin_history SET before_json = '"x"' WHERE bulletin = 'b1' AND action = 'updated'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.BulletinHistory(ctx, "b1"); err == nil {
		t.Error("a malformed before_json must surface")
	}
	if _, err := pool.Exec(ctx, `UPDATE psirt_bulletin_history SET before_json = NULL, after_json = '"x"' WHERE bulletin = 'b1' AND action = 'updated'`); err != nil {
		t.Fatal(err)
	}
	if _, err := st.BulletinHistory(ctx, "b1"); err == nil {
		t.Error("a malformed after_json must surface")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := st.ListBulletins(cancelled); err == nil {
		t.Error("list on a cancelled context")
	}
	if _, err := st.BulletinHistory(cancelled, "b1"); err == nil {
		t.Error("history on a cancelled context")
	}
	if err := st.CreateBulletin(cancelled, bulletin("b5", "BUL-0005", "", 1, at)); err == nil {
		t.Error("create on a cancelled context")
	}
}
