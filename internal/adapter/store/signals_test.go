package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/themis-project/themis/internal/domain"
)

type stubThreatSignalStore struct {
	epss    *float64
	epssErr error
	kev     bool
	kevErr  error
}

func (s stubThreatSignalStore) UpsertEPSS(context.Context, []domain.EPSSSignal) error { return nil }
func (s stubThreatSignalStore) UpsertKEV(context.Context, []domain.KEVSignal) error   { return nil }
func (s stubThreatSignalStore) ListKEVCVEIDs(context.Context) ([]string, error)       { return nil, nil }
func (s stubThreatSignalStore) MarkStale(context.Context, bool) error                 { return nil }
func (s stubThreatSignalStore) SignalsStale(context.Context) (bool, error)            { return false, nil }
func (s stubThreatSignalStore) GetEPSSForCVE(context.Context, string) (*float64, error) {
	return s.epss, s.epssErr
}
func (s stubThreatSignalStore) IsKEVListed(context.Context, string) (bool, error) {
	return s.kev, s.kevErr
}
func (s stubThreatSignalStore) CountEPSSRows(context.Context) (int, error)       { return 0, nil }
func (s stubThreatSignalStore) LastSuccessfulFetch(context.Context) (time.Time, error) {
	return time.Time{}, nil
}

type stubExploitStore struct {
	has    bool
	hasErr error
}

func (s stubExploitStore) UpsertExploits(context.Context, []domain.ExploitRecord) error { return nil }
func (s stubExploitStore) HasPublicExploit(context.Context, string) (bool, error) {
	return s.has, s.hasErr
}
func (s stubExploitStore) CountExploits(context.Context) (int, error) { return 0, nil }

func TestCombinedSignalReader(t *testing.T) {
	ctx := context.Background()
	score := 0.75
	reader := CombinedSignalReader{
		Threat: stubThreatSignalStore{epss: &score, kev: true},
		Exploit: stubExploitStore{has: true},
	}
	gotEPSS, err := reader.GetEPSSForCVE(ctx, "CVE-1")
	if err != nil || gotEPSS == nil || *gotEPSS != 0.75 {
		t.Fatalf("epss=%v err=%v", gotEPSS, err)
	}
	kev, err := reader.IsKEVListed(ctx, "CVE-1")
	if err != nil || !kev {
		t.Fatalf("kev=%v err=%v", kev, err)
	}
	hasExploit, err := reader.HasPublicExploit(ctx, "CVE-1")
	if err != nil || !hasExploit {
		t.Fatalf("has=%v err=%v", hasExploit, err)
	}

	nilReader := CombinedSignalReader{}
	if epss, err := nilReader.GetEPSSForCVE(ctx, "CVE-1"); epss != nil || err != nil {
		t.Fatalf("expected nil epss, got=%v err=%v", epss, err)
	}
	if kev, err := nilReader.IsKEVListed(ctx, "CVE-1"); kev || err != nil {
		t.Fatalf("expected false kev, got=%v err=%v", kev, err)
	}
	if has, err := nilReader.HasPublicExploit(ctx, "CVE-1"); has || err != nil {
		t.Fatalf("expected false exploit, got=%v err=%v", has, err)
	}
}

func TestPostgresExploitStore(t *testing.T) {
	ctx := context.Background()
	published := time.Now().UTC()
	pool := storeFakePool{conn: storeFakeConn{}}
	store := NewPostgresExploitStore(pool)
	if err := store.UpsertExploits(ctx, []domain.ExploitRecord{{
		EDBID: "EDB-1", CVEID: "CVE-1", ExploitType: "remote", PublishedDate: &published, Title: "PoC",
	}}); err != nil {
		t.Fatal(err)
	}

	boolPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{true}}},
	}}
	has, err := NewPostgresExploitStore(boolPool).HasPublicExploit(ctx, "CVE-1")
	if err != nil || !has {
		t.Fatalf("has=%v err=%v", has, err)
	}

	countPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{5}}},
	}}
	count, err := NewPostgresExploitStore(countPool).CountExploits(ctx)
	if err != nil || count != 5 {
		t.Fatalf("count=%d err=%v", count, err)
	}

	execErrPool := storeFakePool{conn: storeFakeConn{execErr: errors.New("exec failed")}}
	if err := NewPostgresExploitStore(execErrPool).UpsertExploits(ctx, []domain.ExploitRecord{{EDBID: "EDB-2"}}); err == nil {
		t.Fatal("expected upsert error")
	}
}

func TestPostgresThreatSignalStore(t *testing.T) {
	ctx := context.Background()
	fetchedAt := time.Now().UTC()

	upsertPool := storeFakePool{conn: storeFakeConn{}}
	if err := NewPostgresThreatSignalStore(upsertPool).UpsertEPSS(ctx, []domain.EPSSSignal{{
		CVEID: "CVE-1", Score: 0.5, FetchedAt: fetchedAt,
	}}); err != nil {
		t.Fatal(err)
	}
	if err := NewPostgresThreatSignalStore(upsertPool).UpsertEPSS(ctx, nil); err != nil {
		t.Fatal(err)
	}

	kevPool := &scriptedFakePool{}
	kevPool.addQuery([][]any{{"CVE-OLD"}})
	kevPool.addExec(1, nil)
	kevPool.addExec(1, nil)
	if err := NewPostgresThreatSignalStore(kevPool).UpsertKEV(ctx, []domain.KEVSignal{{
		CVEID: "CVE-NEW", FetchedAt: fetchedAt,
	}}); err != nil {
		t.Fatal(err)
	}

	listRows := &fakeRows{data: [][]any{{"CVE-1"}, {"CVE-2"}}}
	listPool := storeFakePool{conn: storeFakeConn{}, rows: listRows}
	ids, err := NewPostgresThreatSignalStore(listPool).ListKEVCVEIDs(ctx)
	if err != nil || len(ids) != 2 {
		t.Fatalf("ids=%v err=%v", ids, err)
	}

	markPool := storeFakePool{conn: storeFakeConn{}}
	if err := NewPostgresThreatSignalStore(markPool).MarkStale(ctx, true); err != nil {
		t.Fatal(err)
	}

	stalePool := &scriptedFakePool{}
	stalePool.addQueryRow(true)
	stale, err := NewPostgresThreatSignalStore(stalePool).SignalsStale(ctx)
	if err != nil || !stale {
		t.Fatalf("stale=%v err=%v", stale, err)
	}

	recentPool := &scriptedFakePool{}
	recentPool.addQueryRow(false)
	recentPool.addQueryRow(time.Now().UTC())
	staleRecent, err := NewPostgresThreatSignalStore(recentPool).SignalsStale(ctx)
	if err != nil || staleRecent {
		t.Fatalf("stale=%v err=%v", staleRecent, err)
	}

	oldFetch := time.Now().UTC().Add(-30 * time.Hour)
	oldPool := &scriptedFakePool{}
	oldPool.addQueryRow(false)
	oldPool.addQueryRow(oldFetch)
	staleOld, err := NewPostgresThreatSignalStore(oldPool).SignalsStale(ctx)
	if err != nil || !staleOld {
		t.Fatalf("stale=%v err=%v", staleOld, err)
	}

	epssScore := 0.33
	epssPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{epssScore}}},
	}}
	gotEPSS, err := NewPostgresThreatSignalStore(epssPool).GetEPSSForCVE(ctx, "CVE-1")
	if err != nil || gotEPSS == nil || *gotEPSS != 0.33 {
		t.Fatalf("epss=%v err=%v", gotEPSS, err)
	}

	noEPSSPool := storeFakePool{conn: storeFakeConn{queryErr: pgx.ErrNoRows}}
	if epss, err := NewPostgresThreatSignalStore(noEPSSPool).GetEPSSForCVE(ctx, "missing"); epss != nil || err != nil {
		t.Fatalf("epss=%v err=%v", epss, err)
	}

	kevListedPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{true}}},
	}}
	listed, err := NewPostgresThreatSignalStore(kevListedPool).IsKEVListed(ctx, "CVE-1")
	if err != nil || !listed {
		t.Fatalf("listed=%v err=%v", listed, err)
	}

	countEPSSPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{100}}},
	}}
	epssCount, err := NewPostgresThreatSignalStore(countEPSSPool).CountEPSSRows(ctx)
	if err != nil || epssCount != 100 {
		t.Fatalf("count=%d err=%v", epssCount, err)
	}

	lastPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{fetchedAt}}},
	}}
	last, err := NewPostgresThreatSignalStore(lastPool).LastSuccessfulFetch(ctx)
	if err != nil || !last.Equal(fetchedAt) {
		t.Fatalf("last=%v err=%v", last, err)
	}

	epochPool := seqFakePool{conn: &seqFakeConn{
		rows: []pgx.Row{scanRow{values: []any{time.Unix(0, 0).UTC()}}},
	}}
	emptyLast, err := NewPostgresThreatSignalStore(epochPool).LastSuccessfulFetch(ctx)
	if err != nil || !emptyLast.IsZero() {
		t.Fatalf("last=%v err=%v", emptyLast, err)
	}
}
