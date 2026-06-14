package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPostgresSystemStatusRepository(t *testing.T) {
	ctx := context.Background()
	pool := &scriptedFakePool{}
	pool.addQueryRow(100, 40)
	pool.addQueryRow(50, 20)
	pool.addQuery([][]any{{"high", 10}, {"low", 5}})
	pool.addQuery([][]any{{"detected", 30}, {"open", 20}})
	pool.addQuery([][]any{{"lodash", "4.17.21", "pkg:npm/lodash@4.17.21", "webapp", 3, 3, 9.8, "CVE-2021-1"}})

	status, err := NewPostgresSystemStatusRepository(pool).GetSystemStatus(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if status.Components.TotalRegistered != 100 || status.Components.WithVulnerabilities != 40 {
		t.Fatalf("components=%+v", status.Components)
	}
	if status.Components.Clean != 60 {
		t.Fatalf("clean=%d", status.Components.Clean)
	}
	if status.Vulnerabilities.TotalFindings != 50 || status.Vulnerabilities.UniqueCVEs != 20 {
		t.Fatalf("vulnerabilities=%+v", status.Vulnerabilities)
	}
	if status.Vulnerabilities.BySeverity["high"] != 10 || status.Vulnerabilities.ByState["detected"] != 30 {
		t.Fatalf("breakdown severity=%+v state=%+v", status.Vulnerabilities.BySeverity, status.Vulnerabilities.ByState)
	}
	if len(status.TopComponents) != 1 || status.TopComponents[0].HighestSeverity != "high" {
		t.Fatalf("top=%+v", status.TopComponents)
	}

	cappedPool := &scriptedFakePool{}
	cappedPool.addQueryRow(1, 1)
	cappedPool.addQueryRow(1, 1)
	cappedPool.addQuery([][]any{{"high", 1}})
	cappedPool.addQuery([][]any{{"detected", 1}})
	cappedPool.addQuery([][]any{{"pkg", "1.0.0", "pkg:npm/pkg@1", "prod", 1, 3, 7.0, "CVE-1"}})
	capped, err := NewPostgresSystemStatusRepository(cappedPool).GetSystemStatus(ctx, 100)
	if err != nil || capped.AsOf.IsZero() {
		t.Fatalf("status=%+v err=%v", capped, err)
	}

	negativeCleanPool := &scriptedFakePool{}
	negativeCleanPool.addQueryRow(10, 20)
	negativeCleanPool.addQueryRow(0, 0)
	negativeCleanPool.addQuery(nil)
	negativeCleanPool.addQuery(nil)
	negativeCleanPool.addQuery(nil)
	negativeStatus, err := NewPostgresSystemStatusRepository(negativeCleanPool).GetSystemStatus(ctx, 5)
	if err != nil || negativeStatus.Components.Clean != 0 {
		t.Fatalf("clean=%d err=%v", negativeStatus.Components.Clean, err)
	}

	queryErr := storeFakePool{conn: storeFakeConn{queryErr: errors.New("query failed")}}
	if _, err := NewPostgresSystemStatusRepository(queryErr).GetSystemStatus(ctx, 10); err == nil {
		t.Fatal("expected system status error")
	}
}

func TestPostgresSystemStatusTopComponentUnknownSeverity(t *testing.T) {
	pool := &scriptedFakePool{}
	pool.addQueryRow(1, 1)
	pool.addQueryRow(1, 1)
	pool.addQuery([][]any{{"unknown", 1}})
	pool.addQuery([][]any{{"detected", 1}})
	pool.addQuery([][]any{{"pkg", "1.0.0", "pkg:npm/pkg@1", "prod", 1, 0, 0.0, "CVE-1"}})
	status, err := NewPostgresSystemStatusRepository(pool).GetSystemStatus(context.Background(), 10)
	if err != nil || status.TopComponents[0].HighestSeverity != "unknown" {
		t.Fatalf("top=%+v err=%v", status.TopComponents, err)
	}
}

func TestPostgresSystemStatusRepositoryConstructors(t *testing.T) {
	if NewPostgresSystemStatusRepository(nil) == nil {
		t.Fatal("expected system status repository")
	}
	_ = time.Now()
}
