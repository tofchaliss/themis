package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCatalogListCVEsNeedingCVSS(t *testing.T) {
	ctx := context.Background()

	okPool := &scriptedFakePool{}
	okPool.addQuery([][]any{{"CVE-1"}, {"CVE-2"}})
	ids, err := NewPostgresVulnerabilityCatalog(okPool).ListCVEsNeedingCVSS(ctx, 0, time.Now())
	if err != nil || len(ids) != 2 || ids[0] != "CVE-1" {
		t.Fatalf("ids=%v err=%v", ids, err)
	}

	errPool := storeFakePool{conn: storeFakeConn{queryErr: errors.New("query failed")}}
	if _, err := NewPostgresVulnerabilityCatalog(errPool).ListCVEsNeedingCVSS(ctx, 10, time.Now()); err == nil {
		t.Fatal("expected query error")
	}
}

func TestCatalogApplyCVSS(t *testing.T) {
	ctx := context.Background()

	// Both updates succeed (default scripted exec returns ok).
	if err := NewPostgresVulnerabilityCatalog(&scriptedFakePool{}).ApplyCVSS(ctx, "CVE-1", "high", 7.5, "v"); err != nil {
		t.Fatalf("happy path err=%v", err)
	}

	// Catalog update fails.
	failCatalog := &scriptedFakePool{}
	failCatalog.addExec(0, errors.New("catalog exec failed"))
	if err := NewPostgresVulnerabilityCatalog(failCatalog).ApplyCVSS(ctx, "CVE-1", "high", 7.5, "v"); err == nil {
		t.Fatal("expected catalog update error")
	}

	// Catalog update ok, risk_context propagation fails.
	failRC := &scriptedFakePool{}
	failRC.addExec(1, nil)
	failRC.addExec(0, errors.New("risk_context exec failed"))
	if err := NewPostgresVulnerabilityCatalog(failRC).ApplyCVSS(ctx, "CVE-1", "high", 7.5, "v"); err == nil {
		t.Fatal("expected risk_context propagation error")
	}
}

func TestCatalogMarkCVSSChecked(t *testing.T) {
	ctx := context.Background()
	if err := NewPostgresVulnerabilityCatalog(&scriptedFakePool{}).MarkCVSSChecked(ctx, "CVE-1"); err != nil {
		t.Fatalf("happy path err=%v", err)
	}
	errPool := storeFakePool{conn: storeFakeConn{execErr: errors.New("exec failed")}}
	if err := NewPostgresVulnerabilityCatalog(errPool).MarkCVSSChecked(ctx, "CVE-1"); err == nil {
		t.Fatal("expected exec error")
	}
}
