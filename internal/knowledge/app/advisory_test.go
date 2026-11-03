package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

type advisoryByID struct {
	asked string
	cards []domain.Faultline
	err   error
}

func (a *advisoryByID) FaultlinesByAdvisory(_ context.Context, id string) ([]domain.Faultline, error) {
	a.asked = id
	return a.cards, a.err
}

// EDR-INCIDENT-01 D2: the id is normalised before the store sees it; a blank id and an unwired
// lister are refused, never an empty answer; a store failure passes through.
func TestReadService_ByAdvisory(t *testing.T) {
	ctx := context.Background()
	read := app.NewReadService(nil, nil)
	if _, err := read.ByAdvisory(ctx, "RHSA-2026:0001"); !errors.Is(err, app.ErrAdvisoryUnavailable) {
		t.Errorf("unwired: %v", err)
	}
	lister := &advisoryByID{}
	read = read.WithAdvisory(lister)
	if _, err := read.ByAdvisory(ctx, "  "); !errors.Is(err, app.ErrInvalidAdvisory) {
		t.Errorf("blank: %v", err)
	}
	if got, err := read.ByAdvisory(ctx, " rhsa-2026:0001 "); err != nil || got != nil || lister.asked != "RHSA-2026:0001" {
		t.Errorf("normalised ask = %q, got %v err %v", lister.asked, got, err)
	}
	boom := errors.New("db down")
	lister.err = boom
	if _, err := read.ByAdvisory(ctx, "RHSA-2026:0001"); !errors.Is(err, boom) {
		t.Errorf("store failure: %v", err)
	}
}
