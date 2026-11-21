//go:build integration

package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/registry/adapters/store"
	"github.com/themis-project/themis/internal/registry/domain"
)

// TestSecurityRequirementsAppendOnly records two changes at one level and reads them newest
// first; the earlier record stays (EDR-SCORING-01 S3).
func TestSecurityRequirementsAppendOnly(t *testing.T) {
	ctx := context.Background()
	s := store.New(newPool(t))
	_, _, rel := seed(t, s)
	at := time.Unix(1_700_000_000, 0).UTC()
	first, err := domain.NewRequirementRecord(domain.TagRelease, string(rel), "H", "", "", "card data", "ops", "ci", at)
	must(t, err)
	second, err := domain.NewRequirementRecord(domain.TagRelease, string(rel), "H", "M", "H", "uptime", "ops", "", at.Add(time.Hour))
	must(t, err)
	must(t, s.AppendRequirement(ctx, first))
	must(t, s.AppendRequirement(ctx, second))
	hist, err := s.RequirementHistory(ctx, domain.TagRelease, string(rel))
	must(t, err)
	if len(hist) != 2 || hist[0].Reason != "uptime" || hist[1].Via != "ci" || hist[1].Requirements.IR != "X" || !hist[0].At.Equal(second.At) {
		t.Fatalf("history: %+v", hist)
	}
	if none, err := s.RequirementHistory(ctx, domain.TagProduct, "prod-1"); err != nil || len(none) != 0 {
		t.Errorf("product: %+v %v", none, err)
	}
}
