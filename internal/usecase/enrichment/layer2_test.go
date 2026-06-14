package enrichment_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

func TestBlastRadius_NoGraph(t *testing.T) {
	got := enrichment.ComputeBlastRadiusScore(0)
	if got != domain.RiskScoreBlastRadiusMin {
		t.Fatalf("score = %v, want 1.0", got)
	}
}

func TestBlastRadius_OneCustomer(t *testing.T) {
	got := enrichment.ComputeBlastRadiusScore(1)
	if got != 1.0 {
		t.Fatalf("score = %v, want 1.0", got)
	}
}

func TestBlastRadius_FiveCustomers(t *testing.T) {
	got := enrichment.ComputeBlastRadiusScore(5)
	if got != 1.4 {
		t.Fatalf("score = %v, want 1.4", got)
	}
}

func TestBlastRadius_TenCustomers(t *testing.T) {
	got := enrichment.ComputeBlastRadiusScore(10)
	if got != 2.0 {
		t.Fatalf("score = %v, want 2.0", got)
	}
}

func TestBlastRadius_FifteenCustomers(t *testing.T) {
	got := enrichment.ComputeBlastRadiusScore(15)
	if got != 2.0 {
		t.Fatalf("score = %v, want 2.0", got)
	}
}

func TestBlastRadius_SharedCustomerDedup(t *testing.T) {
	// Score uses unique customer count; dedup happens in graph query.
	got := enrichment.ComputeBlastRadiusScore(1)
	if got != 1.0 {
		t.Fatalf("score = %v, want 1.0", got)
	}
}

func TestBlastRadius_OrphanMicroservice(t *testing.T) {
	got := enrichment.ComputeBlastRadiusScore(0)
	if got != 1.0 {
		t.Fatalf("score = %v, want 1.0", got)
	}
}

func TestBlastRadius_DepthCap(t *testing.T) {
	if domain.BlastRadiusTraversalDepth != 7 {
		t.Fatalf("BlastRadiusTraversalDepth = %d, want 7", domain.BlastRadiusTraversalDepth)
	}
}

func TestBlastRadius_Monotone(t *testing.T) {
	prev := enrichment.ComputeBlastRadiusScore(1)
	for n := 2; n <= 15; n++ {
		next := enrichment.ComputeBlastRadiusScore(n)
		if next < prev {
			t.Fatalf("score decreased from %v to %v at n=%d", prev, next, n)
		}
		prev = next
	}
}

func TestNoOpLayer2(t *testing.T) {
	var layer enrichment.NoOpLayer2
	result, err := layer.Enrich(t.Context(), domain.EnrichmentFinding{})
	if err != nil || result.Score != 1.0 {
		t.Fatalf("NoOpLayer2() = %+v, %v", result, err)
	}
}

type layer2Stub struct {
	result domain.BlastRadiusResult
	err    error
}

func (s layer2Stub) Enrich(context.Context, domain.EnrichmentFinding) (domain.BlastRadiusResult, error) {
	return s.result, s.err
}

type teamNotifyStub struct {
	events []domain.NotificationEvent
}

func (s *teamNotifyStub) NotifyTeam(_ context.Context, event domain.NotificationEvent) error {
	s.events = append(s.events, event)
	return nil
}

func TestApplyFindingLayer2AndTeamNotify(t *testing.T) {
	repo := &layer3Repo{}
	notify := &teamNotifyStub{}
	handler := &enrichment.Handler{
		Repo: repo,
		Layer2: layer2Stub{result: domain.BlastRadiusResult{
			Score:       1.4,
			CustomerIDs: []string{"cust-1", "cust-2"},
		}},
		TeamNotify: notify,
	}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err != nil {
		t.Fatal(err)
	}
	if len(notify.events) != 2 {
		t.Fatalf("notify events = %d, want 2", len(notify.events))
	}
}

func TestApplyFindingLayer2Error(t *testing.T) {
	repo := &layer3Repo{}
	handler := &enrichment.Handler{Repo: repo, Layer2: layer2Stub{err: context.Canceled}}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err == nil {
		t.Fatal("expected layer2 error")
	}
}

func TestHandlerUsesCustomLayer2(t *testing.T) {
	repo := &layer3Repo{}
	handler := &enrichment.Handler{Repo: repo, Layer2: layer2Stub{result: domain.BlastRadiusResult{Score: 2.0}}}
	if err := handler.ApplyVEX(context.Background(), "sbom-1"); err != nil {
		t.Fatal(err)
	}
}
