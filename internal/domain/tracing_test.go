package domain_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestStartStageWithoutInjection(t *testing.T) {
	ctx, end := domain.StartStage(context.Background(), domain.StageParse)
	end()
	if ctx == nil {
		t.Fatal("expected context")
	}
}

func TestWithStageSpanInvokesFactory(t *testing.T) {
	called := false
	ctx := domain.WithStageSpan(context.Background(), func(ctx context.Context, stage string) (context.Context, func()) {
		called = true
		if stage != domain.StageTrustGate {
			t.Fatalf("stage = %q", stage)
		}
		return ctx, func() {}
	})
	_, end := domain.StartStage(ctx, domain.StageTrustGate)
	end()
	if !called {
		t.Fatal("expected stage span factory to run")
	}
}
