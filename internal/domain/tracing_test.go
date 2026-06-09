package domain

import (
	"context"
	"testing"
)

func TestWithStageSpanNil(t *testing.T) {
	ctx := WithStageSpan(context.Background(), nil)
	if ctx == nil {
		t.Fatal("expected context")
	}
}

func TestStartStageWithoutInjector(t *testing.T) {
	_, end := StartStage(context.Background(), StageParse)
	end()
}

func TestStartStageWithInjector(t *testing.T) {
	called := false
	ctx := WithStageSpan(context.Background(), func(ctx context.Context, stage string) (context.Context, func()) {
		called = true
		if stage != StageCorrelate {
			t.Fatalf("stage = %q", stage)
		}
		return ctx, func() {}
	})
	_, end := StartStage(ctx, StageCorrelate)
	end()
	if !called {
		t.Fatal("expected span factory to run")
	}
}
