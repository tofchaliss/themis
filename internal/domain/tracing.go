package domain

import "context"

// Ingestion pipeline stage names used for distributed tracing.
const (
	StageWebhookReceipt = "webhook receipt"
	StageTrustGate      = "trust gate"
	StageParse          = "parse"
	StageCorrelate      = "correlate"
	StageEnrich         = "enrich"
	StageNotify         = "notify"
)

type stageSpanKey struct{}

// StageSpanFunc starts and ends an ingestion pipeline span for a stage.
type StageSpanFunc func(ctx context.Context, stage string) (context.Context, func())

// WithStageSpan injects a stage span factory into ctx (infrastructure layer).
func WithStageSpan(ctx context.Context, fn StageSpanFunc) context.Context {
	if fn == nil {
		return ctx
	}
	return context.WithValue(ctx, stageSpanKey{}, fn)
}

// StartStage runs the injected span factory when present.
func StartStage(ctx context.Context, stage string) (context.Context, func()) {
	if fn, ok := ctx.Value(stageSpanKey{}).(StageSpanFunc); ok && fn != nil {
		return fn(ctx, stage)
	}
	return ctx, func() {}
}
