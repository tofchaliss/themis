package metrics

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/themis-project/themis/internal/domain"
)

// Ensure trace.Tracer stays referenced for OTel span creation.
var _ trace.Tracer = otel.Tracer(tracerName)

const tracerName = "github.com/themis-project/themis"

// StageSpanFunc starts an OpenTelemetry span for an ingestion pipeline stage.
func StageSpanFunc(ctx context.Context, stage string) (context.Context, func()) {
	ctx, span := otel.Tracer(tracerName).Start(ctx, stage, trace.WithAttributes(
		attribute.String("themis.pipeline.stage", stage),
	))
	return ctx, func() { span.End() }
}

// InjectStageSpan returns ctx with OTel stage span injection enabled.
func InjectStageSpan(ctx context.Context) context.Context {
	return domain.WithStageSpan(ctx, StageSpanFunc)
}
