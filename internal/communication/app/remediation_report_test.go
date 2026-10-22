package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/communication/app"
)

type repReader struct {
	rep     app.RemediationReport
	err     error
	product string
}

func (r *repReader) RemediationMetrics(_ context.Context, product string) (app.RemediationReport, error) {
	r.product = product
	return r.rep, r.err
}

type repRenderer struct{ format string }

func (r *repRenderer) RenderRemediation(_ app.RemediationReport, format string) ([]byte, string, error) {
	r.format = format
	return []byte(format), "text/" + format, nil
}

func TestRemediationReports_Render(t *testing.T) {
	ctx := context.Background()
	reader, renderer := &repReader{}, &repRenderer{}
	reps := app.NewRemediationReports(reader, renderer)
	if b, ct, err := reps.Render(ctx, "Gateway", ""); err != nil || string(b) != "markdown" || ct != "text/markdown" || reader.product != "Gateway" {
		t.Fatalf("default = %s %s %v", b, ct, err)
	}
	if b, _, err := reps.Render(ctx, "", " JSON "); err != nil || string(b) != "json" {
		t.Fatalf("json = %s %v", b, err)
	}
	if _, _, err := reps.Render(ctx, "", "pdf"); !errors.Is(err, app.ErrUnknownReportFormat) {
		t.Fatalf("pdf = %v", err)
	}
	reader.err = errors.New("governance down")
	if _, _, err := reps.Render(ctx, "", "json"); err == nil {
		t.Fatal("read error swallowed")
	}
}
