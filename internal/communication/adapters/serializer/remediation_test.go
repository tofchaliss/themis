package serializer_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
)

func sampleReport() app.RemediationReport {
	return app.RemediationReport{
		GeneratedAt: time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC),
		Estate: app.RemediationMetrics{Open: 5, OpenByAge: map[string]map[string]int{"0-7": {"critical": 2}, "over-90": {"unknown": 1}},
			SLAApplicable: 4, WithinSLA: 3, BreachedNow: 1, WithinSLAShare: 0.75,
			TimeToDecision: app.MeanDays{MeanDays: 2.5, Count: 4}, TimeToResolution: app.MeanDays{MeanDays: 12, Count: 1}},
		Products:     []app.RemediationMetrics{{Scope: "Gateway", Open: 2}},
		Unattributed: 3,
	}
}

func TestRenderRemediation(t *testing.T) {
	r := serializer.RemediationRenderer{}
	md, ct, err := r.RenderRemediation(sampleReport(), "markdown")
	if err != nil || !strings.HasPrefix(ct, "text/markdown") {
		t.Fatalf("markdown = %s %v", ct, err)
	}
	text := string(md)
	for _, want := range []string{"# Remediation metrics", "2026-10-22 09:00 UTC", "## Estate", "Open findings: 5",
		"Within SLA: 3 of 4 (75%); breached now: 1", "Mean time to decision: 2.5 days (over 4)",
		"Mean time to remediation (no longer in an evaluated SBOM, then decided by a person): no sample yet",
		"Mean time to resolution (resolved by a person): 12.0 days (over 1)", "| 0-7 | 2 | 0 | 0 | 0 | 0 |", "| over-90 | 0 | 0 | 0 | 0 | 1 |",
		"## Product: Gateway", "Within SLA: no running SLA clock", "3 finding(s) belong to releases"} {
		if !strings.Contains(text, want) {
			t.Errorf("markdown lacks %q:\n%s", want, text)
		}
	}
	rep := sampleReport()
	rep.ProductsUnavailable, rep.Unattributed = true, 0
	md, _, _ = r.RenderRemediation(rep, "markdown")
	if !strings.Contains(string(md), "Per-product figures are not available") || strings.Contains(string(md), "belong to releases") {
		t.Fatalf("unavailable:\n%s", md)
	}
	js, ct, err := r.RenderRemediation(sampleReport(), "json")
	var back app.RemediationReport
	if err != nil || ct != "application/json" || json.Unmarshal(js, &back) != nil || back.Estate.Open != 5 {
		t.Fatalf("json = %s %v", js, err)
	}
	if _, _, err := r.RenderRemediation(sampleReport(), "pdf"); !errors.Is(err, app.ErrUnknownReportFormat) {
		t.Fatalf("pdf = %v", err)
	}
}
