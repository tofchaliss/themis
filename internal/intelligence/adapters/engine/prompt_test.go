package engine

import (
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

func TestPromptRendererHappy(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	ac := domain.AssembledContext{Projection: domain.FindingAssessment{Finding: domain.FindingView{ID: "F1", CVE: "CVE-2024-0001", Components: []string{"pkg:golang/x@1.0.0"}}, Knowledge: domain.FaultlineView{ID: "FL1", Severity: "high", KEV: true}}}
	out, err := r.Render("recommend_position", ac)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{"F1", "CVE-2024-0001", "pkg:golang/x@1.0.0", "FL1", "affected", "not_affected"} {
		if !strings.Contains(out, want) {
			t.Errorf("prompt missing %q\n%s", want, out)
		}
	}
}

func TestPromptRendererSemanticPrecedents(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	ac := domain.AssembledContext{Projection: domain.FindingAssessment{Finding: domain.FindingView{ID: "F1", CVE: "CVE-2026-1", Components: []string{"pkg:golang/openssl"}}, Knowledge: domain.FaultlineView{ID: "FL1", Severity: "high"}}, Precedents: []domain.PrecedentPosition{
		{ReleaseID: "R2", SourceCVE: "CVE-2025-9", Component: "pkg:golang/openssl", Stance: "not_affected", Rationale: "unreachable", Score: 0.87},
	}}
	out, err := r.Render("recommend_position", ac)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	// A semantic precedent renders its release, the similar CVE, the component, the similarity
	// score, and the stance + rationale — so the LLM can weigh a different-CVE precedent.
	for _, want := range []string{"R2", "CVE-2025-9", "pkg:golang/openssl", "0.87", "not_affected", "unreachable"} {
		if !strings.Contains(out, want) {
			t.Errorf("prompt missing precedent detail %q\n%s", want, out)
		}
	}
}

func TestPromptRendererUnknownCapability(t *testing.T) {
	r, _ := NewPromptRenderer()
	if _, err := r.Render("nope", domain.AssembledContext{}); err == nil {
		t.Error("unknown capability should error")
	}
}

func TestNewRendererParseError(t *testing.T) {
	if _, err := newRenderer(map[string]string{"bad": "{{ .Finding.ID "}); err == nil {
		t.Error("malformed template should fail to parse")
	}
}

func TestRenderExecuteError(t *testing.T) {
	r, err := newRenderer(map[string]string{"badfield": "{{ .Nonexistent }}"})
	if err != nil {
		t.Fatalf("newRenderer: %v", err)
	}
	if _, err := r.Render("badfield", domain.AssembledContext{}); err == nil {
		t.Error("template referencing a missing field should fail at execute")
	}
}
