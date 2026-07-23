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
	ac := domain.AssembledContext{
		Finding:   domain.FindingView{ID: "F1", CVE: "CVE-2024-0001", Components: []string{"pkg:golang/x@1.0.0"}},
		Faultline: domain.FaultlineView{ID: "FL1", Severity: "high", KEV: true},
	}
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
