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

// The plan template must carry the PRE-COMPUTED grouping into the prompt. If it did not, the
// model would be asked to rediscover from raw rows that nine CVEs share one upgrade — slow,
// expensive, and non-deterministic, when it is a GROUP BY (EDR-TRUST-01 T10).
func TestRenderPlanRemediation(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	rpm := func(name, source, version string) domain.PostureComponent {
		return domain.PostureComponent{
			PURL: "pkg:rpm/rocky/" + name + "@" + version, Name: name,
			Version: version, Ecosystem: "rpm", Source: source,
		}
	}
	ac := domain.AssembledContext{Release: domain.ReleasePosture{
		ReleaseID: "rel-1",
		Entries: []domain.PostureEntry{
			{FindingID: "f1", CVE: "CVE-2007-4559", ResidualPriority: 97,
				Components: []domain.PostureComponent{rpm("python3-ply", "python-ply", "3.9-9.el8")}},
			{FindingID: "f2", CVE: "CVE-2021-3177", ResidualPriority: 96,
				Components: []domain.PostureComponent{rpm("python3-ply", "python-ply", "3.9-9.el8")}},
		},
	}}

	got, err := r.Render("plan_remediation", ac)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for _, want := range []string{
		"rel-1",               // the subject
		"upgrade python-ply",  // named by the SOURCE package — the name a fix is published under
		"closes 2 finding(s)", // the collapse the model must not have to rediscover
		"CVE-2007-4559",       // worst-first within the action
		"3.9-9.el8",           // what is installed
	} {
		if !strings.Contains(got, want) {
			t.Errorf("prompt missing %q:\n%s", want, got)
		}
	}
	// It must not invite a fix version: the listed versions are INSTALLED, and a model told
	// otherwise would confidently recommend upgrading to the version already deployed.
	if !strings.Contains(got, "not what to upgrade to") {
		t.Error("prompt must state that listed versions are installed, not target versions")
	}
}

// join renders an empty list as "(none)" rather than as blank, so a model reading the prompt is
// never left to infer meaning from an absence — the same reasoning as AI-GROUND-1's honest-absence
// contract, applied to the prompt itself.
func TestPromptJoinHelperOnEmpty(t *testing.T) {
	r, err := NewPromptRenderer()
	if err != nil {
		t.Fatalf("NewPromptRenderer: %v", err)
	}
	ac := domain.AssembledContext{Release: domain.ReleasePosture{
		ReleaseID: "rel-1",
		Entries: []domain.PostureEntry{{
			FindingID: "f1", ResidualPriority: 50,
			Components: []domain.PostureComponent{{Name: "x", Ecosystem: "npm"}}, // no version, no CVE
		}},
	}}
	got, err := r.Render("plan_remediation", ac)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(got, "(none)") {
		t.Errorf("empty lists must render as (none):\n%s", got)
	}
}
