package wiring_test

import (
	"context"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/engine"
	"github.com/themis-project/themis/internal/intelligence/adapters/provider"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

// planProjection serves a release posture and nothing else — a capability whose Selection Type is
// Release must never reach for the Finding projection.
type planProjection struct {
	posture domain.ReleasePosture
	assessN int
}

func (p *planProjection) GetAssessment(context.Context, string) (domain.FindingAssessment, error) {
	p.assessN++
	return domain.FindingAssessment{}, nil
}

func (p *planProjection) GetReleasePosture(context.Context, string) (domain.ReleasePosture, error) {
	return p.posture, nil
}

func (p *planProjection) GetReleaseComparison(context.Context, string, string) (domain.ReleaseComparison, error) {
	return domain.ReleaseComparison{}, nil
}

// echoProvider returns whatever raw JSON it is given, recording the prompt it saw.
type echoProvider struct {
	raw    string
	prompt string
}

func (e *echoProvider) Complete(_ context.Context, req app.CompletionRequest) (app.CompletionResult, error) {
	e.prompt = req.Prompt
	return app.CompletionResult{Text: e.raw, TokensUsed: 1}, nil
}
func (e *echoProvider) Name() string  { return "echo" }
func (e *echoProvider) Model() string { return "echo" }

func planPosture() domain.ReleasePosture {
	rpm := func(name, source, version string) domain.PostureComponent {
		return domain.PostureComponent{
			PURL: "pkg:rpm/rocky/" + name + "@" + version, Name: name,
			Version: version, Ecosystem: "rpm", Source: source,
		}
	}
	return domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-2007-4559", ResidualPriority: 97, Components: []domain.PostureComponent{rpm("python3-ply", "python-ply", "3.9-9.el8")}},
		{FindingID: "f2", CVE: "CVE-2021-3177", ResidualPriority: 96, Components: []domain.PostureComponent{rpm("python3-ply", "python-ply", "3.9-9.el8")}},
		{FindingID: "f3", CVE: "CVE-2026-4480", ResidualPriority: 94, Components: []domain.PostureComponent{rpm("libsmbclient", "samba", "4.19.4-15.el8_10")}},
	}}
}

func planGateway(t *testing.T, proj app.ProjectionReader, prov app.Provider) *app.Gateway {
	t.Helper()
	pr, err := engine.NewPromptRenderer()
	if err != nil {
		t.Fatalf("prompt: %v", err)
	}
	gw, err := app.NewGateway(app.GatewayConfig{
		Registry:   domain.DefaultRegistry(),
		Projection: proj,
		Prompt:     pr,
		Engines:    []app.Engine{engine.NewLLMEngine(provider.NewTieredRouter(prov, nil, nil))},
	})
	if err != nil {
		t.Fatalf("gateway: %v", err)
	}
	return gw
}

func planSelection() domain.Selection {
	return domain.Selection{Type: domain.SelectionRelease, IDs: []string{"rel-1"}}
}

// The capability answers over a RELEASE: it reads the release projection, never the per-Finding
// one, and the grouping reaches the prompt already computed.
func TestPlanRemediation_ProducesAnInformationResponseOverTheReleaseProjection(t *testing.T) {
	proj := &planProjection{posture: planPosture()}
	prov := &echoProvider{raw: `{"subject_id":"rel-1","evidence":[{"kind":"cve","ref":"CVE-2007-4559"}],` +
		`"reasoning":"Upgrade python-ply first: one module rebuild closes two findings including the worst."}`}

	p, oc := planGateway(t, proj, prov).Invoke(context.Background(), "plan_remediation", planSelection(), "corr-1")

	if oc.Reason != app.ReasonOK {
		t.Fatalf("reason = %q detail=%q, want ok", oc.Reason, oc.Detail)
	}
	// An Information Response is NOT a proposal: nothing may reach Governance from this path (T7).
	if oc.Produced || p.Recommendation.Stance != "" {
		t.Errorf("an Information capability must produce no Proposal, got produced=%v %+v", oc.Produced, p)
	}
	if !strings.Contains(oc.Information, "python-ply") {
		t.Errorf("information = %q, want the plan text", oc.Information)
	}
	if proj.assessN != 0 {
		t.Errorf("GetAssessment called %d times — a release capability must not read the Finding projection", proj.assessN)
	}
	// The grouping is computed, not asked for: the prompt must already contain the collapsed
	// action, so the model is spending its tokens on judgement rather than on a GROUP BY.
	if !strings.Contains(prov.prompt, "upgrade python-ply") {
		t.Errorf("prompt did not carry the pre-computed action:\n%s", prov.prompt)
	}
	if !strings.Contains(prov.prompt, "closes 2 finding(s)") {
		t.Errorf("prompt did not carry the collapse count:\n%s", prov.prompt)
	}
}

// Grounding Verification is the ONLY gate on the Information path (T8) — there is no Governance
// stage behind it. A plan citing a CVE the release does not carry must be refused outright.
func TestPlanRemediation_RefusesUngroundedCitations(t *testing.T) {
	proj := &planProjection{posture: planPosture()}
	prov := &echoProvider{raw: `{"subject_id":"rel-1","evidence":[{"kind":"cve","ref":"CVE-2099-0001"}],` +
		`"reasoning":"Upgrade everything."}`}

	_, oc := planGateway(t, proj, prov).Invoke(context.Background(), "plan_remediation", planSelection(), "corr-1")

	if oc.Reason != app.ReasonBusinessInvalid {
		t.Fatalf("reason = %q, want the ungrounded citation refused — nothing downstream catches it", oc.Reason)
	}
	if oc.Information != "" {
		t.Errorf("information = %q, want none: a refused answer must not be shown to a human", oc.Information)
	}
}

// An invented identifier inside the PROSE cannot be schema-checked, and the plan is read as-is by
// a human, so the caveat is embedded in the text itself rather than carried beside it (TRUST-8).
func TestPlanRemediation_FlagsInventedIdentifiersInTheProse(t *testing.T) {
	proj := &planProjection{posture: planPosture()}
	prov := &echoProvider{raw: `{"subject_id":"rel-1","evidence":[{"kind":"cve","ref":"CVE-2007-4559"}],` +
		`"reasoning":"Upgrade python-ply, which also resolves CVE-2099-9999."}`}

	_, oc := planGateway(t, proj, prov).Invoke(context.Background(), "plan_remediation", planSelection(), "corr-1")

	if oc.Reason != app.ReasonOK {
		t.Fatalf("reason = %q — a warned plan is still a valid answer", oc.Reason)
	}
	if !strings.Contains(oc.Information, "UNVERIFIED MENTIONS") || !strings.Contains(oc.Information, "CVE-2099-9999") {
		t.Errorf("information = %q, want the invented CVE flagged inside the text", oc.Information)
	}
}

// A release with nothing outstanding is a real answer, not a grounding failure — and giving it
// without a model call is both faster and more truthful than asking one to say "nothing to do".
func TestPlanRemediation_AnsweresWithoutTheModelWhenNothingIsOutstanding(t *testing.T) {
	decided := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-1", ResidualPriority: 0},
	}}
	prov := &echoProvider{raw: `{"subject_id":"rel-1","evidence":[],"reasoning":"should not be called"}`}

	_, oc := planGateway(t, &planProjection{posture: decided}, prov).
		Invoke(context.Background(), "plan_remediation", planSelection(), "corr-1")

	if oc.Reason != app.ReasonOK || !strings.Contains(oc.Information, "No outstanding Findings") {
		t.Fatalf("reason=%q information=%q, want the deterministic empty answer", oc.Reason, oc.Information)
	}
	if prov.prompt != "" {
		t.Error("the provider must not be called when there is nothing to plan")
	}
	if oc.DecidedBy != "rule:nothing-outstanding" {
		t.Errorf("decided_by = %q, want the rule that answered", oc.DecidedBy)
	}
}

// A Finding-scoped selection must not reach the release capability, and vice versa: the bound is
// enforced before any grounding is assembled or any provider is called (T9).
func TestPlanRemediation_RejectsAFindingSelection(t *testing.T) {
	prov := &echoProvider{raw: `{}`}
	_, oc := planGateway(t, &planProjection{posture: planPosture()}, prov).Invoke(
		context.Background(), "plan_remediation",
		domain.Selection{Type: domain.SelectionFinding, IDs: []string{"f1"}}, "corr-1")

	if oc.Reason != app.ReasonSelectionMismatch {
		t.Fatalf("reason = %q, want a selection mismatch", oc.Reason)
	}
	if prov.prompt != "" {
		t.Error("the provider must not be called for a rejected selection")
	}
}
