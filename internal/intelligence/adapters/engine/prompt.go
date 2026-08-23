package engine

import (
	_ "embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/themis-project/themis/internal/intelligence/domain"
	"github.com/themis-project/themis/internal/platform/observability"
)

//go:embed templates/recommend_position.tmpl
var recommendPositionTmpl string

//go:embed templates/plan_remediation.tmpl
var planRemediationTmpl string

//go:embed templates/explain_vulnerability.tmpl
var explainVulnerabilityTmpl string

//go:embed templates/compare_releases.tmpl
var compareReleasesTmpl string

// promptFuncs are the few helpers the templates need. Deliberately tiny: a prompt template is an
// adapter asset, and logic that grows here is logic that has escaped the domain — the grouping a
// plan needs lives in ReleasePosture.PlanActions, not in a template function.
var promptFuncs = template.FuncMap{
	"add1": func(i int) int { return i + 1 },
	// mul100 renders a 0..1 ratio as a percentage figure (G-AI-3 release-overlap label).
	"mul100": func(f float64) float64 { return f * 100 },
	// first3 caps a long list: a merged module-stream step legitimately covers 33 packages, and
	// printing all 33 turned one plan step into five wrapped lines of noise (PLAN-1). The COLLAPSE
	// is right; the rendering was not.
	"first3": func(v []string) string {
		if len(v) == 0 {
			return "(none)"
		}
		if len(v) <= 3 {
			return strings.Join(v, ", ")
		}
		return strings.Join(v[:3], ", ") + fmt.Sprintf(" +%d more", len(v)-3)
	},
	// sampleCVE returns a REAL citable CVE from this request's own plan, so the response-format
	// example is SELF-GROUNDING: a model that copies the example verbatim still emits a ref that
	// passes Grounding Verification.
	//
	// The example used to read `"ref":"..."`, and a live model cited the literal string "..." —
	// ungrounded, whole plan discarded. That is the third time this capability was refused for
	// something the PROMPT showed it (after the truncated `upgrade` heading and the `<--`
	// annotations). Placeholders in an example are indistinguishable from content to a model
	// filling in a shape.
	//
	// Empty plan → empty string, and the template then omits the example entirely rather than
	// printing a placeholder by another name.
	"sampleCVE": func(actions []domain.UpgradeAction) string {
		for _, a := range actions {
			if len(a.CVEs) > 0 {
				return a.CVEs[0]
			}
		}
		return ""
	},
	// capList bounds a list in the prompt and SAYS how much it dropped.
	//
	// A module-stream card carries one affected range per rebuilt package per EL minor — measured
	// on a live estate: ~100 ranges and 266 unattributed fixes on a single card. That filled the
	// model's budget and it stopped mid-JSON: `schema_invalid: unexpected end of JSON input`,
	// after 164 seconds. The recommendation was not wrong, it was never finished.
	//
	// Truncating silently would be worse than the overflow: the model would reason from a subset
	// while believing it had the whole. The "+N more" tail is what keeps the omission honest.
	"capList": func(v []string, n int) string {
		if len(v) == 0 {
			return "(none)"
		}
		if len(v) <= n {
			return strings.Join(v, " ")
		}
		return strings.Join(v[:n], " ") + fmt.Sprintf(" … +%d more (not shown)", len(v)-n)
	},
	"join": func(v []string) string {
		if len(v) == 0 {
			return "(none)"
		}
		return strings.Join(v, ", ")
	},
}

// PromptRenderer builds provider-facing prompts from the assembled context (D6). The
// templates are Gateway-owned adapter assets — no prompt strings live in the domain
// or app rings. It implements app.PromptRenderer.
type PromptRenderer struct {
	templates map[string]*template.Template
	// logger is optional (nil = silent). It exists so the DETERMINISTIC half of a plan is
	// observable without a model — see WithLogger.
	logger *observability.Logger
}

// WithLogger makes the computed plan grouping visible, and returns the renderer for chaining.
//
// Without it the `GROUP BY` behind a plan can only be inspected THROUGH the model, so a grouping
// bug and a bad generation look identical from outside — which is exactly the ambiguity that cost
// a VM round trip on 2026-08-08 (a plan collapsed from 15 steps to 4 and nothing could say whether
// that was correct). The grouping is the part that is supposed to be deterministic and auditable;
// it should not require an LLM to read it.
//
// It lives on the RENDERER because `Render` is called from the app ring, which depguard forbids
// from logging (CONVENTIONS R1). Adapters may log; app may not.
func (r *PromptRenderer) WithLogger(l *observability.Logger) *PromptRenderer {
	r.logger = l
	return r
}

// NewPromptRenderer builds the renderer with the embedded capability templates.
func NewPromptRenderer() (*PromptRenderer, error) {
	return newRenderer(map[string]string{
		"recommend_position":    recommendPositionTmpl,
		"plan_remediation":      planRemediationTmpl,
		"explain_vulnerability": explainVulnerabilityTmpl,
		"compare_releases":      compareReleasesTmpl,
	})
}

// newRenderer parses the given capability-id -> template-text map (unexported so
// tests can inject templates, including malformed ones).
func newRenderer(src map[string]string) (*PromptRenderer, error) {
	tmpls := make(map[string]*template.Template, len(src))
	for id, text := range src {
		t, err := template.New(id).Funcs(promptFuncs).Parse(text)
		if err != nil {
			return nil, fmt.Errorf("parse prompt template %q: %w", id, err)
		}
		tmpls[id] = t
	}
	return &PromptRenderer{templates: tmpls}, nil
}

// Render renders the capability's prompt from the assembled context.
func (r *PromptRenderer) Render(capabilityID string, ctx domain.AssembledContext) (string, error) {
	t, ok := r.templates[capabilityID]
	if !ok {
		return "", fmt.Errorf("no prompt template for capability %q", capabilityID)
	}
	r.logPlanGrouping(capabilityID, ctx)
	var sb strings.Builder
	if err := t.Execute(&sb, ctx); err != nil {
		return "", fmt.Errorf("render prompt %q: %w", capabilityID, err)
	}
	return sb.String(), nil
}

// logPlanGrouping records the computed upgrade actions for a release-scoped plan.
//
// It calls PlanActions a second time (the template calls it too). That is safe and the equality is
// PROVABLE rather than assumed: PlanActions is pure — no clock, no randomness, no I/O — so two
// calls on the same posture return the same thing. A log that recomputed something impure would be
// worse than no log, because it would describe a prompt that was never sent.
func (r *PromptRenderer) logPlanGrouping(capabilityID string, ctx domain.AssembledContext) {
	if r.logger == nil || capabilityID != "plan_remediation" {
		return
	}
	actions := ctx.Release.PlanActions()
	r.logger.Info("plan grouping computed",
		observability.String("release_id", ctx.Release.ReleaseID),
		observability.Int("outstanding_findings", ctx.Release.OutstandingCount()),
		observability.Int("actions", len(actions)))
	for i, a := range actions {
		if i >= 15 {
			// The prompt itself only carries 15 (see the template). Logging more would describe
			// work the model was never shown.
			r.logger.Info("plan grouping truncated",
				observability.Int("not_shown", len(actions)-15))
			break
		}
		r.logger.Info("plan action",
			observability.Int("rank", i+1),
			observability.String("package", a.Package),
			observability.Int("packages_in_unit", len(a.Packages)),
			observability.Int("closes_findings", len(a.FindingIDs)),
			observability.Int("risk_removed", a.RiskRemoved),
			observability.String("ecosystem", a.Ecosystem))
	}
}
