package main

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerPromptsAndResources adds reusable prompts and live read-only resources.
// Both are advisory and respect the project's D-WRITE-1 human-in-the-loop rule.
func registerPromptsAndResources(s *mcp.Server, c *client) {
	s.AddPrompt(&mcp.Prompt{
		Name:        "triage_finding",
		Title:       "Triage a finding",
		Description: "Guide an advisory triage of a Themis finding; a human confirms the decision.",
		Arguments: []*mcp.PromptArgument{
			{Name: "finding_id", Description: "the vulnerability finding UUID", Required: true},
		},
	}, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		id := req.Params.Arguments["finding_id"]
		text := fmt.Sprintf(`You are helping a security analyst triage Themis finding %q.
1. Call themis_get_triage_history for this finding to see any prior decisions.
2. Review the finding's enrichment (risk_score, epss_score, kev_listed, exploit_public,
   deterministic_level) from the relevant list tool.
3. Recommend exactly one decision — false_positive, accepted_risk, confirmed, resolved, or
   escalate — with a short justification.
Do NOT call themis_submit_triage yourself: under the project's D-WRITE-1 rule a human must make
the state change. Present your recommendation for their confirmation.`, id)
		return &mcp.GetPromptResult{
			Description: "Advisory triage workflow",
			Messages: []*mcp.PromptMessage{
				{Role: "user", Content: &mcp.TextContent{Text: text}},
			},
		}, nil
	})

	s.AddPrompt(&mcp.Prompt{
		Name:        "draft_vex_justification",
		Title:       "Draft a VEX justification",
		Description: "Draft a concise, auditable VEX justification for a CVE / component / status.",
		Arguments: []*mcp.PromptArgument{
			{Name: "cve_id", Description: "the CVE ID", Required: true},
			{Name: "component_purl", Description: "the affected component PURL", Required: false},
			{Name: "status", Description: "VEX status: not_affected, affected, fixed, or under_investigation", Required: false},
		},
	}, func(_ context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		a := req.Params.Arguments
		text := fmt.Sprintf(`Draft a concise, defensible VEX justification for %s on component %q with status %q.
State reasoning an auditor would accept — for not_affected, use a recognised label such as
vulnerable_code_not_present, vulnerable_code_not_in_execute_path, or inline_mitigations_already_exist.
Keep it under 500 characters.`, a["cve_id"], a["component_purl"], a["status"])
		return &mcp.GetPromptResult{
			Messages: []*mcp.PromptMessage{{Role: "user", Content: &mcp.TextContent{Text: text}}},
		}, nil
	})

	addResource := func(uri, name, desc, apiPath string) {
		s.AddResource(&mcp.Resource{
			URI:         uri,
			Name:        name,
			Description: desc,
			MIMEType:    "application/json",
		}, func(ctx context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			raw, err := c.api(ctx, "GET", apiPath, nil, nil, nil)
			if err != nil {
				return nil, err
			}
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: "application/json", Text: string(raw)}},
			}, nil
		})
	}
	addResource("themis://status", "Themis status", "Live system status snapshot", "/status")
	addResource("themis://products", "Themis products", "Live product inventory", "/products")
}
