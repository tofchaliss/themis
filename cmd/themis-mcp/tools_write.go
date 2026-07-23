package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// resolveDocument returns the SBOM/VEX document as a JSON object, from either an
// inline object or a local file path (exactly one must be provided).
func resolveDocument(doc map[string]any, path string) (map[string]any, error) {
	switch {
	case len(doc) > 0 && path != "":
		return nil, fmt.Errorf("provide either 'document' or 'document_path', not both")
	case len(doc) > 0:
		return doc, nil
	case path != "":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading document_path: %w", err)
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			return nil, fmt.Errorf("document_path %q is not a JSON object: %w", path, err)
		}
		return m, nil
	default:
		return nil, fmt.Errorf("provide 'document' (a JSON object) or 'document_path' (a local file)")
	}
}

func registerWriteTools(s *mcp.Server, c *client) {
	// --- inventory: products / projects / versions / artifacts ---------------
	type createProductArgs struct {
		Name        string `json:"name" jsonschema:"product name"`
		Description string `json:"description,omitempty" jsonschema:"optional description"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_create_product",
		Title:       "Create product",
		Description: "Create a product. This also auto-creates a default project. Requires an admin (non-read-only) key.",
		Annotations: additiveHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a createProductArgs) (*mcp.CallToolResult, any, error) {
		body := map[string]any{"name": a.Name}
		if a.Description != "" {
			body["description"] = a.Description
		}
		raw, err := c.api(ctx, "POST", "/products", nil, body, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	type createProjectArgs struct {
		ProductID   string `json:"product_id" jsonschema:"the product UUID"`
		Name        string `json:"name" jsonschema:"project name"`
		Description string `json:"description,omitempty" jsonschema:"optional description"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_create_project",
		Title:       "Create project",
		Description: "Create a project under a product.",
		Annotations: additiveHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a createProjectArgs) (*mcp.CallToolResult, any, error) {
		body := map[string]any{"name": a.Name}
		if a.Description != "" {
			body["description"] = a.Description
		}
		raw, err := c.api(ctx, "POST", "/products/"+esc(a.ProductID)+"/projects", nil, body, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	type createVersionArgs struct {
		ProjectID string `json:"project_id" jsonschema:"the project UUID"`
		Version   string `json:"version" jsonschema:"the version string, e.g. 1.2.3"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_create_version",
		Title:       "Create version",
		Description: "Create a new version under a project.",
		Annotations: additiveHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a createVersionArgs) (*mcp.CallToolResult, any, error) {
		raw, err := c.api(ctx, "POST", "/projects/"+esc(a.ProjectID)+"/versions", nil, map[string]any{"version": a.Version}, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	type registerArtifactArgs struct {
		ProductID   string `json:"product_id" jsonschema:"the product UUID"`
		ImageDigest string `json:"image_digest" jsonschema:"the image digest, e.g. sha256:...; globally unique, re-registering returns the existing artifact"`
		Version     string `json:"version,omitempty" jsonschema:"optional version label"`
		Repository  string `json:"repository,omitempty" jsonschema:"optional repository name"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_register_artifact",
		Title:       "Register artifact",
		Description: "Register a scan-target artifact (image digest) under a product. An artifact must exist before an SBOM referencing it can be uploaded. Returns {id, version_id, image_digest} — use id as artifact_id when uploading.",
		Annotations: additiveHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a registerArtifactArgs) (*mcp.CallToolResult, any, error) {
		body := map[string]any{"image_digest": a.ImageDigest}
		if a.Version != "" {
			body["version"] = a.Version
		}
		if a.Repository != "" {
			body["repository"] = a.Repository
		}
		raw, err := c.api(ctx, "POST", "/products/"+esc(a.ProductID)+"/artifacts", nil, body, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	// --- asset graph (blast radius inputs) -----------------------------------
	type createMicroserviceArgs struct {
		ProductID   string            `json:"product_id" jsonschema:"the product UUID"`
		Name        string            `json:"name" jsonschema:"microservice name"`
		Description string            `json:"description,omitempty" jsonschema:"optional description"`
		TechStack   map[string]string `json:"tech_stack,omitempty" jsonschema:"optional tech-stack tags as key/value pairs"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_create_microservice",
		Title:       "Create microservice",
		Description: "Register a microservice within a product's security boundary (asset-graph node).",
		Annotations: additiveHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a createMicroserviceArgs) (*mcp.CallToolResult, any, error) {
		body := map[string]any{"name": a.Name}
		if a.Description != "" {
			body["description"] = a.Description
		}
		if len(a.TechStack) > 0 {
			body["tech_stack"] = a.TechStack
		}
		raw, err := c.api(ctx, "POST", "/products/"+esc(a.ProductID)+"/microservices", nil, body, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	type createDeploymentArgs struct {
		MicroserviceID string `json:"microservice_id" jsonschema:"the microservice UUID"`
		Environment    string `json:"environment" jsonschema:"deployment environment, e.g. production"`
		CustomerID     string `json:"customer_id" jsonschema:"the owning customer UUID"`
		Region         string `json:"region,omitempty" jsonschema:"optional region"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_create_deployment",
		Title:       "Create deployment",
		Description: "Record a running deployment of a microservice owned by a customer (asset-graph edge feeding blast-radius).",
		Annotations: additiveHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a createDeploymentArgs) (*mcp.CallToolResult, any, error) {
		body := map[string]any{"environment": a.Environment, "customer_id": a.CustomerID}
		if a.Region != "" {
			body["region"] = a.Region
		}
		raw, err := c.api(ctx, "POST", "/microservices/"+esc(a.MicroserviceID)+"/deployments", nil, body, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	type createCustomerArgs struct {
		Name                    string            `json:"name" jsonschema:"customer/team name"`
		ContactEmail            string            `json:"contact_email" jsonschema:"contact email; must be unique"`
		NotificationPreferences map[string]string `json:"notification_preferences,omitempty" jsonschema:"optional notification preferences as key/value pairs"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_create_customer",
		Title:       "Create customer",
		Description: "Register an internal team/owner that receives security notifications (asset-graph leaf).",
		Annotations: additiveHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a createCustomerArgs) (*mcp.CallToolResult, any, error) {
		body := map[string]any{"name": a.Name, "contact_email": a.ContactEmail}
		if len(a.NotificationPreferences) > 0 {
			body["notification_preferences"] = a.NotificationPreferences
		}
		raw, err := c.api(ctx, "POST", "/customers", nil, body, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	// --- SBOM ingestion (additive evidence) ----------------------------------
	type uploadSBOMArgs struct {
		Format           string         `json:"format" jsonschema:"SBOM format: cyclonedx, spdx, trivy, grype, or syft"`
		Document         map[string]any `json:"document,omitempty" jsonschema:"the SBOM as a JSON object (mutually exclusive with document_path)"`
		DocumentPath     string         `json:"document_path,omitempty" jsonschema:"path to a local SBOM JSON file to read instead of inlining document"`
		ArtifactID       string         `json:"artifact_id,omitempty" jsonschema:"the registered artifact UUID this SBOM describes"`
		ProjectID        string         `json:"project_id,omitempty" jsonschema:"optional project UUID"`
		ImageDigest      string         `json:"image_digest,omitempty" jsonschema:"optional image digest"`
		SpecVersion      string         `json:"spec_version,omitempty" jsonschema:"optional spec version, e.g. 1.6"`
		CIJobID          string         `json:"ci_job_id,omitempty" jsonschema:"optional CI job id"`
		CIPipelineURL    string         `json:"ci_pipeline_url,omitempty" jsonschema:"optional CI pipeline URL"`
		SupplierIdentity string         `json:"supplier_identity,omitempty" jsonschema:"optional supplier identity"`
		IdempotencyKey   string         `json:"idempotency_key,omitempty" jsonschema:"optional idempotency key; replaying the same key returns the existing ingestion"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_upload_sbom",
		Title:       "Upload SBOM",
		Description: "Upload an SBOM for async correlation. This adds evidence (a new scan) and does not alter existing findings' judgment. Returns 202 with an ingestion_id — the SBOM is NOT processed yet; call themis_wait_for_ingestion, then read findings by the resulting scan_id. The artifact should be registered first.",
		Annotations: additiveHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a uploadSBOMArgs) (*mcp.CallToolResult, any, error) {
		format := strings.ToLower(strings.TrimSpace(a.Format))
		if !contains(sbomFormats, format) {
			return nil, nil, fmt.Errorf("format must be one of %v, got %q", sbomFormats, a.Format)
		}
		doc, err := resolveDocument(a.Document, a.DocumentPath)
		if err != nil {
			return nil, nil, err
		}
		body := map[string]any{"format": format, "document": doc}
		putIfSet(body, "artifact_id", a.ArtifactID)
		putIfSet(body, "project_id", a.ProjectID)
		putIfSet(body, "image_digest", a.ImageDigest)
		putIfSet(body, "spec_version", a.SpecVersion)
		putIfSet(body, "ci_job_id", a.CIJobID)
		putIfSet(body, "ci_pipeline_url", a.CIPipelineURL)
		putIfSet(body, "supplier_identity", a.SupplierIdentity)
		headers := map[string]string{"Idempotency-Key": a.IdempotencyKey}
		raw, err := c.api(ctx, "POST", "/sbom/upload", nil, body, headers)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	// --- VEX upload (judgment-bearing: can suppress findings) ----------------
	type uploadVEXArgs struct {
		Format           string         `json:"format" jsonschema:"VEX format, e.g. openvex, cyclonedx, or csaf"`
		Document         map[string]any `json:"document,omitempty" jsonschema:"the VEX document as a JSON object (mutually exclusive with document_path)"`
		DocumentPath     string         `json:"document_path,omitempty" jsonschema:"path to a local VEX JSON file"`
		SBOMChecksum     string         `json:"sbom_checksum" jsonschema:"checksum of the parent SBOM this VEX applies to"`
		SpecVersion      string         `json:"spec_version,omitempty" jsonschema:"optional spec version"`
		SupplierIdentity string         `json:"supplier_identity,omitempty" jsonschema:"optional supplier identity"`
		IdempotencyKey   string         `json:"idempotency_key,omitempty" jsonschema:"optional idempotency key"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_upload_vex",
		Title:       "Upload VEX",
		Description: "Upload a VEX document for async application. WARNING: a VEX assertion of not_affected/fixed overlays and can suppress an existing finding's effective_state WITHOUT a triage record. This is a judgment-bearing write — under the project's D-WRITE-1 rule, changing a finding's state is meant to require a human. Prefer surfacing VEX to a person over asserting it autonomously.",
		Annotations: destructiveHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a uploadVEXArgs) (*mcp.CallToolResult, any, error) {
		if strings.TrimSpace(a.Format) == "" {
			return nil, nil, fmt.Errorf("format is required")
		}
		if strings.TrimSpace(a.SBOMChecksum) == "" {
			return nil, nil, fmt.Errorf("sbom_checksum is required")
		}
		doc, err := resolveDocument(a.Document, a.DocumentPath)
		if err != nil {
			return nil, nil, err
		}
		body := map[string]any{"format": a.Format, "document": doc, "sbom_checksum": a.SBOMChecksum}
		putIfSet(body, "spec_version", a.SpecVersion)
		putIfSet(body, "supplier_identity", a.SupplierIdentity)
		headers := map[string]string{"Idempotency-Key": a.IdempotencyKey}
		raw, err := c.api(ctx, "POST", "/vex/upload", nil, body, headers)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	// --- triage (writes effective_state + generates VEX) ---------------------
	type triageArgs struct {
		FindingID     string `json:"finding_id" jsonschema:"the vulnerability finding UUID (from a scan-vulnerability id)"`
		Decision      string `json:"decision" jsonschema:"one of: false_positive, accepted_risk, confirmed, resolved, escalate"`
		Justification string `json:"justification" jsonschema:"required human-readable rationale"`
		AcceptedUntil string `json:"accepted_until,omitempty" jsonschema:"RFC3339 expiry; required when decision is accepted_risk"`
		AssignedTo    string `json:"assigned_to,omitempty" jsonschema:"optional assignee"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_submit_triage",
		Title:       "Submit triage decision",
		Description: "Record a triage decision for a finding. WARNING: this writes risk_context.effective_state, appends triage_history, and (for all decisions except 'escalate') generates a themis_generated VEX assertion that re-applies on future scans. Under the project's D-WRITE-1 rule this is a HUMAN decision; the action is attributed to the MCP server's own API key in the audit log, indistinguishable from a person using that key. Only call this when a human has authorized the specific decision.",
		Annotations: destructiveHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a triageArgs) (*mcp.CallToolResult, any, error) {
		if !contains(triageDecisions, a.Decision) {
			return nil, nil, fmt.Errorf("decision must be one of %v; got %q", triageDecisions, a.Decision)
		}
		if strings.TrimSpace(a.Justification) == "" {
			return nil, nil, fmt.Errorf("justification is required")
		}
		if a.Decision == "accepted_risk" && strings.TrimSpace(a.AcceptedUntil) == "" {
			return nil, nil, fmt.Errorf("accepted_until (RFC3339) is required when decision is accepted_risk")
		}
		body := map[string]any{"decision": a.Decision, "justification": a.Justification}
		putIfSet(body, "accepted_until", a.AcceptedUntil)
		putIfSet(body, "assigned_to", a.AssignedTo)
		raw, err := c.api(ctx, "POST", "/vulnerabilities/"+esc(a.FindingID)+"/triage", nil, body, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	// --- SBOM soft-delete ----------------------------------------------------
	type deleteSBOMArgs struct {
		ScanReportID string `json:"scan_report_id" jsonschema:"the scan/SBOM id from a list_sboms entry (a scan_reports id)"`
		Force        bool   `json:"force,omitempty" jsonschema:"set true to delete even the latest scan for an artifact"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_delete_sbom",
		Title:       "Delete SBOM",
		Description: "Soft-delete (tombstone) an SBOM/scan. Underlying evidence rows are retained but the scan and its findings are hidden. Deleting the latest scan requires force=true. Writes an SBOM_DELETED audit entry. This is destructive to the visible finding set.",
		Annotations: destructiveHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a deleteSBOMArgs) (*mcp.CallToolResult, any, error) {
		query := url.Values{}
		if a.Force {
			query.Set("force", "true")
		}
		raw, err := c.api(ctx, "DELETE", "/sboms/"+esc(a.ScanReportID), query, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	registerConfigWriteTools(s, c)
}

func registerConfigWriteTools(s *mcp.Server, c *client) {
	type notifRule struct {
		Name        string `json:"name" jsonschema:"rule name"`
		EventType   string `json:"event_type" jsonschema:"event type this rule matches"`
		Channel     string `json:"channel" jsonschema:"delivery channel: email, slack, or webhook"`
		Destination string `json:"destination" jsonschema:"channel destination (address/URL)"`
		Enabled     *bool  `json:"enabled,omitempty" jsonschema:"whether the rule is enabled"`
	}
	type updateNotifArgs struct {
		Rules []notifRule `json:"rules" jsonschema:"the complete set of notification rules (this REPLACES all existing rules)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_update_notification_config",
		Title:       "Update notification config",
		Description: "Replace the notification routing rules. WARNING: this is a full replacement — omitted rules are removed. Requires an admin (non-read-only) key.",
		Annotations: destructiveHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a updateNotifArgs) (*mcp.CallToolResult, any, error) {
		for i, r := range a.Rules {
			if !contains(notificationChannels, r.Channel) {
				return nil, nil, fmt.Errorf("rules[%d].channel must be one of %v; got %q", i, notificationChannels, r.Channel)
			}
		}
		raw, err := c.api(ctx, "PUT", "/config/notifications", nil, map[string]any{"rules": a.Rules}, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	type updateScannerArgs struct {
		EnabledFormats      []string `json:"enabled_formats,omitempty" jsonschema:"SBOM formats to accept"`
		MaxComponents       int      `json:"max_components,omitempty" jsonschema:"max components per SBOM"`
		ParseTimeoutSeconds int      `json:"parse_timeout_seconds,omitempty" jsonschema:"parser timeout in seconds"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_update_scanner_config",
		Title:       "Update scanner config",
		Description: "Replace the scanner configuration. WARNING: this is a full replacement. Requires an admin (non-read-only) key.",
		Annotations: destructiveHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a updateScannerArgs) (*mcp.CallToolResult, any, error) {
		body := map[string]any{}
		if len(a.EnabledFormats) > 0 {
			body["enabled_formats"] = a.EnabledFormats
		}
		if a.MaxComponents > 0 {
			body["max_components"] = a.MaxComponents
		}
		if a.ParseTimeoutSeconds > 0 {
			body["parse_timeout_seconds"] = a.ParseTimeoutSeconds
		}
		raw, err := c.api(ctx, "PUT", "/config/scanners", nil, body, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})
}

func putIfSet(m map[string]any, key, value string) {
	if value != "" {
		m[key] = value
	}
}
