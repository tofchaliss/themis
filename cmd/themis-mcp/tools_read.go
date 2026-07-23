package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// pageArgs is embedded by list tools for cursor pagination.
type pageArgs struct {
	Cursor string `json:"cursor,omitempty" jsonschema:"opaque pagination cursor from a previous response's next_cursor"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max items to return (1-100, default 50)"`
}

// vulnFilterArgs is embedded by the finding-listing tools.
type vulnFilterArgs struct {
	Severity       string `json:"severity,omitempty" jsonschema:"filter by severity: critical, high, medium, low, or none"`
	EffectiveState string `json:"effective_state,omitempty" jsonschema:"filter by effective state, e.g. detected, confirmed, false_positive, accepted_risk, resolved, in_triage"`
	CVEID          string `json:"cve_id,omitempty" jsonschema:"filter to a single CVE ID, e.g. CVE-2024-1234"`
}

func registerReadTools(s *mcp.Server, c *client) {
	// --- health --------------------------------------------------------------
	type healthArgs struct{}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_health",
		Title:       "Themis health",
		Description: "Check Themis liveness (/healthz) and readiness (/readyz). Requires no API key. Use as a preflight before other calls; readiness reports the database and CVE-feed status.",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ healthArgs) (*mcp.CallToolResult, any, error) {
		out := map[string]any{}
		for _, ep := range []string{"/healthz", "/readyz"} {
			status, body, err := c.rootGet(ctx, ep)
			entry := map[string]any{"status_code": status}
			if err != nil {
				entry["error"] = err.Error()
			} else if len(body) > 0 && json.Valid(body) {
				entry["body"] = body
			} else {
				entry["body"] = strings.TrimSpace(string(body))
			}
			out[strings.TrimPrefix(ep, "/")] = entry
		}
		raw, _ := json.Marshal(out)
		return jsonText(raw)
	})

	// --- system status -------------------------------------------------------
	type statusArgs struct {
		Top int `json:"top,omitempty" jsonschema:"number of top vulnerable components to include (default 10, max 50)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_status",
		Title:       "System status",
		Description: "System-wide overview: component counts, total findings and unique CVEs, severity/state breakdowns, top vulnerable components, and feed health (signals_stale, degraded_feeds).",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a statusArgs) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		if a.Top > 0 {
			q.Set("top", fmt.Sprint(a.Top))
		}
		raw, err := c.api(ctx, "GET", "/status", q, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	// --- products / projects / versions -------------------------------------
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_list_products",
		Title:       "List products",
		Description: "List registered products (paginated).",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a pageArgs) (*mcp.CallToolResult, any, error) {
		raw, err := c.api(ctx, "GET", "/products", pageQuery(a.Cursor, a.Limit), nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	type productPageArgs struct {
		ProductID string `json:"product_id" jsonschema:"the product UUID"`
		pageArgs
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_list_projects",
		Title:       "List projects",
		Description: "List the projects under a product (paginated).",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a productPageArgs) (*mcp.CallToolResult, any, error) {
		raw, err := c.api(ctx, "GET", "/products/"+esc(a.ProductID)+"/projects", pageQuery(a.Cursor, a.Limit), nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_list_versions",
		Title:       "List product versions",
		Description: "List the versions of a product (paginated). Each version references a project_id.",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a productPageArgs) (*mcp.CallToolResult, any, error) {
		raw, err := c.api(ctx, "GET", "/products/"+esc(a.ProductID)+"/versions", pageQuery(a.Cursor, a.Limit), nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	// --- scans ---------------------------------------------------------------
	type projectPageArgs struct {
		ProjectID string `json:"project_id" jsonschema:"the project UUID"`
		pageArgs
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_list_scans",
		Title:       "List project scans",
		Description: "List correlation scans for a project (paginated). Each scan is one correlation run over an artifact.",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a projectPageArgs) (*mcp.CallToolResult, any, error) {
		raw, err := c.api(ctx, "GET", "/projects/"+esc(a.ProjectID)+"/scans", pageQuery(a.Cursor, a.Limit), nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	type scanArgs struct {
		ScanID string `json:"scan_id" jsonschema:"the scan UUID"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_get_scan",
		Title:       "Get scan",
		Description: "Get a single scan's summary, including vulnerability_counts and the originating ingestion_id.",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a scanArgs) (*mcp.CallToolResult, any, error) {
		raw, err := c.api(ctx, "GET", "/scans/"+esc(a.ScanID), nil, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	// --- findings ------------------------------------------------------------
	type scanVulnArgs struct {
		ScanID string `json:"scan_id" jsonschema:"the scan UUID"`
		vulnFilterArgs
		pageArgs
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_list_scan_vulnerabilities",
		Title:       "List scan findings",
		Description: "List vulnerability findings for one scan, with optional severity / effective_state / cve_id filters. Each finding carries enrichment (risk_score, epss_score, kev_listed, exploit_public, deterministic_level, blast_radius_score, upstream_vex_coverage).",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a scanVulnArgs) (*mcp.CallToolResult, any, error) {
		q := pageQuery(a.Cursor, a.Limit)
		applyVulnFilters(q, a.vulnFilterArgs)
		raw, err := c.api(ctx, "GET", "/scans/"+esc(a.ScanID)+"/vulnerabilities", q, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	type productVulnArgs struct {
		ProductID string `json:"product_id" jsonschema:"the product UUID"`
		Version   string `json:"version,omitempty" jsonschema:"optional product version; if set, findings are scoped to that version"`
		vulnFilterArgs
		pageArgs
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_list_product_vulnerabilities",
		Title:       "List product findings",
		Description: "List findings rolled up to the latest scan per artifact for a product (or a specific version when 'version' is given). Requires a key scoped to this product (or admin).",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a productVulnArgs) (*mcp.CallToolResult, any, error) {
		q := pageQuery(a.Cursor, effectiveLimit(a.Limit))
		applyVulnFilters(q, a.vulnFilterArgs)
		path := "/products/" + esc(a.ProductID) + "/vulnerabilities"
		if a.Version != "" {
			path = "/products/" + esc(a.ProductID) + "/versions/" + esc(a.Version) + "/vulnerabilities"
		}
		raw, err := c.api(ctx, "GET", path, q, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	type projectVulnArgs struct {
		ProjectID string `json:"project_id" jsonschema:"the project UUID"`
		vulnFilterArgs
		pageArgs
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_list_project_vulnerabilities",
		Title:       "List project findings",
		Description: "List findings for a project (latest scan per artifact). Requires a key scoped to the owning product (or admin).",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a projectVulnArgs) (*mcp.CallToolResult, any, error) {
		q := pageQuery(a.Cursor, effectiveLimit(a.Limit))
		applyVulnFilters(q, a.vulnFilterArgs)
		raw, err := c.api(ctx, "GET", "/projects/"+esc(a.ProjectID)+"/vulnerabilities", q, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	// --- components / cve-watch ---------------------------------------------
	type componentArgs struct {
		Purl      string `json:"purl,omitempty" jsonschema:"filter by exact Package URL (PURL)"`
		ProductID string `json:"product_id,omitempty" jsonschema:"filter to components in a specific product"`
		pageArgs
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_list_components",
		Title:       "List components",
		Description: "Query the component catalog by PURL and/or product (paginated).",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a componentArgs) (*mcp.CallToolResult, any, error) {
		q := pageQuery(a.Cursor, a.Limit)
		if a.Purl != "" {
			q.Set("purl", a.Purl)
		}
		if a.ProductID != "" {
			q.Set("product_id", a.ProductID)
		}
		raw, err := c.api(ctx, "GET", "/components", q, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	type cveWatchArgs struct {
		ProductID string `json:"product_id,omitempty" jsonschema:"filter to a specific product"`
		Severity  string `json:"severity,omitempty" jsonschema:"filter by severity"`
		pageArgs
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_list_cve_watch",
		Title:       "List CVE-watch findings",
		Description: "List findings auto-created by the CVE-watch scheduler (newly published CVEs matching catalog components).",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a cveWatchArgs) (*mcp.CallToolResult, any, error) {
		q := pageQuery(a.Cursor, a.Limit)
		if a.ProductID != "" {
			q.Set("product_id", a.ProductID)
		}
		if a.Severity != "" {
			q.Set("severity", a.Severity)
		}
		raw, err := c.api(ctx, "GET", "/cve-watch/findings", q, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	// --- SBOMs ---------------------------------------------------------------
	type sbomListArgs struct {
		ProductID string `json:"product_id,omitempty" jsonschema:"if set, list only this product's SBOMs; otherwise list system-wide"`
		pageArgs
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_list_sboms",
		Title:       "List SBOMs",
		Description: "List ingested SBOMs system-wide, or for one product. Response envelope is {sboms, next_cursor, total}; each entry includes component/vulnerability counts and is_latest.",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a sbomListArgs) (*mcp.CallToolResult, any, error) {
		path := "/sboms"
		if a.ProductID != "" {
			path = "/products/" + esc(a.ProductID) + "/sboms"
		}
		raw, err := c.api(ctx, "GET", path, pageQuery(a.Cursor, a.Limit), nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	// --- ingestion status ----------------------------------------------------
	type ingestionArgs struct {
		IngestionID string `json:"ingestion_id" jsonschema:"the ingestion UUID returned by an upload"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_get_ingestion",
		Title:       "Get ingestion status",
		Description: "Get the status of an async ingestion. status is one of RECEIVED, VALIDATING, CORRELATING, ENRICHING, COMPLETED, NOTIFIED, REJECTED, FAILED. On success scan_id is populated; on REJECTED/FAILED stage_detail carries the reason.",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a ingestionArgs) (*mcp.CallToolResult, any, error) {
		raw, err := c.api(ctx, "GET", "/ingestions/"+esc(a.IngestionID), nil, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	type waitArgs struct {
		IngestionID         string `json:"ingestion_id" jsonschema:"the ingestion UUID to wait on"`
		TimeoutSeconds      int    `json:"timeout_seconds,omitempty" jsonschema:"max seconds to poll before giving up (default 60)"`
		PollIntervalSeconds int    `json:"poll_interval_seconds,omitempty" jsonschema:"seconds between polls (default 2)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_wait_for_ingestion",
		Title:       "Wait for ingestion",
		Description: "Poll an ingestion until it reaches a terminal state (COMPLETED, NOTIFIED, REJECTED, FAILED) or the timeout elapses. Returns the final status; on success use its scan_id to read findings. A 202 upload only means 'queued', so use this to know when findings are ready.",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a waitArgs) (*mcp.CallToolResult, any, error) {
		timeout := time.Duration(a.TimeoutSeconds) * time.Second
		if timeout <= 0 {
			timeout = 60 * time.Second
		}
		interval := time.Duration(a.PollIntervalSeconds) * time.Second
		if interval <= 0 {
			interval = 2 * time.Second
		}
		deadline := time.Now().Add(timeout)
		terminal := map[string]bool{"COMPLETED": true, "NOTIFIED": true, "REJECTED": true, "FAILED": true}
		var last json.RawMessage
		for {
			raw, err := c.api(ctx, "GET", "/ingestions/"+esc(a.IngestionID), nil, nil, nil)
			if err != nil {
				return nil, nil, err
			}
			last = raw
			var st struct {
				Status string `json:"status"`
			}
			_ = json.Unmarshal(raw, &st)
			if terminal[st.Status] {
				return jsonText(raw)
			}
			if time.Now().After(deadline) {
				wrapped, _ := json.Marshal(map[string]any{
					"timed_out":     true,
					"last_observed": last,
					"note":          fmt.Sprintf("ingestion did not reach a terminal state within %s; last status above", timeout),
				})
				return jsonText(wrapped)
			}
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(interval):
			}
		}
	})

	// --- triage history (read-only) -----------------------------------------
	type triageHistoryArgs struct {
		FindingID string `json:"finding_id" jsonschema:"the vulnerability finding UUID"`
		pageArgs
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_get_triage_history",
		Title:       "Get triage history",
		Description: "List the append-only triage decisions recorded for a finding (decision, justification, actor, recorded_at).",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a triageHistoryArgs) (*mcp.CallToolResult, any, error) {
		raw, err := c.api(ctx, "GET", "/vulnerabilities/"+esc(a.FindingID)+"/triage/history", pageQuery(a.Cursor, a.Limit), nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	// --- blast radius --------------------------------------------------------
	type blastArgs struct {
		ProductID       string `json:"product_id" jsonschema:"the product UUID"`
		VulnerabilityID string `json:"vulnerability_id,omitempty" jsonschema:"optional: scope to a specific finding"`
		ComponentID     string `json:"component_id,omitempty" jsonschema:"optional: scope to a specific component"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_get_blast_radius",
		Title:       "Get blast radius",
		Description: "Compute how many customer teams a product (optionally a specific finding/component) affects, via the asset graph. Returns blast_radius_score, affected_teams, and unique_customer_count.",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a blastArgs) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		if a.VulnerabilityID != "" {
			q.Set("vulnerability_id", a.VulnerabilityID)
		}
		if a.ComponentID != "" {
			q.Set("component_id", a.ComponentID)
		}
		raw, err := c.api(ctx, "GET", "/products/"+esc(a.ProductID)+"/blast-radius", q, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	// --- VEX export / coverage ----------------------------------------------
	type vexExportArgs struct {
		ProductID string `json:"product_id" jsonschema:"the product UUID"`
		Version   string `json:"version" jsonschema:"the product version"`
		Format    string `json:"format,omitempty" jsonschema:"export format: openvex or cyclonedx (default cyclonedx)"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_export_vex",
		Title:       "Export VEX",
		Description: "Export a standards-compliant VEX document for a product version. Returns the raw VEX JSON (OpenVEX or CycloneDX-VEX) as an opaque document.",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a vexExportArgs) (*mcp.CallToolResult, any, error) {
		q := url.Values{}
		if a.Format != "" {
			q.Set("format", a.Format)
		}
		raw, err := c.api(ctx, "GET", "/products/"+esc(a.ProductID)+"/versions/"+esc(a.Version)+"/vex", q, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	type vexCoverageArgs struct {
		ProductID string `json:"product_id" jsonschema:"the product UUID"`
		Version   string `json:"version" jsonschema:"the product version"`
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_get_vex_coverage",
		Title:       "Get VEX coverage",
		Description: "Upstream-VEX coverage aggregate for a product version: {covered, not_covered, purl_mismatch}.",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a vexCoverageArgs) (*mcp.CallToolResult, any, error) {
		raw, err := c.api(ctx, "GET", "/products/"+esc(a.ProductID)+"/versions/"+esc(a.Version)+"/vex-coverage", nil, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})

	// --- config (read) -------------------------------------------------------
	type noArgs struct{}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_get_notification_config",
		Title:       "Get notification config",
		Description: "Read the notification routing rules.",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
		raw, err := c.api(ctx, "GET", "/config/notifications", nil, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})
	mcp.AddTool(s, &mcp.Tool{
		Name:        "themis_get_scanner_config",
		Title:       "Get scanner config",
		Description: "Read the scanner configuration (enabled_formats, max_components, parse_timeout_seconds).",
		Annotations: readOnlyHints(),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
		raw, err := c.api(ctx, "GET", "/config/scanners", nil, nil, nil)
		if err != nil {
			return nil, nil, err
		}
		return jsonText(raw)
	})
}

func applyVulnFilters(q url.Values, f vulnFilterArgs) {
	if f.Severity != "" {
		q.Set("severity", f.Severity)
	}
	if f.EffectiveState != "" {
		q.Set("effective_state", f.EffectiveState)
	}
	if f.CVEID != "" {
		q.Set("cve_id", f.CVEID)
	}
}
