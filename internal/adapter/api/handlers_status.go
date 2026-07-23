package api

import (
	"net/http"
	"strconv"

	"github.com/themis-project/themis/internal/domain"
)

// GetStatus handles GET /api/v1/status.
func (h *Handler) GetStatus(w http.ResponseWriter, r *http.Request) {
	if h.deps.Status == nil {
		WriteCatalogError(w, http.StatusInternalServerError, CodeInternalError)
		return
	}
	topN := 10
	if raw := r.URL.Query().Get("top"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			topN = n
		}
	}
	if topN > 50 {
		topN = 50
	}
	status, err := h.deps.Status.GetSystemStatus(r.Context(), topN)
	if err != nil {
		RespondError(w, r, err)
		return
	}
	signalsStale := false
	if h.deps.ThreatSignals != nil {
		stale, err := h.deps.ThreatSignals.SignalsStale(r.Context())
		if err != nil {
			RespondError(w, r, err)
			return
		}
		signalsStale = stale
	}
	degradedFeeds := []string{}
	if h.deps.FeedHealth != nil {
		feeds, err := h.deps.FeedHealth.DegradedFeeds(r.Context())
		if err != nil {
			RespondError(w, r, err)
			return
		}
		if feeds != nil {
			degradedFeeds = feeds
		}
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"as_of": status.AsOf,
		"components": map[string]int{
			"total_registered":     status.Components.TotalRegistered,
			"with_vulnerabilities": status.Components.WithVulnerabilities,
			"clean":                status.Components.Clean,
		},
		"vulnerabilities": map[string]any{
			"total_findings": status.Vulnerabilities.TotalFindings,
			"unique_cves":    status.Vulnerabilities.UniqueCVEs,
			"by_severity":    status.Vulnerabilities.BySeverity,
			"by_state":       status.Vulnerabilities.ByState,
		},
		"top_components": toTopComponents(status.TopComponents),
		"signals_stale":  signalsStale,
		"degraded_feeds": degradedFeeds,
	})
}

func toTopComponents(items []domain.TopComponentEntry) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		out = append(out, map[string]any{
			"name":                item.Name,
			"version":             item.Version,
			"purl":                item.PURL,
			"product_name":        item.ProductName,
			"vulnerability_count": item.VulnerabilityCount,
			"highest_severity":    item.HighestSeverity,
			"highest_cvss_score":  item.HighestCVSSScore,
			"highest_cve_id":      item.HighestCVEID,
		})
	}
	return out
}
