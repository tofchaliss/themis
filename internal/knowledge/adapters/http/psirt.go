package http

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/adapters/http/gen"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// WithPSIRT wires the PSIRT early alert (EDR-PSIRT-01 P2).
func (h *Handler) WithPSIRT(p *app.PSIRTService) *Handler {
	h.psirt = p
	return h
}

// psirtCache memoizes one alert answer per (window, floor) for publishedCacheTTL: a page
// reload must not re-ask NVD and CVE.org. A transport economy, not a rule.
type psirtCache struct {
	mu   sync.Mutex
	at   map[string]time.Time
	rows map[string]app.PSIRTResult
	now  func() time.Time
}

func (c *psirtCache) get(key string) (app.PSIRTResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	if at, ok := c.at[key]; ok && now().Sub(at) < publishedCacheTTL {
		return c.rows[key], true
	}
	return app.PSIRTResult{}, false
}

func (c *psirtCache) put(key string, res app.PSIRTResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	if c.at == nil {
		c.at, c.rows = map[string]time.Time{}, map[string]app.PSIRTResult{}
	}
	c.at[key], c.rows[key] = now(), res
}

// GetPSIRTAlerts handles GET /psirt/alerts. No world source is a 503; a failing one is a 502.
func (h *Handler) GetPSIRTAlerts(w http.ResponseWriter, r *http.Request, params gen.GetPSIRTAlertsParams) {
	if h.psirt == nil || !h.published.Enabled() {
		writeProblem(w, http.StatusServiceUnavailable, "no PSIRT source wired",
			"this node has no per-CVE source configured for the PSIRT alert")
		return
	}
	days := 0
	if params.Days != nil {
		days = *params.Days
	}
	if days <= 0 {
		days = app.PublishedDefaultDays
	}
	if days > app.PublishedMaxDays {
		days = app.PublishedMaxDays
	}
	floor := "high"
	if params.MinSeverity != nil {
		switch m := strings.ToLower(strings.TrimSpace(*params.MinSeverity)); m {
		case "critical", "high", "medium", "low":
			floor = m
		case "":
		default:
			writeProblem(w, http.StatusBadRequest, "invalid min_severity", "min_severity is one of critical, high, medium, low")
			return
		}
	}
	key := floor + "/" + strconv.Itoa(days)
	res, hit := h.psirtCache.get(key)
	if !hit {
		var err error
		res, err = h.psirt.Alerts(r.Context(), days, floor)
		if err != nil {
			status := http.StatusBadGateway
			if errors.Is(err, app.ErrPublishedUnavailable) {
				status = http.StatusServiceUnavailable
			}
			writeProblem(w, status, "cannot read the PSIRT alert", err.Error())
			return
		}
		h.psirtCache.put(key, res)
	}
	out := gen.PSIRTAlerts{
		Alerts:            make([]gen.PSIRTAlert, 0, len(res.Alerts)),
		EstateUnavailable: res.EstateUnavailable,
		LookupsSkipped:    res.LookupsSkipped,
		IssueTypeTable:    domain.IssueTypeTableVersion,
	}
	for _, a := range res.Alerts {
		item := gen.PSIRTAlert{
			Cve: a.CVE, Published: a.Published, Carded: a.Carded,
			OriginalScore: float32(a.Score), OriginalSeverity: string(value.SeverityFromCVSSScore(a.Score)), ScoreSource: a.ScoreSource,
			Matches: make([]gen.PSIRTMatch, 0, len(a.Matches)),
		}
		if a.Summary != "" {
			item.Summary = strptr(a.Summary)
		}
		if !a.Modified.IsZero() {
			m := a.Modified
			item.Modified = &m
		}
		if len(a.Weaknesses) > 0 {
			cwes := append([]string(nil), a.Weaknesses...)
			item.Cwes = &cwes
			item.IssueType = strptr(domain.IssueType(cwes))
		}
		if len(a.Affected) > 0 {
			aff := append([]string(nil), a.Affected...)
			item.AffectedProducts = &aff
		}
		for _, m := range a.Matches {
			item.Matches = append(item.Matches, gen.PSIRTMatch{ProductId: m.ProductID, ProductName: m.ProductName, Component: m.Component, MatchedOn: m.MatchedOn})
		}
		out.Alerts = append(out.Alerts, item)
	}
	writeJSON(w, http.StatusOK, out)
}
