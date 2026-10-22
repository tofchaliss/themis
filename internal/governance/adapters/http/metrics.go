package http

import (
	"net/http"

	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/domain"
)

// GetRemediationMetrics serves the remediation metrics (EDR-REMEDIATION-01 D6).
func (h *Handler) GetRemediationMetrics(w http.ResponseWriter, r *http.Request, params gen.GetRemediationMetricsParams) {
	if h.metrics == nil {
		writeProblem(w, http.StatusServiceUnavailable, "metrics unavailable", "the metrics read is not wired on this node")
		return
	}
	product := ""
	if params.Product != nil {
		product = *params.Product
	}
	rep, err := h.metrics.Remediation(r.Context(), product)
	if err != nil {
		writeErr(w, "compute remediation metrics", err)
		return
	}
	out := gen.RemediationReport{
		GeneratedAt: h.now(), Estate: toMetrics(rep.Estate), Products: []gen.RemediationMetrics{},
		ProductsUnavailable: rep.ProductsUnavailable, Unattributed: rep.Unattributed,
	}
	for _, p := range rep.Products {
		out.Products = append(out.Products, toMetrics(p))
	}
	writeJSON(w, http.StatusOK, out)
}

func toMean(m domain.Mean) gen.MeanDays { return gen.MeanDays{MeanDays: float32(m.Days), Count: m.N} }

func toMetrics(m domain.RemediationMetrics) gen.RemediationMetrics {
	return gen.RemediationMetrics{
		Scope: m.Scope, Open: m.Open, OpenByAge: m.OpenByAge, SlaApplicable: m.SLAApplicable,
		WithinSla: m.WithinSLA, BreachedNow: m.BreachedNow, WithinSlaShare: float32(m.WithinShare),
		TimeToDecision: toMean(m.TimeToDecision), TimeToRemediation: toMean(m.TimeToRemediation),
		TimeToResolution: toMean(m.TimeToResolution),
	}
}
