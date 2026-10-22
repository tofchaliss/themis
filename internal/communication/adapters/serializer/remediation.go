package serializer

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/communication/app"
)

// RemediationRenderer renders the remediation-metrics report (EDR-REMEDIATION-01 D6) as JSON for
// tools and markdown for people. Time to remediation and time to resolution are written as two
// labelled lines, never merged: the first counts only Findings an SBOM stopped carrying AND a
// person decided afterwards (D8 Q4), the second only Findings a person resolved.
type RemediationRenderer struct{}

var _ app.RemediationRenderer = RemediationRenderer{}

var ageBands = []string{"0-7", "8-30", "31-90", "over-90"}
var severityBuckets = []string{"critical", "high", "medium", "low", "unknown"}

// RenderRemediation renders rep as "json" or "markdown".
func (RemediationRenderer) RenderRemediation(rep app.RemediationReport, format string) ([]byte, string, error) {
	switch format {
	case "json":
		b, err := json.MarshalIndent(rep, "", "  ")
		return b, "application/json", err
	case "markdown":
		return renderRemediationMarkdown(rep), "text/markdown; charset=utf-8", nil
	default:
		return nil, "", app.ErrUnknownReportFormat
	}
}

func mean(m app.MeanDays) string {
	if m.Count == 0 {
		return "no sample yet"
	}
	return fmt.Sprintf("%.1f days (over %d)", m.MeanDays, m.Count)
}

func writeScope(b *strings.Builder, m app.RemediationMetrics, title string) {
	fmt.Fprintf(b, "\n## %s\n\n", title)
	fmt.Fprintf(b, "- Open findings: %d\n", m.Open)
	if m.SLAApplicable > 0 {
		fmt.Fprintf(b, "- Within SLA: %d of %d (%.0f%%); breached now: %d\n", m.WithinSLA, m.SLAApplicable, m.WithinSLAShare*100, m.BreachedNow)
	} else {
		b.WriteString("- Within SLA: no running SLA clock\n")
	}
	fmt.Fprintf(b, "- Mean time to decision: %s\n", mean(m.TimeToDecision))
	fmt.Fprintf(b, "- Mean time to remediation (no longer in an evaluated SBOM, then decided by a person): %s\n", mean(m.TimeToRemediation))
	fmt.Fprintf(b, "- Mean time to resolution (resolved by a person): %s\n", mean(m.TimeToResolution))
	b.WriteString("\n| Age (days) | Critical | High | Medium | Low | Unknown |\n|---|---|---|---|---|---|\n")
	for _, band := range ageBands {
		fmt.Fprintf(b, "| %s |", band)
		for _, sev := range severityBuckets {
			fmt.Fprintf(b, " %d |", m.OpenByAge[band][sev])
		}
		b.WriteString("\n")
	}
}

func renderRemediationMarkdown(rep app.RemediationReport) []byte {
	var b strings.Builder
	b.WriteString("# Remediation metrics\n\n")
	fmt.Fprintf(&b, "Generated %s. Figures are read from Themis at that moment; nothing here is a decision.\n",
		rep.GeneratedAt.UTC().Format("2006-01-02 15:04 UTC"))
	writeScope(&b, rep.Estate, "Estate")
	if rep.ProductsUnavailable {
		b.WriteString("\nPer-product figures are not available: the product list could not be read.\n")
	}
	for _, p := range rep.Products {
		writeScope(&b, p, "Product: "+p.Scope)
	}
	if rep.Unattributed > 0 {
		fmt.Fprintf(&b, "\n%d finding(s) belong to releases the product list does not include; they count in the estate figures only.\n", rep.Unattributed)
	}
	return []byte(b.String())
}
