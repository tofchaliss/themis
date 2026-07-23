package feed

import "github.com/themis-project/themis/internal/knowledge/domain"

// tierBySource classifies each feed source into its intelligence tier
// (openspec/intel-source-tiers.md), so feed health can be surfaced at the right severity
// (the go-forward D-FEED-2 fix). NVD + EPSS/KEV are Tier-1 mandatory; OSV, Red Hat CSAF and
// ExploitDB are Tier-2 recommended; vendor VEX is Tier-3 enrichment. The (Tier-1) scanner
// source is added with the scanner ACL.
var tierBySource = map[string]domain.Tier{
	"nvd":       domain.Tier1Critical,
	"epsskev":   domain.Tier1Critical,
	"osv":       domain.Tier2Recommended,
	"redhat":    domain.Tier2Recommended,
	"exploitdb": domain.Tier2Recommended,
	"vexfeed":   domain.Tier3Enrichment,
	"scanner":   domain.Tier1Critical, // scanner evidence (Trivy/Grype) — Tier-1 per the taxonomy
}

// Tier returns the intelligence tier for a feed source, or domain.TierUnknown if the source
// is not classified. Callers combine it with a feed's live observation
// (domain.FeedObservation.Evaluate) to get a tier-aware health verdict.
func (r *Registry) Tier(source string) domain.Tier {
	return tierBySource[source]
}
