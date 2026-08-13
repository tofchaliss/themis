package feed

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// alpineRecord is one Alpine secdb fix statement in the ACL's record shape: a package, the apk
// version that fixes, and the security ids that version addresses. The scheduled client
// (AlpineClient) walks whole branch DBs itself; this ACL exists for the generic ingest path and
// is what registers `alpine` as a shipped source (the trust/tier guards derive from the
// registry, so a source without an ACL cannot be classified — by design).
type alpineRecord struct {
	Package    string   `json:"package"`
	FixVersion string   `json:"fix_version"`
	CVEs       []string `json:"cves"`
	ObservedAt string   `json:"observed_at"`
}

// alpineACL translates Alpine secdb fix records into fix-bound vuln-facts Proposals.
type alpineACL struct{}

func (alpineACL) Source() string { return "alpine" }

func (a alpineACL) Translate(raw []byte) ([]Translated, error) {
	var rec alpineRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("alpine: invalid json: %w", err)
	}
	at, err := parseObserved(rec.ObservedAt)
	if err != nil {
		return nil, err
	}
	pkg := strings.TrimSpace(rec.Package)
	fixVersion := strings.TrimSpace(rec.FixVersion)
	if pkg == "" || fixVersion == "" || fixVersion == "0" {
		return nil, fmt.Errorf("alpine: record needs a package and a fix version (\"0\" is the secdb unfixed marker, not a bound)")
	}
	var out []Translated
	for _, raw := range rec.CVEs {
		cve, cerr := firstCVE(strings.Fields(raw)...)
		if cerr != nil {
			continue // non-CVE ids (XSA-…, ZBX-…) can never match a card
		}
		// SeverityUnknown throughout: the secdb states no severity, and the reconciled headline
		// skips unknown — the Proposal contributes the fix bound and nothing else (EDR-VEX-01 D7).
		p, perr := domain.NewVulnFactsProposal(a.Source(), at, domain.VulnFacts{
			Severity: value.SeverityUnknown,
			Fixes:    []domain.FixedVersion{{Package: pkg, Version: fixVersion, Ecosystem: "apk"}},
		})
		if perr != nil {
			return nil, perr
		}
		out = append(out, Translated{CVE: cve, Proposal: p})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("alpine: no canonical CVE among %v", rec.CVEs)
	}
	return out, nil
}
