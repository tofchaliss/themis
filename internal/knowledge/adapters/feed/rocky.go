package feed

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/kernel/value"
	"github.com/themis-project/themis/internal/knowledge/domain"
)

// rockyRecord is one Rocky RXSA fix statement in the ACL's record shape: a source package, the
// rpm version (EVR/NEVRA) that fixes, and the CVEs that version addresses. The scheduled client
// (RockyClient) walks the errata API itself; this ACL exists for the generic ingest path and is
// what registers `rocky` as a shipped source (the trust/tier guards derive from the registry,
// so a source without an ACL cannot be classified — by design, same as `alpine`).
type rockyRecord struct {
	Package    string   `json:"package"`
	FixVersion string   `json:"fix_version"`
	CVEs       []string `json:"cves"`
	ObservedAt string   `json:"observed_at"`
}

// rockyACL translates Rocky RXSA fix records into fix-bound vuln-facts Proposals.
type rockyACL struct{}

func (rockyACL) Source() string { return "rocky" }

func (a rockyACL) Translate(raw []byte) ([]Translated, error) {
	var rec rockyRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("rocky: invalid json: %w", err)
	}
	at, err := parseObserved(rec.ObservedAt)
	if err != nil {
		return nil, err
	}
	pkg := strings.TrimSpace(rec.Package)
	fixVersion := strings.TrimSpace(rec.FixVersion)
	if pkg == "" || fixVersion == "" {
		return nil, fmt.Errorf("rocky: record needs a package and a fix version")
	}
	var out []Translated
	for _, raw := range rec.CVEs {
		cve, cerr := firstCVE(strings.Fields(raw)...)
		if cerr != nil {
			continue // non-CVE ids can never match a card
		}
		// SeverityUnknown throughout: `rocky` contributes fix bounds and never contends for
		// the severity headline (EDR-VEX-01 D11, mirroring `alpine`).
		p, perr := domain.NewVulnFactsProposal(a.Source(), at, domain.VulnFacts{
			Severity: value.SeverityUnknown,
			Fixes:    []domain.FixedVersion{{Package: pkg, Version: fixVersion, Ecosystem: "rpm"}},
		})
		if perr != nil {
			return nil, perr
		}
		out = append(out, Translated{CVE: cve, Proposal: p})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("rocky: no canonical CVE among %v", rec.CVEs)
	}
	return out, nil
}
