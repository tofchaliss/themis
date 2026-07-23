package feed

import (
	"encoding/json"
	"fmt"

	"github.com/themis-project/themis/internal/knowledge/domain"
)

// epssKevRecord is the combined EPSS + KEV exploit signal for a CVE (the PoC keeps
// these together in epss_kev_signals).
type epssKevRecord struct {
	CVE        string  `json:"cve"`
	ObservedAt string  `json:"observed_at"`
	EPSS       float64 `json:"epss"`
	KEV        bool    `json:"kev"`
}

// epssKevACL translates EPSS/KEV records into exploit-signal Proposals.
type epssKevACL struct{}

func (epssKevACL) Source() string { return "epsskev" }

func (a epssKevACL) Translate(raw []byte) ([]Translated, error) {
	var rec epssKevRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("epsskev: invalid json: %w", err)
	}
	cve, err := firstCVE(rec.CVE)
	if err != nil {
		return nil, err
	}
	at, err := parseObserved(rec.ObservedAt)
	if err != nil {
		return nil, err
	}
	p, err := domain.NewExploitSignalProposal(a.Source(), at, domain.ExploitSignal{EPSS: rec.EPSS, KEV: rec.KEV})
	if err != nil {
		return nil, err
	}
	return []Translated{{CVE: cve, Proposal: p}}, nil
}
