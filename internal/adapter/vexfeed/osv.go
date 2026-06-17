package vexfeed

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// ParseOSVFeed parses an OSV JSON feed (Alpine, Rocky, Wolfi).
func ParseOSVFeed(raw []byte, feed string) ([]domain.VendorVEXAssertion, error) {
	var entries []osvEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		var single osvEntry
		if err2 := json.Unmarshal(raw, &single); err2 != nil {
			return nil, fmt.Errorf("parse osv feed: %w", err)
		}
		entries = []osvEntry{single}
	}
	var out []domain.VendorVEXAssertion
	for _, entry := range entries {
		cveID := entry.firstCVE()
		if cveID == "" {
			continue
		}
		for _, affected := range entry.Affected {
			eco := affected.Package.Ecosystem
			name := affected.Package.Name
			for _, r := range affected.Ranges {
				if r.Type != "ECOSYSTEM" && r.Type != "" {
					continue
				}
				introduced, fixed := r.bounds()
				out = append(out, domain.VendorVEXAssertion{
					AdvisoryID:  entry.ID,
					Feed:        feed,
					CVEID:       cveID,
					Ecosystem:   eco,
					PackageName: name,
					Status:      domain.VEXStatusAffected,
					Introduced:  introduced,
					Fixed:       fixed,
				})
			}
		}
	}
	return out, nil
}

type osvEntry struct {
	ID         string         `json:"id"`
	Aliases    []string       `json:"aliases"`
	Affected   []osvAffected  `json:"affected"`
}

func (e osvEntry) firstCVE() string {
	for _, alias := range e.Aliases {
		if normalized := domain.NormalizeCVEID(alias); strings.HasPrefix(strings.ToUpper(normalized), "CVE-") {
			return normalized
		}
	}
	return domain.NormalizeCVEID(e.ID)
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []osvRange `json:"ranges"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type osvEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

func (r osvRange) bounds() (introduced, fixed string) {
	for _, ev := range r.Events {
		if ev.Introduced != "" {
			introduced = ev.Introduced
		}
		if ev.Fixed != "" {
			fixed = ev.Fixed
		}
	}
	return introduced, fixed
}
