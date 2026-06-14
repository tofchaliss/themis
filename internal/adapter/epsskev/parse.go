package epsskev

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ParseEPSSCSV reads FIRST.org EPSS CSV rows (cve,epss,percentile).
func ParseEPSSCSV(r io.Reader) (map[string]float64, error) {
	reader := csv.NewReader(r)
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read epss csv: %w", err)
	}
	out := make(map[string]float64)
	for _, row := range records {
		if len(row) == 0 {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(row[0]), "#") {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(row[0]), "cve") {
			continue
		}
		if len(row) < 2 {
			continue
		}
		cveID := strings.ToUpper(strings.TrimSpace(row[0]))
		if !strings.HasPrefix(cveID, "CVE-") {
			continue
		}
		score, err := strconv.ParseFloat(strings.TrimSpace(row[1]), 64)
		if err != nil {
			return nil, fmt.Errorf("invalid epss score for %s: %w", cveID, err)
		}
		if score < 0 || score > 1 {
			return nil, fmt.Errorf("epss score out of range for %s: %f", cveID, score)
		}
		out[cveID] = score
	}
	return out, nil
}

type kevDocument struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// ParseKEVJSON extracts CVE IDs from the CISA KEV feed.
func ParseKEVJSON(body []byte) ([]string, error) {
	var doc kevDocument
	if err := jsonUnmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse kev json: %w", err)
	}
	seen := make(map[string]struct{}, len(doc.Vulnerabilities))
	var out []string
	for _, item := range doc.Vulnerabilities {
		cveID := strings.ToUpper(strings.TrimSpace(item.CVEID))
		if cveID == "" || !strings.HasPrefix(cveID, "CVE-") {
			continue
		}
		if _, ok := seen[cveID]; ok {
			continue
		}
		seen[cveID] = struct{}{}
		out = append(out, cveID)
	}
	return out, nil
}
