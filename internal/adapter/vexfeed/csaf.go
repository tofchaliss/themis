package vexfeed

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

// ParseCSAFAdvisory extracts vendor VEX assertions from a Red Hat CSAF 2.0 document.
func ParseCSAFAdvisory(raw []byte, advisoryID string) ([]domain.VendorVEXAssertion, error) {
	var doc csafDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse csaf: %w", err)
	}
	if doc.Document.Tracking.ID == "" && advisoryID == "" {
		return nil, fmt.Errorf("csaf advisory missing tracking.id")
	}
	if doc.Document.Tracking.ID == "" {
		doc.Document.Tracking.ID = advisoryID
	}
	id := doc.Document.Tracking.ID

	var out []domain.VendorVEXAssertion
	for _, vuln := range doc.Vulnerabilities {
		cveID := strings.TrimSpace(vuln.CVE)
		if cveID == "" {
			continue
		}
		for _, prod := range vuln.ProductStatus {
			for _, branch := range prod.Branches {
				purl := strings.TrimSpace(branch.Product.ID)
				if purl == "" {
					continue
				}
				status := mapCSAFCategory(prod.Category)
				out = append(out, domain.VendorVEXAssertion{
					AdvisoryID:    id,
					Feed:          "rhel",
					CVEID:         cveID,
					ComponentPURL: purl,
					Status:        status,
					Justification: prod.Category,
				})
			}
		}
	}
	return out, nil
}

func mapCSAFCategory(category string) string {
	switch strings.ToLower(category) {
	case "fixed", "known_not_affected", "known affected":
		return domain.VEXStatusNotAffected
	case "known_affected", "affected":
		return domain.VEXStatusAffected
	default:
		if strings.Contains(strings.ToLower(category), "not_affected") {
			return domain.VEXStatusNotAffected
		}
		return domain.VEXStatusAffected
	}
}

type csafDocument struct {
	Document struct {
		Tracking struct {
			ID string `json:"id"`
		} `json:"tracking"`
	} `json:"document"`
	Vulnerabilities []csafVulnerability `json:"vulnerabilities"`
}

type csafVulnerability struct {
	CVE           string             `json:"cve"`
	ProductStatus []csafProductGroup `json:"product_status"`
}

type csafProductGroup struct {
	Category string        `json:"category"`
	Branches []csafBranch  `json:"branches"`
}

type csafBranch struct {
	Product struct {
		ID string `json:"product_id"`
	} `json:"product"`
}

// ParseCSAFAdvisoryVulnerabilities parses CSAF using vulnerabilities[].product_status map form.
func ParseCSAFAdvisoryVulnerabilities(raw []byte, advisoryID string) ([]domain.VendorVEXAssertion, error) {
	var doc csafDocumentAlt
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse csaf: %w", err)
	}
	id := doc.Document.Tracking.ID
	if id == "" {
		id = advisoryID
	}
	if id == "" {
		return nil, fmt.Errorf("csaf advisory missing tracking.id")
	}

	var out []domain.VendorVEXAssertion
	for _, vuln := range doc.Vulnerabilities {
		cveID := strings.TrimSpace(vuln.CVE)
		if cveID == "" {
			continue
		}
		for category, productIDs := range vuln.ProductStatus {
			status := mapCSAFCategory(category)
			for _, pid := range productIDs {
				purl := strings.TrimSpace(pid)
				if purl == "" {
					continue
				}
				out = append(out, domain.VendorVEXAssertion{
					AdvisoryID:    id,
					Feed:          "rhel",
					CVEID:         cveID,
					ComponentPURL: purl,
					Status:        status,
					Justification: category,
				})
			}
		}
	}
	return out, nil
}

type csafDocumentAlt struct {
	Document struct {
		Tracking struct {
			ID string `json:"id"`
		} `json:"tracking"`
	} `json:"document"`
	Vulnerabilities []struct {
		CVE            string              `json:"cve"`
		ProductStatus  map[string][]string `json:"product_status"`
	} `json:"vulnerabilities"`
}

// ParseCSAF tries both CSAF shapes.
func ParseCSAF(raw []byte, advisoryID string) ([]domain.VendorVEXAssertion, error) {
	out, err := ParseCSAFAdvisoryVulnerabilities(raw, advisoryID)
	if err == nil && len(out) > 0 {
		return out, nil
	}
	return ParseCSAFAdvisory(raw, advisoryID)
}
