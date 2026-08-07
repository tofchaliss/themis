package feed

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// CSAF 2.0 VEX parsing (parity B4). A vendor CSAF-VEX document states, per CVE, which products
// are `known_not_affected`. The hard part — and where the legacy naive parser produced nothing —
// is resolving a `product_status` product-id back to a package name: real CSAF keeps the PURL in
// the `product_tree` (branches / full_product_names / relationships), not in `product_status`.
// This parser walks the product tree to build a product-id → PURL map, then maps each
// not_affected product-id to the package name its PURL carries. A product-id it cannot resolve
// to a PURL is skipped — conservative, so we never emit a garbage suppression statement.

// csafStatement is one resolved not_affected applicability from a CSAF-VEX document.
type csafStatement struct {
	CVE           value.CVEID
	Package       string
	Justification string
	ObservedAt    time.Time
}

type csafDocument struct {
	Document struct {
		Tracking struct {
			ID                 string `json:"id"`
			CurrentReleaseDate string `json:"current_release_date"`
			InitialReleaseDate string `json:"initial_release_date"`
		} `json:"tracking"`
	} `json:"document"`
	ProductTree     csafProductTree     `json:"product_tree"`
	Vulnerabilities []csafVulnerability `json:"vulnerabilities"`
}

type csafProductTree struct {
	Branches         []csafBranch          `json:"branches"`
	Relationships    []csafRelationship    `json:"relationships"`
	FullProductNames []csafFullProductName `json:"full_product_names"`
}

type csafBranch struct {
	Category string          `json:"category"`
	Name     string          `json:"name"`
	Product  *csafProductRef `json:"product"`
	Branches []csafBranch    `json:"branches"`
}

type csafProductRef struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
	Helper    *struct {
		PURL string `json:"purl"`
	} `json:"product_identification_helper"`
}

type csafFullProductName = csafProductRef

type csafRelationship struct {
	Category        string              `json:"category"`
	ProductRef      string              `json:"product_reference"`
	RelatesTo       string              `json:"relates_to_product_reference"`
	FullProductName csafFullProductName `json:"full_product_name"`
}

type csafVulnerability struct {
	CVE           string `json:"cve"`
	ProductStatus struct {
		KnownNotAffected []string `json:"known_not_affected"`
	} `json:"product_status"`
}

// parseCSAFVEX parses a CSAF 2.0 VEX document into per-(CVE, package) not_affected statements. A
// malformed document is an error; individual unresolvable products are skipped, not fatal.
func parseCSAFVEX(raw []byte) ([]csafStatement, error) {
	var doc csafDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("csaf: invalid json: %w", err)
	}
	observedAt, ok := parseCSAFDate(doc.Document.Tracking.CurrentReleaseDate, doc.Document.Tracking.InitialReleaseDate)
	if !ok {
		return nil, nil // no reconcilable release date — skip the document defensively
	}

	// product-id → PURL, walked from every place CSAF may carry it.
	purls := map[string]string{}
	collectBranchPURLs(doc.ProductTree.Branches, purls)
	for _, fpn := range doc.ProductTree.FullProductNames {
		addPURL(purls, fpn)
	}
	for _, rel := range doc.ProductTree.Relationships {
		addPURL(purls, rel.FullProductName)
	}

	justification := "CSAF VEX: not affected"
	if id := strings.TrimSpace(doc.Document.Tracking.ID); id != "" {
		justification += " (" + id + ")"
	}

	var out []csafStatement
	for _, v := range doc.Vulnerabilities {
		cve, err := value.NewCVEID(strings.TrimSpace(v.CVE))
		if err != nil {
			continue // a vulnerability entry without a canonical CVE — skip
		}
		seen := map[string]struct{}{}
		for _, pid := range v.ProductStatus.KnownNotAffected {
			pkg := packageOfProduct(pid, purls)
			if pkg == "" {
				continue // unresolvable product-id → skip (never emit a garbage suppression)
			}
			if _, dup := seen[pkg]; dup {
				continue
			}
			seen[pkg] = struct{}{}
			out = append(out, csafStatement{CVE: cve, Package: pkg, Justification: justification, ObservedAt: observedAt})
		}
	}
	return out, nil
}

// collectBranchPURLs walks the product_tree branches recursively, recording every product's PURL.
func collectBranchPURLs(branches []csafBranch, purls map[string]string) {
	for _, b := range branches {
		if b.Product != nil {
			addPURL(purls, *b.Product)
		}
		collectBranchPURLs(b.Branches, purls)
	}
}

func addPURL(purls map[string]string, p csafProductRef) {
	if p.ProductID == "" || p.Helper == nil {
		return
	}
	if purl := strings.TrimSpace(p.Helper.PURL); purl != "" {
		purls[p.ProductID] = purl
	}
}

// packageOfProduct resolves a product-id to a bare package name via its PURL (the reliable
// carrier). Returns "" when the product-id has no resolvable PURL.
func packageOfProduct(productID string, purls map[string]string) string {
	if purl, ok := purls[productID]; ok {
		return purlPackageName(purl)
	}
	return ""
}

// purlPackageName extracts the package name from a PURL: the last "/"-segment before the "@"
// version (e.g. "pkg:rpm/redhat/openssl@1.0.2k-16.el8_10?arch=x86_64" → "openssl").
func purlPackageName(purl string) string {
	s := value.StripVersionQualifiers(strings.TrimSpace(purl)) // drop ?qualifier / #subpath
	if at := strings.IndexByte(s, '@'); at >= 0 {
		s = s[:at]
	}
	if slash := strings.LastIndexByte(s, '/'); slash >= 0 {
		s = s[slash+1:]
	}
	return strings.TrimSpace(s)
}

// parseCSAFDate parses the first parseable RFC 3339 date among the candidates.
func parseCSAFDate(candidates ...string) (time.Time, bool) {
	for _, c := range candidates {
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(c)); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
