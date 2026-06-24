package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

const defaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// ClientConfig configures the NVD HTTP client.
type ClientConfig struct {
	BaseURL      string
	APIKey       string
	HTTPClient   *http.Client
	RateLimiter  *TokenBucket
	ResultsLimit int
}

// Client fetches CVE records from the NVD REST API.
type Client struct {
	baseURL      string
	apiKey       string
	httpClient   *http.Client
	limiter      *TokenBucket
	resultsLimit int
}

// NewClient creates an NVD feed client with token-bucket rate limiting.
func NewClient(cfg ClientConfig) *Client {
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	limiter := cfg.RateLimiter
	if limiter == nil {
		limiter = NewTokenBucket(5, 5)
	}
	limit := cfg.ResultsLimit
	if limit <= 0 {
		limit = 2000
	}
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		apiKey:       cfg.APIKey,
		httpClient:   httpClient,
		limiter:      limiter,
		resultsLimit: limit,
	}
}

// FetchModifiedSince returns CVEs modified after since.
func (c *Client) FetchModifiedSince(ctx context.Context, since time.Time) ([]domain.FeedVulnerability, error) {
	if since.IsZero() {
		since = time.Now().UTC().Add(-30 * 24 * time.Hour)
	}
	end := time.Now().UTC()
	var all []domain.FeedVulnerability
	for startIndex := 0; ; startIndex += c.resultsLimit {
		page, total, err := c.fetchPage(ctx, since, end, startIndex)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if startIndex+c.resultsLimit >= total {
			break
		}
	}
	return all, nil
}

// FetchByCVEID fetches a single CVE's CVSS verdict from the NVD by-ID endpoint
// (/cves/2.0?cveId=…). The bool is false when NVD has no record (or no usable
// CVSS) for the ID, so the CR-5 backfill can mark it checked and retry later.
func (c *Client) FetchByCVEID(ctx context.Context, cveID string) (domain.CVSSData, bool, error) {
	cveID = strings.TrimSpace(cveID)
	if cveID == "" {
		return domain.CVSSData{}, false, nil
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return domain.CVSSData{}, false, err
	}

	query := url.Values{}
	query.Set("cveId", cveID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"?"+query.Encode(), nil)
	if err != nil {
		return domain.CVSSData{}, false, err
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return domain.CVSSData{}, false, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return domain.CVSSData{}, false, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return domain.CVSSData{}, false, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return domain.CVSSData{}, false, fmt.Errorf("nvd api status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload nvdResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return domain.CVSSData{}, false, fmt.Errorf("decode nvd response: %w", err)
	}
	if len(payload.Vulnerabilities) == 0 {
		return domain.CVSSData{}, false, nil
	}
	severity, score, vector := extractNVDCVSS(payload.Vulnerabilities[0].CVE)
	if score <= 0 && severity == "unknown" {
		return domain.CVSSData{}, false, nil
	}
	return domain.CVSSData{Severity: severity, Score: score, Vector: vector}, true, nil
}

func (c *Client) fetchPage(ctx context.Context, since, end time.Time, startIndex int) ([]domain.FeedVulnerability, int, error) {
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, 0, err
	}

	query := url.Values{}
	query.Set("lastModStartDate", since.UTC().Format("2006-01-02T15:04:05.000"))
	query.Set("lastModEndDate", end.UTC().Format("2006-01-02T15:04:05.000"))
	query.Set("startIndex", fmt.Sprintf("%d", startIndex))
	query.Set("resultsPerPage", fmt.Sprintf("%d", c.resultsLimit))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"?"+query.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, 0, fmt.Errorf("nvd api status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload nvdResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, 0, fmt.Errorf("decode nvd response: %w", err)
	}

	out := make([]domain.FeedVulnerability, 0, len(payload.Vulnerabilities))
	for _, item := range payload.Vulnerabilities {
		out = append(out, mapNVDCVE(item.CVE)...)
	}
	return out, payload.TotalResults, nil
}

type nvdResponse struct {
	TotalResults      int `json:"totalResults"`
	Vulnerabilities   []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID              string `json:"id"`
	Configurations  []struct {
		Nodes []struct {
			CPEMatch []cpeMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	Metrics struct {
		CVSSMetricV31 []nvdCVSSMetricV3 `json:"cvssMetricV31"`
		CVSSMetricV30 []nvdCVSSMetricV3 `json:"cvssMetricV30"`
		CVSSMetricV2  []nvdCVSSMetricV2 `json:"cvssMetricV2"`
	} `json:"metrics"`
}

type nvdCVSSMetricV3 struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type nvdCVSSMetricV2 struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

type cpeMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

func mapNVDCVE(cve nvdCVE) []domain.FeedVulnerability {
	severity, score, vector := extractNVDCVSS(cve)

	var out []domain.FeedVulnerability
	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				if !match.Vulnerable {
					continue
				}
				ecosystem, name := parseCPEPackage(match.Criteria)
				if name == "" {
					continue
				}
				affected := cpeAffectedVersions(match)
				out = append(out, domain.FeedVulnerability{
					CVEID:            cve.ID,
					Severity:         severity,
					CVSSScore:        score,
					CVSSVector:       vector,
					Ecosystem:        ecosystem,
					PackageName:      name,
					AffectedVersions: affected,
					Source:           domain.FindingSourceNVD,
				})
			}
		}
	}
	if len(out) == 0 {
		out = append(out, domain.FeedVulnerability{
			CVEID:            cve.ID,
			Severity:         severity,
			CVSSScore:        score,
			CVSSVector:       vector,
			AffectedVersions: []string{"unknown"},
			Source:           domain.FindingSourceNVD,
		})
	}
	return out
}

// extractNVDCVSS reads CVSS severity/score/vector in precedence order
// v3.1 → v3.0 → v2.0, taking the first metric present. Previously only
// cvssMetricV31 was read, so CVEs scored solely under v3.0 or v2.0 came back
// severity=unknown/score=0 even though NVD had scored them (D-NVD-1 Finding 3).
func extractNVDCVSS(cve nvdCVE) (severity string, score float64, vector string) {
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		m := cve.Metrics.CVSSMetricV31[0].CVSSData
		return normalizeNVDSeverity(m.BaseSeverity, m.BaseScore), m.BaseScore, m.VectorString
	}
	if len(cve.Metrics.CVSSMetricV30) > 0 {
		m := cve.Metrics.CVSSMetricV30[0].CVSSData
		return normalizeNVDSeverity(m.BaseSeverity, m.BaseScore), m.BaseScore, m.VectorString
	}
	if len(cve.Metrics.CVSSMetricV2) > 0 {
		m := cve.Metrics.CVSSMetricV2[0]
		return normalizeNVDSeverity(m.BaseSeverity, m.CVSSData.BaseScore), m.CVSSData.BaseScore, m.CVSSData.VectorString
	}
	return "unknown", 0, ""
}

// normalizeNVDSeverity lowercases the NVD base severity, deriving it from the
// base score when absent (CVSS v2 metrics often omit a textual severity).
func normalizeNVDSeverity(baseSeverity string, score float64) string {
	if s := strings.ToLower(strings.TrimSpace(baseSeverity)); s != "" {
		return s
	}
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

func parseCPEPackage(criteria string) (ecosystem, name string) {
	parts := strings.Split(criteria, ":")
	if len(parts) < 5 {
		return "", ""
	}
	vendor := parts[3]
	product := parts[4]
	if product == "*" || product == "-" {
		return "", ""
	}
	return cpeVendorToEcosystem(vendor), product
}

func cpeVendorToEcosystem(vendor string) string {
	switch strings.ToLower(vendor) {
	case "npm", "nodejs":
		return "npm"
	case "apache", "maven":
		return "maven"
	case "python", "pypi":
		return "pypi"
	case "golang", "go":
		return "go"
	default:
		// Do not fabricate an ecosystem. An unmapped vendor yields "" so
		// domain.PackageIdentityMatch falls back to name-only matching instead of
		// the old vendor==product → "npm" guess that misrouted openssl:openssl
		// (and every other self-named product) into the npm ecosystem.
		return ""
	}
}

// cpeAffectedVersions builds the affected-version constraints for a CPE match as
// a SINGLE comma-joined AND group via the unified engine (CR-1). The previous
// implementation dropped the lower bound whenever an upper bound existed and
// appended bounds as separate OR slice elements, so "[2.0, 2.5)" collapsed to
// "< 2.5" and matched every 1.x/0.x version (D-NVD-1 Finding 1). It now also
// honours versionStartExcluding (exclusive lower bound).
func cpeAffectedVersions(match cpeMatch) []string {
	group := domain.BuildConstraintGroup(
		match.VersionStartIncluding,
		match.VersionStartExcluding,
		match.VersionEndIncluding,
		match.VersionEndExcluding,
	)
	if group == "" {
		// No version bounds → the product is affected at all versions.
		return []string{"unknown"}
	}
	return []string{group}
}
