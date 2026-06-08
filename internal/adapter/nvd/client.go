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
		CVSSMetricV31 []struct {
			CVSSData struct {
				BaseScore     float64 `json:"baseScore"`
				VectorString  string  `json:"vectorString"`
				BaseSeverity  string  `json:"baseSeverity"`
			} `json:"cvssData"`
		} `json:"cvssMetricV31"`
	} `json:"metrics"`
}

type cpeMatch struct {
	Vulnerable          bool   `json:"vulnerable"`
	Criteria            string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

func mapNVDCVE(cve nvdCVE) []domain.FeedVulnerability {
	severity := "unknown"
	score := 0.0
	vector := ""
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		metric := cve.Metrics.CVSSMetricV31[0].CVSSData
		score = metric.BaseScore
		vector = metric.VectorString
		severity = strings.ToLower(metric.BaseSeverity)
	}

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
		})
	}
	return out
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
	return cpeVendorToEcosystem(vendor, product), product
}

func cpeVendorToEcosystem(vendor, product string) string {
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
		if vendor == product {
			return "npm"
		}
		return vendor
	}
}

func cpeAffectedVersions(match cpeMatch) []string {
	var affected []string
	if match.VersionEndExcluding != "" {
		affected = append(affected, "< "+match.VersionEndExcluding)
	}
	if match.VersionEndIncluding != "" {
		affected = append(affected, "<= "+match.VersionEndIncluding)
	}
	if match.VersionStartIncluding != "" && len(affected) == 0 {
		affected = append(affected, ">= "+match.VersionStartIncluding)
	}
	if len(affected) == 0 {
		affected = []string{"unknown"}
	}
	return affected
}
