package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

const defaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// nvdMaxAttempts bounds retries when NVD throttles (HTTP 429/503 — the Cloudflare
// challenge page) or a transient network error occurs.
const nvdMaxAttempts = 3

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
	sleep        func(context.Context, time.Duration) error
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
		sleep:        sleepContext,
	}
}

// get performs a rate-limited GET against NVD with bounded retry/backoff on
// transient throttling (HTTP 429/503 — NVD's Cloudflare challenge — plus 502/504)
// and transient network errors, honouring Retry-After. It returns the body and
// status code; non-transient statuses (including 404) are returned to the caller
// without retry so each path can interpret them.
func (c *Client) get(ctx context.Context, reqURL string) ([]byte, int, error) {
	var lastErr error
	for attempt := 0; attempt < nvdMaxAttempts; attempt++ {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, 0, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, 0, err
		}
		if c.apiKey != "" {
			req.Header.Set("apiKey", c.apiKey)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			if attempt+1 < nvdMaxAttempts {
				if waitErr := c.sleep(ctx, backoffDelay(attempt, 0)); waitErr != nil {
					return nil, 0, waitErr
				}
				continue
			}
			return nil, 0, err
		}

		body, readErr := io.ReadAll(resp.Body)
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, resp.StatusCode, readErr
		}
		if isTransientNVDStatus(resp.StatusCode) && attempt+1 < nvdMaxAttempts {
			lastErr = nvdStatusError(resp.StatusCode, body)
			if waitErr := c.sleep(ctx, backoffDelay(attempt, retryAfter)); waitErr != nil {
				return nil, 0, waitErr
			}
			continue
		}
		return body, resp.StatusCode, nil
	}
	return nil, 0, lastErr
}

// isTransientNVDStatus reports whether an NVD response status warrants a retry.
func isTransientNVDStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable,
		http.StatusBadGateway, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

// backoffDelay returns the wait before the next attempt: Retry-After when the
// server supplied it, else exponential (1s, 2s, 4s…) capped at 30s.
func backoffDelay(attempt int, retryAfter time.Duration) time.Duration {
	if retryAfter > 0 {
		return retryAfter
	}
	d := time.Duration(1<<uint(attempt)) * time.Second
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

// parseRetryAfter reads a delta-seconds Retry-After header (NVD/Cloudflare form).
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	return 0
}

// nvdStatusError wraps a non-success NVD response, collapsing whitespace and
// truncating the body so a multi-kilobyte Cloudflare 503 challenge page does not
// flood the logs on every throttled CVE.
func nvdStatusError(status int, body []byte) error {
	snippet := strings.Join(strings.Fields(string(body)), " ")
	const maxLen = 160
	if len(snippet) > maxLen {
		snippet = snippet[:maxLen] + "…"
	}
	return fmt.Errorf("nvd api status %d: %s", status, snippet)
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

	query := url.Values{}
	query.Set("cveId", cveID)
	body, status, err := c.get(ctx, c.baseURL+"?"+query.Encode())
	if err != nil {
		return domain.CVSSData{}, false, err
	}
	if status == http.StatusNotFound {
		return domain.CVSSData{}, false, nil
	}
	if status < 200 || status >= 300 {
		return domain.CVSSData{}, false, nvdStatusError(status, body)
	}

	var payload nvdResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return domain.CVSSData{}, false, fmt.Errorf("decode nvd response: %w", err)
	}
	if len(payload.Vulnerabilities) == 0 {
		// A well-formed cveId always resolves to a record at NVD; an empty result on
		// a 2xx is a transient/throttled response (NVD returns empty 200s or
		// Cloudflare interstitials under load, especially unkeyed), not a verdict of
		// "NVD has no CVSS". Return a transient error so the CR-5 backfill retries it
		// next cycle instead of marking it checked and suppressing it for the whole
		// back-off window — which is how a throttle storm poisoned hundreds of rows.
		return domain.CVSSData{}, false, fmt.Errorf("nvd returned no record for %s (transient/throttled response)", cveID)
	}
	severity, score, vector := extractNVDCVSS(payload.Vulnerabilities[0].CVE)
	if score <= 0 && severity == "unknown" {
		// Record present but genuinely unscored (e.g. awaiting NVD analysis): a real
		// "no CVSS yet" miss, so the backfill may mark it checked and back off.
		return domain.CVSSData{}, false, nil
	}
	return domain.CVSSData{Severity: severity, Score: score, Vector: vector}, true, nil
}

func (c *Client) fetchPage(ctx context.Context, since, end time.Time, startIndex int) ([]domain.FeedVulnerability, int, error) {
	query := url.Values{}
	query.Set("lastModStartDate", since.UTC().Format("2006-01-02T15:04:05.000"))
	query.Set("lastModEndDate", end.UTC().Format("2006-01-02T15:04:05.000"))
	query.Set("startIndex", fmt.Sprintf("%d", startIndex))
	query.Set("resultsPerPage", fmt.Sprintf("%d", c.resultsLimit))

	body, status, err := c.get(ctx, c.baseURL+"?"+query.Encode())
	if err != nil {
		return nil, 0, err
	}
	if status < 200 || status >= 300 {
		return nil, 0, nvdStatusError(status, body)
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
