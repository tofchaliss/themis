// Package redhat is the adapter for Red Hat's public Security Data API
// (access.redhat.com/hydra/rest/securitydata). It fetches the per-CVE document
// and reduces it to a domain.RedHatCVEReport for the VEX-overlay enrichment
// service. No auth; public, rate-limited GET.
package redhat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

const defaultBaseURL = "https://access.redhat.com/hydra/rest/securitydata"

// maxAttempts bounds retries on transient (429/5xx) responses.
const maxAttempts = 3

// RateLimiter paces outbound requests (satisfied by nvd.TokenBucket).
type RateLimiter interface {
	Wait(ctx context.Context) error
}

type noopLimiter struct{}

func (noopLimiter) Wait(context.Context) error { return nil }

// ClientConfig configures the Red Hat Security Data API client.
type ClientConfig struct {
	BaseURL     string
	HTTPClient  *http.Client
	RateLimiter RateLimiter
}

// Client fetches per-CVE vendor verdicts from the Red Hat Security Data API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	limiter    RateLimiter
	sleep      func(context.Context, time.Duration) error
}

// NewClient creates a Red Hat Security Data API client.
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
		limiter = noopLimiter{}
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
		limiter:    limiter,
		sleep:      sleepContext,
	}
}

// FetchCVE returns Red Hat's verdict document for cveID. The bool is false when
// Red Hat has no record for the CVE (HTTP 404), so the caller can mark it checked
// and skip it; a transient/non-2xx status returns an error so it is retried.
func (c *Client) FetchCVE(ctx context.Context, cveID string) (domain.RedHatCVEReport, bool, error) {
	cveID = strings.TrimSpace(cveID)
	if cveID == "" {
		return domain.RedHatCVEReport{}, false, nil
	}
	url := fmt.Sprintf("%s/cve/%s.json", c.baseURL, cveID)

	var body []byte
	var status int
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if waitErr := c.limiter.Wait(ctx); waitErr != nil {
			return domain.RedHatCVEReport{}, false, waitErr
		}
		body, status, err = c.do(ctx, url)
		if err != nil {
			if attempt+1 < maxAttempts {
				if sErr := c.sleep(ctx, backoff(attempt)); sErr != nil {
					return domain.RedHatCVEReport{}, false, sErr
				}
				continue
			}
			return domain.RedHatCVEReport{}, false, err
		}
		if isTransient(status) && attempt+1 < maxAttempts {
			if sErr := c.sleep(ctx, backoff(attempt)); sErr != nil {
				return domain.RedHatCVEReport{}, false, sErr
			}
			continue
		}
		break
	}

	if status == http.StatusNotFound {
		return domain.RedHatCVEReport{}, false, nil
	}
	if status < 200 || status >= 300 {
		return domain.RedHatCVEReport{}, false, fmt.Errorf("redhat securitydata status %d for %s", status, cveID)
	}

	report, err := parseCVE(body, cveID)
	if err != nil {
		return domain.RedHatCVEReport{}, false, err
	}
	return report, true, nil
}

func (c *Client) do(ctx context.Context, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func isTransient(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func backoff(attempt int) time.Duration {
	d := time.Duration(1<<uint(attempt)) * time.Second
	if d > 15*time.Second {
		d = 15 * time.Second
	}
	return d
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// rhCVEResponse is the subset of the Red Hat Security Data API CVE document we map.
type rhCVEResponse struct {
	Name           string `json:"name"`
	ThreatSeverity string `json:"threat_severity"`
	CVSS3          struct {
		BaseScore string `json:"cvss3_base_score"`
	} `json:"cvss3"`
	Statement    string `json:"statement"`
	PackageState []struct {
		ProductName string `json:"product_name"`
		FixState    string `json:"fix_state"`
		PackageName string `json:"package_name"`
		CPE         string `json:"cpe"`
	} `json:"package_state"`
	AffectedRelease []struct {
		ProductName string `json:"product_name"`
		Package     string `json:"package"`
		CPE         string `json:"cpe"`
		Advisory    string `json:"advisory"`
	} `json:"affected_release"`
}

func parseCVE(body []byte, cveID string) (domain.RedHatCVEReport, error) {
	var raw rhCVEResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return domain.RedHatCVEReport{}, fmt.Errorf("decode redhat cve %s: %w", cveID, err)
	}
	name := raw.Name
	if name == "" {
		name = cveID
	}
	report := domain.RedHatCVEReport{
		CVEID:          name,
		ThreatSeverity: raw.ThreatSeverity,
		CVSS3:          raw.CVSS3.BaseScore,
		Statement:      strings.TrimSpace(raw.Statement),
	}
	for _, ps := range raw.PackageState {
		report.PackageStates = append(report.PackageStates, domain.RedHatPackageState{
			PackageName: ps.PackageName,
			FixState:    ps.FixState,
			CPE:         ps.CPE,
		})
	}
	for _, ar := range raw.AffectedRelease {
		report.AffectedReleases = append(report.AffectedReleases, domain.RedHatAffectedRelease{
			PackageNEVRA: ar.Package,
			CPE:          ar.CPE,
			Advisory:     ar.Advisory,
		})
	}
	return report, nil
}
