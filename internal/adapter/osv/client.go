package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/domain"
)

const defaultBaseURL = "https://api.osv.dev/v1/querybatch"

// ClientConfig configures the OSV HTTP client.
type ClientConfig struct {
	BaseURL     string
	HTTPClient  *http.Client
	RateLimiter *TokenBucket
}

// Client queries the OSV batch API.
type Client struct {
	baseURL    string
	httpClient *http.Client
	limiter    *TokenBucket
}

// NewClient creates an OSV feed client with token-bucket rate limiting.
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
		limiter = NewTokenBucket(10, 10)
	}
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
		limiter:    limiter,
	}
}

// QueryByEcosystem batch-queries OSV for packages in an ecosystem.
func (c *Client) QueryByEcosystem(ctx context.Context, ecosystem string, packages []domain.OSVPackageQuery) ([]domain.FeedVulnerability, error) {
	if len(packages) == 0 {
		return nil, nil
	}
	osvEco, ok := MapEcosystem(ecosystem)
	if !ok {
		return nil, nil
	}
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, err
	}

	reqBody := batchRequest{Queries: make([]batchQuery, 0, len(packages))}
	for _, pkg := range packages {
		reqBody.Queries = append(reqBody.Queries, batchQuery{
			Package: packageRef{
				Ecosystem: osvEco,
				Name:      normalizePackageName(ecosystem, pkg.Name),
			},
		})
	}
	encoded, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("osv api status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload batchResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decode osv response: %w", err)
	}

	var out []domain.FeedVulnerability
	for i, result := range payload.Results {
		name := packages[i].Name
		for _, vuln := range result.Vulns {
			out = append(out, mapOSVVuln(vuln, ecosystem, name))
		}
	}
	return out, nil
}

type batchRequest struct {
	Queries []batchQuery `json:"queries"`
}

type batchQuery struct {
	Package packageRef `json:"package"`
}

type packageRef struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

type batchResponse struct {
	Results []struct {
		Vulns []osvVuln `json:"vulns"`
	} `json:"results"`
}

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

func mapOSVVuln(vuln osvVuln, ecosystem, packageName string) domain.FeedVulnerability {
	score, vector := extractCVSSFromSeverity(vuln.Severity)
	severity := severityFromScore(score)

	affected := extractAffectedVersions(vuln)
	fixes := extractFixVersions(vuln)
	if len(affected) == 0 {
		affected = []string{"unknown"}
	}

	return domain.FeedVulnerability{
		CVEID:            resolveCVEID(vuln),
		Severity:         severity,
		CVSSScore:        score,
		CVSSVector:       vector,
		Ecosystem:        ecosystem,
		PackageName:      packageName,
		AffectedVersions: affected,
		FixVersions:      fixes,
	}
}

func resolveCVEID(vuln osvVuln) string {
	for _, alias := range vuln.Aliases {
		normalized := domain.NormalizeCVEID(alias)
		if strings.HasPrefix(strings.ToUpper(normalized), "CVE-") {
			return normalized
		}
	}
	return domain.NormalizeCVEID(vuln.ID)
}

func extractAffectedVersions(vuln osvVuln) []string {
	var affected []string
	for _, item := range vuln.Affected {
		if len(item.Versions) > 0 {
			affected = append(affected, item.Versions...)
		}
		for _, rng := range item.Ranges {
			for _, event := range rng.Events {
				if event.Introduced != "" && event.Fixed != "" {
					affected = append(affected, ">= "+event.Introduced, "< "+event.Fixed)
				} else if event.Fixed != "" {
					affected = append(affected, "< "+event.Fixed)
				} else if event.LastAffected != "" {
					affected = append(affected, "<= "+event.LastAffected)
				}
			}
		}
	}
	return affected
}

func extractFixVersions(vuln osvVuln) []string {
	var fixes []string
	for _, item := range vuln.Affected {
		for _, rng := range item.Ranges {
			for _, event := range rng.Events {
				if event.Fixed != "" && event.Fixed != "0" {
					fixes = append(fixes, event.Fixed)
				}
			}
		}
	}
	return fixes
}
