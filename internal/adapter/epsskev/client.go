package epsskev

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/themis-project/themis/internal/domain"
)

const defaultMaxRetries = 3

// ClientConfig configures EPSS and KEV HTTP fetchers.
type ClientConfig struct {
	EPSSURL    string
	KEVURL     string
	HTTPClient *http.Client
	MaxRetries int
	Sleep      func(time.Duration)
}

// Client implements domain.ThreatSignalFetcher.
type Client struct {
	epssURL    string
	kevURL     string
	httpClient *http.Client
	maxRetries int
	sleep      func(time.Duration)
}

// NewClient creates an EPSS/KEV feed client.
func NewClient(cfg ClientConfig) *Client {
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	maxRetries := cfg.MaxRetries
	if maxRetries <= 0 {
		maxRetries = defaultMaxRetries
	}
	sleep := cfg.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	return &Client{
		epssURL:    cfg.EPSSURL,
		kevURL:     cfg.KEVURL,
		httpClient: httpClient,
		maxRetries: maxRetries,
		sleep:      sleep,
	}
}

// FetchEPSS downloads and parses the EPSS CSV feed.
func (c *Client) FetchEPSS(ctx context.Context) ([]domain.EPSSSignal, error) {
	body, err := c.getWithRetry(ctx, c.epssURL)
	if err != nil {
		return nil, err
	}
	reader, closer, err := decompressIfGzip(body)
	if err != nil {
		return nil, err
	}
	if closer != nil {
		defer func() { _ = closer.Close() }()
	}
	scores, err := ParseEPSSCSV(reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	out := make([]domain.EPSSSignal, 0, len(scores))
	for cveID, score := range scores {
		out = append(out, domain.EPSSSignal{
			CVEID:     cveID,
			Score:     score,
			FetchedAt: now,
		})
	}
	return out, nil
}

// FetchKEV downloads and parses the CISA KEV JSON feed.
func (c *Client) FetchKEV(ctx context.Context) ([]domain.KEVSignal, error) {
	body, err := c.getWithRetry(ctx, c.kevURL)
	if err != nil {
		return nil, err
	}
	cveIDs, err := ParseKEVJSON(body)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	out := make([]domain.KEVSignal, 0, len(cveIDs))
	for _, cveID := range cveIDs {
		out = append(out, domain.KEVSignal{
			CVEID:     cveID,
			Listed:    true,
			FetchedAt: now,
		})
	}
	return out, nil
}

func (c *Client) getWithRetry(ctx context.Context, url string) ([]byte, error) {
	var lastErr error
	for attempt := 1; attempt <= c.maxRetries; attempt++ {
		body, status, err := c.getOnce(ctx, url)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if status > 0 && status < 500 {
			break
		}
		if attempt < c.maxRetries {
			c.sleep(backoffDelay(attempt))
		}
	}
	return nil, lastErr
}

func (c *Client) getOnce(ctx context.Context, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("epsskev fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("epsskev fetch %s: status %d", url, resp.StatusCode)
	}
	return body, resp.StatusCode, nil
}

func decompressIfGzip(body []byte) (io.Reader, io.Closer, error) {
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, nil, fmt.Errorf("decompress epss gzip: %w", err)
		}
		return gr, gr, nil
	}
	return bytes.NewReader(body), nil, nil
}

func backoffDelay(attempt int) time.Duration {
	return time.Duration(attempt*attempt) * time.Second
}
