package vexfeed

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const defaultMaxRetries = 3

// HTTPFetcher downloads vendor feed payloads with retry/backoff.
type HTTPFetcher struct {
	HTTPClient *http.Client
	MaxRetries int
	Sleep      func(time.Duration)
}

// Fetch retrieves a URL body, retrying 429/5xx responses.
func (f *HTTPFetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	if url == "" {
		return nil, fmt.Errorf("empty feed url")
	}
	maxRetries := f.MaxRetries
	if maxRetries <= 0 {
		maxRetries = defaultMaxRetries
	}
	sleep := f.Sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	client := f.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		body, status, err := f.fetchOnce(ctx, client, url)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if status == http.StatusTooManyRequests || status >= 500 {
			if attempt < maxRetries {
				sleep(backoffDelay(attempt))
				continue
			}
		}
		if status > 0 && status < 500 && status != http.StatusTooManyRequests {
			break
		}
	}
	return nil, lastErr
}

func (f *HTTPFetcher) fetchOnce(ctx context.Context, client *http.Client, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("vexfeed fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("vexfeed fetch %s: status %d", url, resp.StatusCode)
	}
	return body, resp.StatusCode, nil
}

func backoffDelay(attempt int) time.Duration {
	return time.Duration(attempt*attempt) * time.Second
}
