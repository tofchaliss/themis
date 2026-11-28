package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Reporter tells Themis what became of a request (D28 item 2).
type Reporter interface {
	Report(ctx context.Context, rec Record) error
}

// ThemisReporter makes the status call: POST to the callback address with the API key of scope
// delivery:callback. The key is sent in the header and never logged.
type ThemisReporter struct {
	URL    string
	APIKey string
	Client *http.Client
}

// NewThemisReporter wires the reporter.
func NewThemisReporter(url, apiKey string, timeout time.Duration) *ThemisReporter {
	return &ThemisReporter{URL: url, APIKey: apiKey, Client: &http.Client{Timeout: timeout}}
}

// Report sends the end state of the record. Themis takes a repeated report of the same state
// for the same intent id as a no-op, so a report may be sent again until one succeeds.
func (t *ThemisReporter) Report(ctx context.Context, rec Record) error {
	body, err := json.Marshal(map[string]any{
		"intent_id": rec.IntentID, "status": rec.State, "reason": rec.Reason, "build_ref": rec.BuildRef,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", t.APIKey)
	resp, err := t.Client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("themis answered the status call with %d", resp.StatusCode)
	}
	return nil
}
