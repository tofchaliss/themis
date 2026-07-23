package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// client is a thin HTTP client for the Themis REST API. It talks to the running
// server over /api/v1 and is deliberately decoupled from the core Go module —
// the MCP server is just another API consumer.
type client struct {
	root   string // e.g. "http://localhost:8080" (no trailing slash)
	apiKey string
	hc     *http.Client
}

func newClient(baseURL, apiKey string, timeout time.Duration) *client {
	return &client{
		root:   strings.TrimRight(baseURL, "/"),
		apiKey: apiKey,
		hc:     &http.Client{Timeout: timeout},
	}
}

// apiError renders a Themis error response as a Go error. Themis uses two error
// envelopes depending on the route ({error:{code,message,hint}} for most, and
// RFC-7807 {title,detail,status} for a few), and the error code does not always
// match the HTTP status — so this parses whichever shape is present and always
// keeps the HTTP status, which is the reliable signal.
type apiError struct {
	Status  int
	Code    string
	Message string
	Hint    string
}

func (e *apiError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "themis API error (HTTP %d)", e.Status)
	if e.Code != "" {
		fmt.Fprintf(&b, " [%s]", e.Code)
	}
	if e.Message != "" {
		fmt.Fprintf(&b, ": %s", e.Message)
	}
	if e.Hint != "" {
		fmt.Fprintf(&b, " — hint: %s", e.Hint)
	}
	return b.String()
}

func parseAPIError(status int, body []byte) *apiError {
	e := &apiError{Status: status}

	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Hint    string `json:"hint"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &envelope) == nil && (envelope.Error.Code != "" || envelope.Error.Message != "") {
		e.Code = envelope.Error.Code
		e.Message = envelope.Error.Message
		e.Hint = envelope.Error.Hint
		return e
	}

	var problem struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &problem) == nil && (problem.Title != "" || problem.Detail != "") {
		e.Code = problem.Title
		e.Message = problem.Detail
		return e
	}

	msg := strings.TrimSpace(string(body))
	if len(msg) > 500 {
		msg = msg[:500] + "…"
	}
	e.Message = msg
	return e
}

// api performs a request against /api/v1 + path. On a 2xx it returns the raw
// response body; otherwise it returns an *apiError built from the response.
func (c *client) api(ctx context.Context, method, path string, query url.Values, body any, headers map[string]string) (json.RawMessage, error) {
	target := c.root + "/api/v1" + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encoding request body: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("requesting %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response from %s %s: %w", method, path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if resp.StatusCode == http.StatusUnauthorized && c.apiKey == "" {
			return nil, fmt.Errorf("themis returned 401 Unauthorized and no THEMIS_API_KEY is configured — set an API key for the MCP server")
		}
		return nil, parseAPIError(resp.StatusCode, data)
	}
	return json.RawMessage(data), nil
}

// rootGet hits a root-level endpoint (outside /api/v1, no API key) and returns
// the status and body without treating a non-2xx as an error — /readyz returns a
// meaningful 503 that the caller wants to see.
func (c *client) rootGet(ctx context.Context, path string) (int, json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.root+path, nil)
	if err != nil {
		return 0, nil, err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("requesting %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("reading response from %s: %w", path, err)
	}
	return resp.StatusCode, json.RawMessage(data), nil
}
