package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

var marshalTeamsPayload = func(payload map[string]any) ([]byte, error) {
	return json.Marshal(payload)
}

const channelTypeTeams = "teams"

type httpPoster func(ctx context.Context, client *http.Client, url string, body []byte) (int, error)

func postTeamsWebhook(ctx context.Context, client *http.Client, webhookURL string, payload map[string]any, post httpPoster) error {
	if webhookURL == "" {
		return fmt.Errorf("teams webhook url not configured")
	}
	body, err := marshalTeamsPayload(payload)
	if err != nil {
		return err
	}
	status, err := post(ctx, client, webhookURL, body)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("teams webhook returned status %d", status)
	}
	return nil
}

func defaultHTTPPoster(ctx context.Context, client *http.Client, url string, body []byte) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}
