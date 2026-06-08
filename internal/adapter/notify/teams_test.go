package notify

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostTeamsWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	status, err := defaultHTTPPoster(context.Background(), http.DefaultClient, server.URL, []byte(`{}`))
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
}

func TestPostTeamsWebhookMissingURL(t *testing.T) {
	err := postTeamsWebhook(context.Background(), http.DefaultClient, "", map[string]any{}, defaultHTTPPoster)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestDefaultHTTPPosterInvalidURL(t *testing.T) {
	_, err := defaultHTTPPoster(context.Background(), http.DefaultClient, ":", []byte(`{}`))
	if err == nil {
		t.Fatal("expected invalid URL error")
	}
}

func TestDefaultHTTPPosterDoError(t *testing.T) {
	client := &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("network down")
	})}
	_, err := defaultHTTPPoster(context.Background(), client, "http://example.com", []byte(`{}`))
	if err == nil {
		t.Fatal("expected do error")
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestPostTeamsWebhookPosterError(t *testing.T) {
	err := postTeamsWebhook(context.Background(), http.DefaultClient, "http://example.com", map[string]any{"type": "message"}, func(context.Context, *http.Client, string, []byte) (int, error) {
		return 0, errors.New("post failed")
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPostTeamsWebhookMarshalError(t *testing.T) {
	orig := marshalTeamsPayload
	marshalTeamsPayload = func(map[string]any) ([]byte, error) { return nil, errors.New("marshal") }
	t.Cleanup(func() { marshalTeamsPayload = orig })
	err := postTeamsWebhook(context.Background(), http.DefaultClient, "http://example.com", map[string]any{"x": "y"}, defaultHTTPPoster)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPostTeamsWebhookNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	err := postTeamsWebhook(context.Background(), http.DefaultClient, server.URL, map[string]any{"type": "message"}, defaultHTTPPoster)
	if err == nil {
		t.Fatal("expected error")
	}
}
