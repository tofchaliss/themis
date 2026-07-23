package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	xff := httptest.NewRequest(http.MethodGet, "/", nil)
	xff.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	if got := ClientIP(xff); got != "203.0.113.7" {
		t.Fatalf("xff = %q, want 203.0.113.7", got)
	}

	badXFF := httptest.NewRequest(http.MethodGet, "/", nil)
	badXFF.Header.Set("X-Forwarded-For", "not-an-ip")
	badXFF.RemoteAddr = "198.51.100.9:4567"
	if got := ClientIP(badXFF); got != "198.51.100.9" {
		t.Fatalf("fallback = %q, want 198.51.100.9", got)
	}

	noPort := httptest.NewRequest(http.MethodGet, "/", nil)
	noPort.RemoteAddr = "192.0.2.5"
	if got := ClientIP(noPort); got != "192.0.2.5" {
		t.Fatalf("noport = %q, want 192.0.2.5", got)
	}

	garbage := httptest.NewRequest(http.MethodGet, "/", nil)
	garbage.RemoteAddr = "garbage"
	if got := ClientIP(garbage); got != "" {
		t.Fatalf("garbage = %q, want empty", got)
	}
}

func TestClientIPContext(t *testing.T) {
	ctx := WithClientIP(context.Background(), "10.1.2.3")
	if ClientIPFromContext(ctx) != "10.1.2.3" {
		t.Fatal("ip not stored")
	}
	if ClientIPFromContext(WithClientIP(context.Background(), "")) != "" {
		t.Fatal("empty ip should be a no-op")
	}
	if ClientIPFromContext(context.Background()) != "" {
		t.Fatal("missing ip should be empty")
	}
}
