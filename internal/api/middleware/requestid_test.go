package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/api/middleware"
)

func TestRequestIDMiddleware(t *testing.T) {
	rec := middleware.ServeTest(middleware.CaptureRequestID())
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatal("expected X-Request-ID response header")
	}
	if rec.Body.String() == "" {
		t.Fatal("expected request ID in body")
	}
	if rec.Header().Get("X-Request-ID") != rec.Body.String() {
		t.Fatal("header and context request ID mismatch")
	}
}

func TestRequestIDFromContextEmpty(t *testing.T) {
	if middleware.RequestIDFromContext(t.Context()) != "" {
		t.Fatal("expected empty request ID for bare context")
	}
}

func TestRequestIDForTest(t *testing.T) {
	const want = "fixed-id"
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	middleware.RequestIDForTest(middleware.CaptureRequestID(), want).ServeHTTP(rec, req)
	if rec.Body.String() != want {
		t.Fatalf("body = %q, want %q", rec.Body.String(), want)
	}
}
