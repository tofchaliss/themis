package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"

	"github.com/google/uuid"
)

type requestIDKey struct{}

// RequestIDFromContext returns the request ID stored in ctx.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey{}).(string); ok {
		return v
	}
	return ""
}

// RequestID generates a UUID per request and stores it in the request context.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.NewString()
		ctx := context.WithValue(r.Context(), requestIDKey{}, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDForTest injects a fixed request ID (used in tests).
func RequestIDForTest(next http.Handler, id string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), requestIDKey{}, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// CaptureRequestID is a test helper handler that echoes the request ID.
func CaptureRequestID() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(RequestIDFromContext(r.Context())))
	})
}

// ServeTest runs a handler through RequestID middleware.
func ServeTest(next http.Handler) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	RequestID(next).ServeHTTP(rec, req)
	return rec
}
