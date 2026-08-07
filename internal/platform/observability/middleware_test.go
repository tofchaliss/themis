package observability

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.uber.org/zap/zapcore"
)

// N8: a span per request, started unconditionally. With no OTLP endpoint the global provider is a
// no-op — the point is that instrumentation EXISTS whether or not anyone is collecting, because
// instrumentation added later never gets added.
func TestRequestLogger_StartsASpanCarryingTheCorrelationID(t *testing.T) {
	rec := tracetest.NewSpanRecorder()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec)))
	t.Cleanup(func() { otel.SetTracerProvider(prev) })

	log, _ := captured(zapcore.InfoLevel)
	r := chi.NewRouter()
	r.Use(RequestLogger(log))
	r.Get("/findings/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/boom", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })

	for _, path := range []string{"/findings/abc-123", "/boom"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		r.ServeHTTP(httptest.NewRecorder(), req)
	}

	spans := rec.Ended()
	if len(spans) != 2 {
		t.Fatalf("spans = %d, want 2", len(spans))
	}
	byName := map[string]sdktrace.ReadOnlySpan{}
	for _, sp := range spans {
		byName[sp.Name()] = sp
	}
	// Named by the route TEMPLATE, not the concrete path: a million Finding ids must not become a
	// million span names, for the same reason they must not become a million metric labels.
	found, ok := byName["GET /findings/{id}"]
	if !ok {
		t.Fatalf("span names = %v, want the route template", byName)
	}
	attrs := map[string]string{}
	for _, a := range found.Attributes() {
		attrs[string(a.Key)] = a.Value.AsString()
	}
	if attrs["themis.correlation_id"] == "" {
		t.Error("the span must carry the correlation id — a trace nobody can line up against a log " +
			"answers 'where did the time go' but not 'what happened to MY request'")
	}
	if attrs["http.route"] != "/findings/{id}" {
		t.Errorf("http.route = %q, want the template", attrs["http.route"])
	}
	// A 5xx marks the span failed so a backend can surface it without a query that already knows
	// which statuses matter. A 2xx must not — a rejected request is the server working.
	if byName["GET /boom"].Status().Code != codes.Error {
		t.Error("a 500 must mark the span as an error")
	}
	if found.Status().Code == codes.Error {
		t.Error("a 200 must not be marked an error")
	}
}
