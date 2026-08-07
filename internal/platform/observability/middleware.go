package observability

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// CorrelationHeader carries a cross-node correlation id so a workflow can be reconstructed
// across services (R1 · BCK-0051).
const CorrelationHeader = "X-Correlation-ID"

// statusWriter captures the response status code for request logging.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.status = http.StatusOK
		w.wrote = true
	}
	return w.ResponseWriter.Write(b)
}

// RequestLogger logs one structured record per HTTP request (method, path, status, duration,
// correlation id) through the shared logger, so every API component is observed uniformly on
// both channels (R1). It derives or propagates a correlation id and echoes it on the response.
func RequestLogger(l *Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			cid := r.Header.Get(CorrelationHeader)
			if cid == "" {
				cid = uuid.NewString()
			}
			w.Header().Set(CorrelationHeader, cid)

			// A span per request — the third R1 signal. Started unconditionally: with no OTLP
			// endpoint the global provider is a no-op costing a few nanoseconds, and making
			// instrumentation conditional is how instrumentation rots.
			//
			// The span carries the CORRELATION ID, which is what makes traces and logs joinable.
			// A trace nobody can line up against a log line answers "where did the time go" but
			// not "what happened to MY request" — and today's debugging needed the second.
			ctx, span := Tracer("themis/http").Start(r.Context(), r.Method,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					attribute.String("http.request.method", r.Method),
					attribute.String("themis.correlation_id", cid),
				))
			defer span.End()

			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r.WithContext(ctx))

			// The route TEMPLATE is only known AFTER routing — chi fills its RouteContext as the
			// request descends the tree, which is why the metrics call below reads it here too.
			// So the span is named provisionally and RENAMED once the pattern exists; naming it
			// up front produced "GET other" for every request, collapsing every endpoint into one
			// span name and making the traces useless for exactly the question they answer.
			route := routePattern(r)
			span.SetName(r.Method + " " + route)
			span.SetAttributes(
				attribute.String("http.route", route),
				attribute.Int("http.response.status_code", sw.status),
			)
			// A 5xx marks the span as failed so a trace backend can surface it without a query
			// that already knows which statuses matter. A 4xx does NOT: a rejected request is the
			// server working, and marking it an error is how error rates stop meaning anything.
			if sw.status >= 500 {
				span.SetStatus(codes.Error, http.StatusText(sw.status))
			}

			d := time.Since(start)
			l.Info("http request",
				String("method", r.Method),
				String("path", r.URL.Path),
				Int("status", sw.status),
				Duration("duration", d),
				String("correlation_id", cid),
			)
			// The same request, counted. The log line answers "what happened to this request";
			// the counter answers "what is happening to requests" — error RATE and latency
			// distribution, which no volume of individual lines gives you.
			//
			// routePattern, not r.URL.Path: the raw path embeds ids, and a per-id metric label
			// is unbounded cardinality — the classic way to take down a metrics backend.
			Default().RecordHTTPRequest(r.Method, routePattern(r), sw.status, d)
		})
	}
}

// routePattern returns the chi route TEMPLATE (e.g. "/findings/{id}") rather than the concrete
// path, so a million Finding ids collapse into one time series instead of a million. Falls back
// to "other" when no pattern is available, which is safer than falling back to the raw path:
// an unbounded label is worse than a coarse one.
func routePattern(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		if p := rc.RoutePattern(); p != "" {
			return p
		}
	}
	return "other"
}
