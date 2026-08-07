package observability

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
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

			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)

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
