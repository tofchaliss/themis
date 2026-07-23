package observability

import (
	"net/http"
	"time"

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

			l.Info("http request",
				String("method", r.Method),
				String("path", r.URL.Path),
				Int("status", sw.status),
				Duration("duration", time.Since(start)),
				String("correlation_id", cid),
			)
		})
	}
}
