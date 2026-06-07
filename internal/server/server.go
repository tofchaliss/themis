package server

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/themis-project/themis/internal/api/middleware"
)

// ReadinessChecker provides dependencies for the readiness probe.
type ReadinessChecker struct {
	DBPing             func(ctx context.Context) error
	CVEFeedLastSuccess func() time.Time
}

// Server serves HTTP endpoints including health probes.
type Server struct {
	router     chi.Router
	logger     *zap.Logger
	readiness  ReadinessChecker
	httpServer *http.Server
}

// New creates an HTTP server with health routes and middleware.
func New(addr string, logger *zap.Logger, readiness ReadinessChecker, readTimeout, writeTimeout time.Duration) *Server {
	s := &Server{
		logger:    logger,
		readiness: readiness,
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)
	s.router = r

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	return s
}

// Start begins serving HTTP traffic.
func (s *Server) Start() error {
	s.logger.Info("starting http server", zap.String("addr", s.httpServer.Addr))
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// Handler returns the root HTTP handler (for tests).
func (s *Server) Handler() http.Handler {
	return s.router
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	checks := map[string]string{}
	status := http.StatusOK

	if s.readiness.DBPing != nil {
		if err := s.readiness.DBPing(ctx); err != nil {
			checks["database"] = err.Error()
			status = http.StatusServiceUnavailable
		} else {
			checks["database"] = "ok"
		}
	}

	if s.readiness.CVEFeedLastSuccess != nil {
		last := s.readiness.CVEFeedLastSuccess()
		if last.IsZero() {
			checks["cve_feed"] = "no successful poll yet"
			status = http.StatusServiceUnavailable
		} else {
			checks["cve_feed"] = last.UTC().Format(time.RFC3339)
		}
	}

	writeJSON(w, status, map[string]any{
		"status": statusText(status),
		"checks": checks,
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func statusText(status int) string {
	if status == http.StatusOK {
		return "ready"
	}
	return "not_ready"
}

// NewReadinessFromPool builds a ReadinessChecker from a database pool and CVE timestamp.
func NewReadinessFromPool(pool databasePool, cveLastSuccess *atomic.Value) ReadinessChecker {
	return ReadinessChecker{
		DBPing: func(ctx context.Context) error {
			return pool.Ping(ctx)
		},
		CVEFeedLastSuccess: func() time.Time {
			if cveLastSuccess == nil {
				return time.Time{}
			}
			if v := cveLastSuccess.Load(); v != nil {
				if ts, ok := v.(time.Time); ok {
					return ts
				}
			}
			return time.Time{}
		},
	}
}
