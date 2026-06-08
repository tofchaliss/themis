package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/themis-project/themis/internal/adapter/api/gen"
	apimiddleware "github.com/themis-project/themis/internal/adapter/api/middleware"
)

// MountConfig configures API route mounting.
type MountConfig struct {
	Handler       *Handler
	APIKeyAuth    apimiddleware.APIKeyAuth
	WebhookAuth   apimiddleware.WebhookAuth
	MaxUploadSize int64
}

// Mount registers /api/v1 routes on the router.
func Mount(r chi.Router, cfg MountConfig) {
	wrapped := &webhookServer{Handler: cfg.Handler, webhook: cfg.WebhookAuth}
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(apimiddleware.MaxBytes(cfg.MaxUploadSize))
		r.Use(cfg.APIKeyAuth.Middleware)
		gen.HandlerFromMux(wrapped, r)
	})
}

type webhookServer struct {
	*Handler
	webhook apimiddleware.WebhookAuth
}

func (s *webhookServer) WebhookScan(w http.ResponseWriter, r *http.Request) {
	s.webhook.Middleware(http.HandlerFunc(s.Handler.WebhookScan)).ServeHTTP(w, r)
}

// Ensure webhookServer implements the generated interface.
var _ gen.ServerInterface = (*webhookServer)(nil)
