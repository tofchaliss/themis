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
	// Middleware runs on /api/v1 only, before auth and handlers.
	Middleware []func(http.Handler) http.Handler
}

// Mount registers /api/v1 routes on the router.
func Mount(r chi.Router, cfg MountConfig) {
	wrapped := &webhookServer{Handler: cfg.Handler, webhook: cfg.WebhookAuth}
	r.Route("/api/v1", func(r chi.Router) {
		for _, mw := range cfg.Middleware {
			r.Use(mw)
		}
		r.Use(apimiddleware.MaxBytes(cfg.MaxUploadSize))
		r.Use(cfg.APIKeyAuth.Middleware)
		gen.HandlerFromMux(wrapped, r)
		r.Post("/products/{id}/microservices", cfg.Handler.CreateMicroservice)
		r.Post("/microservices/{id}/deployments", cfg.Handler.CreateDeployment)
		r.Post("/customers", cfg.Handler.CreateCustomer)
		r.Get("/products/{id}/blast-radius", cfg.Handler.GetProductBlastRadius)
		r.Get("/products/{id}/versions/{v}/vex", cfg.Handler.GetProductVersionVEX)
		r.Get("/products/{id}/versions/{v}/vex-coverage", cfg.Handler.GetProductVersionVEXCoverage)
		r.Get("/status", cfg.Handler.GetStatus)
		r.Get("/sboms", cfg.Handler.ListSBOMs)
		r.Get("/products/{id}/sboms", cfg.Handler.ListProductSBOMs)
		r.Delete("/sboms/{id}", cfg.Handler.DeleteSBOM)
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
