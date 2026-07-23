package provider

import (
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

// StaticRouter is the Δ1 router (Revision 2): one engine, one provider, so routing
// is trivial — it always returns the single configured provider. Δ2 replaces it with
// cost/privacy-aware selection behind the same app.Router port, touching no caller.
type StaticRouter struct {
	provider app.Provider
}

// NewStaticRouter binds the router to a single provider.
func NewStaticRouter(p app.Provider) *StaticRouter { return &StaticRouter{provider: p} }

// Select returns the single configured provider regardless of requirements.
func (r *StaticRouter) Select(_ domain.RoutingRequirements) (app.Provider, error) {
	return r.provider, nil
}
