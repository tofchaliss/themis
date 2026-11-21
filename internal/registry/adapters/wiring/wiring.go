// Package wiring is the registry context's composition helper: it builds the REST
// handler over a pgx pool and returns it plus the Store for operational tasks (dev
// purge). Both the registry binary and tests use it, so they exercise identical
// wiring. The Postgres Store implements the application Repository port directly, so
// no adapter bridge is needed.
package wiring

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/themis-project/themis/internal/kernel/id"
	reghttp "github.com/themis-project/themis/internal/registry/adapters/http"
	"github.com/themis-project/themis/internal/registry/adapters/store"
	"github.com/themis-project/themis/internal/registry/app"
)

// RegistryAPI wires the registry application service over the given pool and returns
// the REST handler (routes under /products, /projects, /releases — mount it under
// /api/v1) plus the Store for operational tasks.
func RegistryAPI(pool *pgxpool.Pool) (http.Handler, *store.Store) {
	st := store.New(pool)
	// Security requirements (EDR-SCORING-01 S3) ride the same store and database.
	svc := app.NewRegistryService(st, idGen{}).WithRequirements(st, func() time.Time { return time.Now().UTC() })
	return reghttp.NewHandler(svc).Router(), st
}

// idGen backs the app IDGenerator port with the kernel's UUID helper.
type idGen struct{}

func (idGen) NewID() string { return id.New() }
