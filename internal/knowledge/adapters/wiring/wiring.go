// Package wiring is the Knowledge context's composition helper for the read API: it
// builds the read-side REST handler over a pgx pool and returns it plus the Store for
// operational tasks (outbox relay, reconciler, dev purge). The Postgres Store
// implements the read ports (Repository + ProjectionReader) directly.
package wiring

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	knhttp "github.com/themis-project/themis/internal/knowledge/adapters/http"
	"github.com/themis-project/themis/internal/knowledge/adapters/store"
	"github.com/themis-project/themis/internal/knowledge/app"
)

// KnowledgeReadAPI wires the Knowledge read service over the given pool and returns the
// REST handler (routes under /faultlines — mount it under /api/v1) plus the Store.
func KnowledgeReadAPI(pool *pgxpool.Pool) (http.Handler, *store.Store) {
	st := store.New(pool)
	read := app.NewReadService(st, st)
	return knhttp.NewHandler(read).Router(), st
}
