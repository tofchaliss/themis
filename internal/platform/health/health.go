// Package health is the platform liveness/readiness seam (EDR-ENHANCE-T2, closing R6/F5):
// every node mounts the same two endpoints, outside the authenticated /api/v1 group, so "the
// process is up" and "the process can actually serve" become observable facts instead of
// inferences. Found the hard way on the VM (2026-08-08): a crash-looping node restarted 81
// times unnoticed, and a rotated DB password stayed invisible because pooled connections
// outlive the credential they were opened with.
//
// Like the other platform packages (observability, eventbus, auth) it is business-agnostic —
// kernel-free, context-free, drivers only — and importable only by adapters and the cmd
// composition roots.
//
//   - GET /healthz — liveness: 200 the moment the HTTP server serves. No checks; its only
//     information is that the process is up and accepting connections.
//   - GET /readyz  — readiness: runs the node's registered checks (DB reachable, migrations
//     clean, credentials still valid) and answers 200, or 503 naming every failure. A node
//     that boots but cannot serve is exactly the state R6 recorded as invisible.
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Check is one named readiness probe. Probes must be cheap and bounded — /readyz may be
// polled every few seconds by an orchestrator.
type Check struct {
	Name  string
	Probe func(ctx context.Context) error
}

// probeTimeout bounds each check so a hung dependency degrades readiness instead of hanging
// the probe endpoint itself.
const probeTimeout = 5 * time.Second

// Healthz is the liveness endpoint: serving it IS the signal.
func Healthz() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	}
}

// Readyz is the readiness endpoint over the node's checks. All pass ⇒ 200; any failure ⇒ 503
// with every failing check named — an operator must see the whole story, not the first line.
func Readyz(checks ...Check) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type failure struct {
			Name  string `json:"name"`
			Error string `json:"error"`
		}
		var failed []failure
		for _, c := range checks {
			ctx, cancel := context.WithTimeout(r.Context(), probeTimeout)
			err := c.Probe(ctx)
			cancel()
			if err != nil {
				failed = append(failed, failure{Name: c.Name, Error: err.Error()})
			}
		}
		if len(failed) > 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "degraded", "failed": failed})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
	}
}

// Pinger is the slice of a pgx pool the DB check needs (interface here so the check is
// unit-testable without a live database).
type Pinger interface {
	Ping(ctx context.Context) error
}

// PoolCheck reports whether the node's database answers at all, through the pool the node
// actually serves from.
func PoolCheck(name string, pool Pinger) Check {
	return Check{Name: name, Probe: func(ctx context.Context) error { return pool.Ping(ctx) }}
}

// Execer is the slice of a pgx pool ExecCheck needs.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// ExecCheck runs one bounded statement and fails readiness if it errors — the idiom for "the
// migrations actually ran": probing `SELECT version FROM <migrations-table>` fails while the
// table does not exist, which is precisely the silently-half-migrated state the systemd
// installer defect shipped (a node that boots but cannot serve).
func ExecCheck(name string, db Execer, sql string) Check {
	return Check{Name: name, Probe: func(ctx context.Context) error {
		_, err := db.Exec(ctx, sql)
		return err
	}}
}

// PgxDialer returns a fresh-connection dialer for CredentialWatch: it opens a NEW connection
// on the DSN — never borrowing from a pool — and closes it. Driver knowledge stays in this
// package; the composition root passes only its DSN.
func PgxDialer(dsn string) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		conn, err := pgx.Connect(ctx, dsn)
		if err != nil {
			return err
		}
		return conn.Close(ctx)
	}
}

// CredentialWatch detects the R6 rotation trap: after a DB password rotation, POOLED
// connections keep working, so every node reports healthy until they all fail together at the
// next restart. The watch periodically opens a FRESH connection — the only operation that
// actually exercises the stored credential — and remembers the outcome. It never touches the
// serving pool: detection must not break what still works.
type CredentialWatch struct {
	dial     func(ctx context.Context) error
	interval time.Duration
	onStale  func(error) // nil ok; called once per transition to stale (a log seam, not a policy seam)

	mu    sync.Mutex
	stale error // last fresh-dial failure; nil = credentials verified
}

// NewCredentialWatch builds a watch over a fresh-connection dialer. The dialer must open a NEW
// connection (never borrow from a pool) and close it; interval ≤ 0 defaults to 60s.
func NewCredentialWatch(dial func(ctx context.Context) error, interval time.Duration, onStale func(error)) *CredentialWatch {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	return &CredentialWatch{dial: dial, interval: interval, onStale: onStale}
}

// Run probes on the interval until ctx ends. Call in a goroutine from the composition root.
func (w *CredentialWatch) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		w.probe(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (w *CredentialWatch) probe(ctx context.Context) {
	dctx, cancel := context.WithTimeout(ctx, probeTimeout)
	err := w.dial(dctx)
	cancel()
	w.mu.Lock()
	wasStale := w.stale != nil
	w.stale = err
	w.mu.Unlock()
	if err != nil && !wasStale && w.onStale != nil {
		w.onStale(err)
	}
}

// Check exposes the watch's latest verdict as a readiness check, so a rotated credential
// flips /readyz to 503 within one interval instead of surfacing at the next restart.
func (w *CredentialWatch) Check(name string) Check {
	return Check{Name: name, Probe: func(context.Context) error {
		w.mu.Lock()
		defer w.mu.Unlock()
		return w.stale
	}}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
