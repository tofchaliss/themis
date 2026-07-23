package app

import "context"

// OutboxRelay delivers one batch of pending terminal Communication events and reports how
// many it delivered (0 when drained). The Postgres Relay implements it.
type OutboxRelay interface {
	DeliverPending(ctx context.Context) (int, error)
}

// ReconcileService is Communication's first-class, state-based recovery job (D11 · BCK-0050):
// it continues incomplete work from durable state — draining the terminal-event outbox — with
// no workflow replay. Undelivered Publications are recovered by the delivery worker
// (idempotent re-run off the durable pending status), and the durable publishable-positions
// queue holds pending human triggers, so the reconciler only needs to drain the outbox.
type ReconcileService struct {
	relay OutboxRelay
}

// NewReconcileService wires the reconciler over the outbox relay.
func NewReconcileService(relay OutboxRelay) *ReconcileService {
	return &ReconcileService{relay: relay}
}

// Reconcile drains the terminal-event outbox in batches until nothing remains, returning the
// total delivered. Safe to run repeatedly (exactly-once delivery makes a re-run a no-op).
func (s *ReconcileService) Reconcile(ctx context.Context) (int, error) {
	total := 0
	for {
		n, err := s.relay.DeliverPending(ctx)
		if err != nil {
			return total, err
		}
		total += n
		if n == 0 {
			return total, nil
		}
	}
}
