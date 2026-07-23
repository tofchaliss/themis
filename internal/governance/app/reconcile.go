package app

import "context"

// OutboxRelay delivers one batch of pending Governance events and reports how many it
// delivered (0 when the outbox is drained). The Postgres Relay implements it.
type OutboxRelay interface {
	DeliverPending(ctx context.Context) (int, error)
}

// ReconcileService is Governance's first-class, state-based recovery job (D12 · BCK-0050):
// it continues incomplete work from durable state — publishing Positions that were
// established-but-not-yet-delivered — with no workflow replay. Inbound-event idempotency
// (find-or-create Findings, dedup proposals) and the durable human-wait state handle the
// rest, so the reconciler only needs to drain the transactional outbox.
type ReconcileService struct {
	relay OutboxRelay
}

// NewReconcileService wires the reconciler over the outbox relay.
func NewReconcileService(relay OutboxRelay) *ReconcileService {
	return &ReconcileService{relay: relay}
}

// Reconcile drains the outbox in batches until no pending events remain, returning the
// total delivered. It is safe to run repeatedly: exactly-once delivery makes a re-run that
// finds nothing pending a no-op.
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
