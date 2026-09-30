package delivery

import (
	"context"

	"github.com/themis-project/themis/internal/communication/domain"
)

// Sender hands one delivery intent's materialized payload to an outward channel — a Jira
// API, a mail relay, a CI trigger (EDR-DELIVERY-01 N-M1a).
//
// It takes the INTENT and not just the bytes on purpose: a real sender needs the kind, the
// destination name and the lineage to address and de-duplicate its own call, and every one
// of those is already frozen on the record. It resolves the destination NAME to an endpoint
// and a credential out of its own configuration; no credential is ever read from, or written
// to, a delivery intent (D-N-6).
//
// A Sender must be idempotent per intent id where the target allows it: the worker retries,
// and the retry is what makes a transient outage survivable.
type Sender interface {
	Send(ctx context.Context, intent domain.DeliveryIntent) error
}
