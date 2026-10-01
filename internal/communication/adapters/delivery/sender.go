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
//
// TWO OBLIGATIONS ON THE ERROR A REAL SENDER RETURNS (M2/M3), because both are invisible from
// here and permanent once broken:
//
//  1. It is PERSISTED verbatim — `last_error` on the intent and the `error` column of an
//     append-only history row that is never pruned — and logged. It must therefore contain no
//     credential, no signed URL, no echoed payload and no recipient address. Return an enumerated
//     reason (status plus a short class), not the transport's raw text; `app.Redactor` is the port
//     for the rule if one is needed. See the guardrail on `app.DeliveryIntentService.RecordOutcome`.
//  2. It must distinguish "the target refused this permanently" from "the target was unreachable",
//     because the worker treats every error as retryable and will spend the whole attempt budget
//     on a request that can never succeed.
type Sender interface {
	Send(ctx context.Context, intent domain.DeliveryIntent) error
}
