package app

import (
	"context"

	"github.com/themis-project/themis/internal/communication/domain"
)

const deliveryBatch = 100

// DeliveryService is the outbox-style delivery worker (D6): it drains the durable delivery
// queue (Publications not yet delivered), redacts the payload, sends it on the channel, and
// records the outcome — exactly-once-eventually, idempotent, retried. Recording the
// Publication (Pending) was the atomic delivery intent (D9); this worker completes it.
type DeliveryService struct {
	repo      Repository
	deliverer Deliverer
	redactor  Redactor
	clock     Clock
}

// NewDeliveryService wires the delivery worker over its ports.
func NewDeliveryService(repo Repository, deliverer Deliverer, redactor Redactor, clock Clock) *DeliveryService {
	return &DeliveryService{repo: repo, deliverer: deliverer, redactor: redactor, clock: clock}
}

// DeliverPending delivers up to one batch of undelivered Publications and returns how many
// were delivered. A failed delivery is recorded (attempt count + error) and retried on the
// next pass; a delivered one records the outcome + emits PublicationDelivered.
func (s *DeliveryService) DeliverPending(ctx context.Context) (int, error) {
	pubs, err := s.repo.UndeliveredPublications(ctx, deliveryBatch)
	if err != nil {
		return 0, err
	}
	delivered := 0
	for _, pub := range pubs {
		prev := pub.Version()
		payload := s.redactor.Redact(pub.Payload())
		if derr := s.deliverer.Deliver(ctx, pub, payload); derr != nil {
			pub.MarkFailed(derr.Error())
			if uerr := s.repo.UpdateDelivery(ctx, pub, prev, nil); uerr != nil {
				return delivered, uerr
			}
			continue
		}
		now := s.clock.Now()
		if !pub.MarkDelivered(now) {
			continue // already delivered — idempotent
		}
		notes := []OutboxNote{{EventType: EventPublicationDelivered, Event: domain.NewPublicationDelivered(pub, now), OccurredAt: now}}
		if uerr := s.repo.UpdateDelivery(ctx, pub, prev, notes); uerr != nil {
			return delivered, uerr
		}
		delivered++
	}
	return delivered, nil
}
