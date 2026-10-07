//go:build integration

package store_test

import (
	"context"
	"errors"
	"sync"

	"github.com/themis-project/themis/internal/kernel/event"
)

// fakePublisher is the store.Publisher stand-in SHARED by every store integration test that
// drives the relay (the relay's own delivery/retry test and the N-M2a ordering proof): it
// records what was published IN ORDER, which is what makes the relay's publish order — and so
// the bus `seq` order it becomes — assertable. failFirst makes the first publish fail, for the
// retry path. It lives in its own file so neither test owns it.
type fakePublisher struct {
	mu        sync.Mutex
	delivered []event.Envelope
	failFirst bool
	calls     int
}

func (p *fakePublisher) Publish(_ context.Context, env event.Envelope) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.failFirst && p.calls == 1 {
		return errors.New("publish boom")
	}
	p.delivered = append(p.delivered, env)
	return nil
}
