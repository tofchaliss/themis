package queue

import (
	"context"
	"testing"
)

func TestNoopWorkerPool(t *testing.T) {
	var pool NoopWorkerPool
	if err := pool.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := pool.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
}
