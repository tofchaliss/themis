package queue_test

import (
	"testing"

	"github.com/themis-project/themis/internal/queue"
)

func TestName(t *testing.T) {
	if queue.Name() != "queue" {
		t.Fatalf("Name() = %q, want queue", queue.Name())
	}
}
