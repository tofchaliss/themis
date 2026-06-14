package httpserver_test

import (
	"context"
	"testing"
	"time"

	httpserver "github.com/themis-project/themis/internal/infrastructure/http"
)

func TestStartEPSSKevSchedulerNilService(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	httpserver.StartEPSSKevScheduler(ctx, nil, time.Millisecond)
}
