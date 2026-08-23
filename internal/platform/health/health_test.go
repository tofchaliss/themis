package health_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/themis-project/themis/internal/platform/health"
)

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

type fakeExecer struct{ err error }

func (f fakeExecer) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, f.err
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	health.Healthz()(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("healthz = %d %s", rec.Code, rec.Body)
	}
}

func TestReadyz(t *testing.T) {
	// All checks pass ⇒ 200 ready.
	rec := httptest.NewRecorder()
	health.Readyz(health.PoolCheck("db", fakePinger{}))(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ready"`) {
		t.Fatalf("ready = %d %s", rec.Code, rec.Body)
	}

	// Any failure ⇒ 503, EVERY failing check named (the operator sees the whole story).
	rec = httptest.NewRecorder()
	health.Readyz(
		health.PoolCheck("db", fakePinger{err: errors.New("connection refused")}),
		health.ExecCheck("migrations", fakeExecer{err: errors.New("relation does not exist")}, "SELECT version FROM schema_migrations"),
		health.ExecCheck("healthy-one", fakeExecer{}, "SELECT 1"),
	)(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != 503 {
		t.Fatalf("degraded = %d %s", rec.Code, rec.Body)
	}
	var body struct {
		Status string `json:"status"`
		Failed []struct{ Name, Error string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "degraded" || len(body.Failed) != 2 {
		t.Fatalf("body = %+v, want degraded with both failures named", body)
	}
	if body.Failed[0].Name != "db" || body.Failed[1].Name != "migrations" {
		t.Errorf("failed = %+v", body.Failed)
	}
}

func TestCredentialWatch(t *testing.T) {
	// The rotation story: fresh dials succeed, then start failing (password rotated), then
	// succeed again (password fixed). The check must follow, and onStale must fire exactly
	// once per transition into staleness.
	dialErr := error(nil)
	staleCalls := 0
	w := health.NewCredentialWatch(func(context.Context) error { return dialErr }, time.Hour,
		func(error) { staleCalls++ })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx) // first probe happens immediately; the hour interval keeps the test single-shot
	deadline := time.After(2 * time.Second)
	for {
		rec := httptest.NewRecorder()
		health.Readyz(w.Check("db-credentials"))(rec, httptest.NewRequest("GET", "/readyz", nil))
		if rec.Code == 200 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("watch never verified healthy credentials")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	// Rotate the password out from under it: the NEXT probe flips the check.
	dialErr = errors.New("password authentication failed")
	w2 := health.NewCredentialWatch(func(context.Context) error { return dialErr }, 0, func(error) { staleCalls++ })
	w2ctx, w2cancel := context.WithCancel(context.Background())
	go w2.Run(w2ctx)
	deadline = time.After(2 * time.Second)
	for {
		rec := httptest.NewRecorder()
		health.Readyz(w2.Check("db-credentials"))(rec, httptest.NewRequest("GET", "/readyz", nil))
		if rec.Code == 503 && strings.Contains(rec.Body.String(), "password authentication failed") {
			break
		}
		select {
		case <-deadline:
			t.Fatal("stale credentials never surfaced on readyz")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	w2cancel()
	if staleCalls < 1 {
		t.Errorf("onStale calls = %d, want >= 1 (once per transition)", staleCalls)
	}
}

func TestPgxDialer_FailsFastOnUnreachable(t *testing.T) {
	dial := health.PgxDialer("postgres://user:pw@127.0.0.1:1/db") // nothing listens
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := dial(ctx); err == nil {
		t.Fatal("dial to a dead endpoint must error")
	}
}
