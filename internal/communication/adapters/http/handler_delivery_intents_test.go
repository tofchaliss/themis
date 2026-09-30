package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	commhttp "github.com/themis-project/themis/internal/communication/adapters/http"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

var intentEpoch = time.Date(2026, 9, 30, 11, 0, 0, 0, time.UTC)

// --- in-memory intent repo -------------------------------------------------------------

type memIntentRepo struct {
	byID    map[string]domain.DeliveryIntent
	order   []string
	history map[string][]domain.DeliveryAttempt
	listErr error
	getErr  error
}

func newIntentRepo() *memIntentRepo {
	return &memIntentRepo{byID: map[string]domain.DeliveryIntent{}, history: map[string][]domain.DeliveryAttempt{}}
}

func (r *memIntentRepo) SaveIntent(_ context.Context, in domain.DeliveryIntent) (bool, error) {
	if _, dup := r.byID[in.ID()]; dup {
		return false, nil
	}
	r.byID[in.ID()] = in
	r.order = append(r.order, in.ID())
	return true, nil
}

func (r *memIntentRepo) DueIntents(context.Context, domain.DeliveryKind, time.Time, int) ([]domain.DeliveryIntent, error) {
	return nil, nil
}

func (r *memIntentRepo) RecordAttempt(_ context.Context, in domain.DeliveryIntent, att domain.DeliveryAttempt) error {
	r.byID[in.ID()] = in
	r.history[in.ID()] = append(r.history[in.ID()], att)
	return nil
}

func (r *memIntentRepo) SaveIntentState(_ context.Context, in domain.DeliveryIntent) error {
	r.byID[in.ID()] = in
	return nil
}

func (r *memIntentRepo) GetIntent(_ context.Context, id string) (domain.DeliveryIntent, error) {
	if r.getErr != nil {
		return domain.DeliveryIntent{}, r.getErr
	}
	in, ok := r.byID[id]
	if !ok {
		return domain.DeliveryIntent{}, app.ErrIntentNotFound
	}
	return in, nil
}

func (r *memIntentRepo) IntentAttempts(_ context.Context, id string) ([]domain.DeliveryAttempt, error) {
	return r.history[id], nil
}

func (r *memIntentRepo) ListIntents(_ context.Context, f app.IntentFilter) ([]domain.DeliveryIntent, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	var out []domain.DeliveryIntent
	for _, id := range r.order {
		in := r.byID[id]
		if (f.Status == "" || in.Status() == f.Status) && (f.Kind == "" || in.Kind() == f.Kind) {
			out = append(out, in)
		}
	}
	if f.Offset >= len(out) {
		return nil, nil
	}
	out = out[f.Offset:]
	if len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (r *memIntentRepo) CountIntentsByStatus(context.Context) (map[domain.IntentStatus]int, error) {
	return nil, nil
}

type intentClock struct{}

func (intentClock) Now() time.Time { return intentEpoch }

type intentIDs struct{ n int }

func (g *intentIDs) NewID() string { g.n++; return fmt.Sprintf("int-%d", g.n) }

// principalMW stands in for auth.RequireAPIKey: it attaches a fixed principal, so the tests
// exercise the SAME gate production runs (auth.PrincipalFrom + IsAdmin) without a key store.
// A nil principal means the node has auth disabled.
func principalMW(p *auth.Principal) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if p == nil {
				next.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), *p)))
		})
	}
}

func seedIntent(t *testing.T, repo *memIntentRepo, id string, kind domain.DeliveryKind) domain.DeliveryIntent {
	t.Helper()
	in, err := domain.NewDeliveryIntent(id, kind, "default", domain.DeliveryOrigin{
		EventID: "env-" + id, EventType: "governance.finding_opened", EventTime: intentEpoch,
		FindingID: "fnd-1", ReleaseID: "rel-1", FaultlineID: "fl-1", CVE: "CVE-2026-1",
	}, 2, intentEpoch)
	if err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
	if _, err := repo.SaveIntent(context.Background(), in); err != nil {
		t.Fatalf("save %s: %v", id, err)
	}
	return in
}

func intentServer(t *testing.T, repo *memIntentRepo, principal *auth.Principal) *httptest.Server {
	t.Helper()
	pubs := newRepo()
	write := app.NewPublicationService(pubs, fakePositions{}, serializer.Default(), &ids{}, clk{})
	read := app.NewReadService(pubs, fakePositions{}, serializer.Default())
	svc := app.NewDeliveryIntentService(repo, &intentIDs{}, intentClock{},
		app.DeliveryIntentConfig{MaxAttempts: 2, Backoff: domain.BackoffPolicy{Base: time.Minute, Cap: time.Hour}})
	handler := commhttp.NewHandler(write, read).WithDeliveryIntents(svc).Router()
	srv := httptest.NewServer(principalMW(principal)(handler))
	t.Cleanup(srv.Close)
	return srv
}

// deadLetter drives an intent all the way to DEAD_LETTER through the real transitions, so
// the list/retry tests act on a state the system actually produces.
func deadLetter(t *testing.T, repo *memIntentRepo, id string) {
	t.Helper()
	svc := app.NewDeliveryIntentService(repo, &intentIDs{}, intentClock{},
		app.DeliveryIntentConfig{MaxAttempts: 2, Backoff: domain.BackoffPolicy{Base: time.Minute, Cap: time.Hour}})
	for i := 0; i < 2; i++ {
		if _, err := svc.RecordOutcome(context.Background(), repo.byID[id], errors.New("jira refused")); err != nil {
			t.Fatalf("fail %s: %v", id, err)
		}
	}
	if repo.byID[id].Status() != domain.IntentDeadLetter {
		t.Fatalf("setup: %s is %s", id, repo.byID[id].Status())
	}
}

func decodeIntents(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode list: %v (%s)", err, body)
	}
	return out
}

// --- the auth matrix -------------------------------------------------------------------

// Every route under /delivery is admin-only, reads included: the list is a cross-product
// view of the estate's outward traffic, and the mutations re-drive an action against a
// system outside it that a product scope cannot be confined to.
func TestDeliveryIntents_AdminOnly(t *testing.T) {
	principals := map[string]*auth.Principal{
		"read":              {KeyID: "k1", Scopes: []string{auth.ScopeRead}},
		"product":           {KeyID: "k2", Scopes: []string{auth.ProductScopePrefix + "prod-1"}},
		"delivery:callback": {KeyID: "k3", Scopes: []string{auth.ScopeDeliveryCallback}},
	}
	routes := []struct{ method, path string }{
		{http.MethodGet, "/delivery/intents"},
		{http.MethodGet, "/delivery/intents/int-1"},
		{http.MethodPost, "/delivery/intents/int-1/retry"},
		{http.MethodPost, "/delivery/intents/int-1/cancel"},
	}
	for name, p := range principals {
		repo := newIntentRepo()
		seedIntent(t, repo, "int-1", domain.DeliveryJiraIssue)
		srv := intentServer(t, repo, p)
		for _, r := range routes {
			status, _ := do(t, r.method, srv.URL+r.path, nil)
			if status != http.StatusForbidden {
				t.Errorf("%s %s as %s = %d, want 403", r.method, r.path, name, status)
			}
		}
		// A refusal records nothing.
		if repo.byID["int-1"].Status() != domain.IntentPending {
			t.Errorf("%s: a refused request changed the intent to %s", name, repo.byID["int-1"].Status())
		}
	}

	// Admin passes every route.
	repo := newIntentRepo()
	seedIntent(t, repo, "int-1", domain.DeliveryJiraIssue)
	srv := intentServer(t, repo, &auth.Principal{KeyID: "k0", Scopes: []string{auth.ScopeAdmin}})
	for _, r := range routes[:2] {
		if status, body := do(t, r.method, srv.URL+r.path, nil); status != http.StatusOK {
			t.Errorf("%s %s as admin = %d (%s)", r.method, r.path, status, body)
		}
	}
}

// With inbound auth disabled the node serves /api/v1 open and says so at startup; the gate
// adds nothing there, exactly like every other route.
func TestDeliveryIntents_OpenWhenAuthDisabled(t *testing.T) {
	repo := newIntentRepo()
	seedIntent(t, repo, "int-1", domain.DeliveryEmail)
	srv := intentServer(t, repo, nil)
	if status, body := do(t, http.MethodGet, srv.URL+"/delivery/intents", nil); status != http.StatusOK {
		t.Errorf("list with auth disabled = %d (%s)", status, body)
	}
}

// --- list ------------------------------------------------------------------------------

func TestListDeliveryIntents_Filters(t *testing.T) {
	repo := newIntentRepo()
	seedIntent(t, repo, "int-1", domain.DeliveryJiraIssue)
	seedIntent(t, repo, "int-2", domain.DeliveryEmail)
	deadLetter(t, repo, "int-1")
	srv := intentServer(t, repo, &auth.Principal{Scopes: []string{auth.ScopeAdmin}})

	// The operator's actual question: show me the failures. Lower case, as a person types it.
	status, body := do(t, http.MethodGet, srv.URL+"/delivery/intents?status=dead_letter", nil)
	if status != http.StatusOK {
		t.Fatalf("list dead_letter = %d (%s)", status, body)
	}
	got := decodeIntents(t, body)
	if len(got) != 1 || got[0]["id"] != "int-1" || got[0]["status"] != "DEAD_LETTER" {
		t.Errorf("dead_letter list = %v", got)
	}
	if got[0]["last_error"] == "" || got[0]["payload_hash"] == "" {
		t.Errorf("dead letter carries no cause or hash: %v", got[0])
	}
	// The list omits the history; the single read carries it.
	if _, present := got[0]["attempts_history"]; present {
		t.Error("the list should not carry the attempt history")
	}

	status, body = do(t, http.MethodGet, srv.URL+"/delivery/intents?kind=email", nil)
	if status != http.StatusOK {
		t.Fatalf("list email = %d (%s)", status, body)
	}
	if got := decodeIntents(t, body); len(got) != 1 || got[0]["kind"] != "email" {
		t.Errorf("email list = %v", got)
	}

	if status, body := do(t, http.MethodGet, srv.URL+"/delivery/intents?limit=1&offset=1", nil); status != http.StatusOK {
		t.Errorf("paged list = %d (%s)", status, body)
	}

	// An unknown filter value is a 400, not a silently empty list — "no failures" and "you
	// misspelled the status" must not look the same.
	for _, q := range []string{"?status=exploded", "?kind=slack"} {
		if status, _ := do(t, http.MethodGet, srv.URL+"/delivery/intents"+q, nil); status != http.StatusBadRequest {
			t.Errorf("list%s = %d, want 400", q, status)
		}
	}

	repo.listErr = errors.New("db down")
	if status, _ := do(t, http.MethodGet, srv.URL+"/delivery/intents", nil); status != http.StatusInternalServerError {
		t.Errorf("store failure = %d, want 500", status)
	}
}

func TestGetDeliveryIntent_CarriesTheAttemptHistory(t *testing.T) {
	repo := newIntentRepo()
	seedIntent(t, repo, "int-1", domain.DeliveryJiraIssue)
	deadLetter(t, repo, "int-1")
	srv := intentServer(t, repo, &auth.Principal{Scopes: []string{auth.ScopeAdmin}})

	status, body := do(t, http.MethodGet, srv.URL+"/delivery/intents/int-1", nil)
	if status != http.StatusOK {
		t.Fatalf("get = %d (%s)", status, body)
	}
	var view map[string]any
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	history, ok := view["attempts_history"].([]any)
	if !ok || len(history) != 2 {
		t.Fatalf("history = %v", view["attempts_history"])
	}
	first, _ := history[0].(map[string]any)
	if first["ok"] != false || first["error"] == "" {
		t.Errorf("history[0] = %v", first)
	}
	if view["origin_event_id"] != "env-int-1" || view["cve"] != "CVE-2026-1" {
		t.Errorf("lineage = %v", view)
	}
	// The payload bytes stay out of the view: the hash already pins which bytes were sent.
	if _, leaked := view["payload"]; leaked {
		t.Error("the operator view exposes the payload bytes")
	}

	if status, _ := do(t, http.MethodGet, srv.URL+"/delivery/intents/nope", nil); status != http.StatusNotFound {
		t.Errorf("unknown intent = %d, want 404", status)
	}

	// A store outage is a 500 and not a 404: "we cannot answer" must not read as "it is not
	// there", which is what would send an operator looking for a delivery that did happen.
	repo.getErr = errors.New("db down")
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/delivery/intents/int-1"},
		{http.MethodPost, "/delivery/intents/int-1/retry"},
		{http.MethodPost, "/delivery/intents/int-1/cancel"},
	} {
		if status, _ := do(t, r.method, srv.URL+r.path, nil); status != http.StatusInternalServerError {
			t.Errorf("%s %s with the store down = %d, want 500", r.method, r.path, status)
		}
	}
}

// --- retry / cancel ----------------------------------------------------------------------

func TestRetryDeliveryIntent(t *testing.T) {
	repo := newIntentRepo()
	seedIntent(t, repo, "int-1", domain.DeliveryJiraIssue)
	deadLetter(t, repo, "int-1")
	srv := intentServer(t, repo, &auth.Principal{Scopes: []string{auth.ScopeAdmin}})

	status, body := do(t, http.MethodPost, srv.URL+"/delivery/intents/int-1/retry", nil)
	if status != http.StatusOK {
		t.Fatalf("retry = %d (%s)", status, body)
	}
	var view map[string]any
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view["status"] != "PENDING" || view["attempts"] != float64(0) || view["last_error"] != "" {
		t.Errorf("retried view = %v", view)
	}
	// The history survives: a retry is a new chapter, not an erasure.
	if len(repo.history["int-1"]) != 2 {
		t.Errorf("history = %d rows after retry, want 2", len(repo.history["int-1"]))
	}

	// Retrying what is already queued is refused — the caller would otherwise believe they
	// had re-driven something they had not.
	if status, _ := do(t, http.MethodPost, srv.URL+"/delivery/intents/int-1/retry", nil); status != http.StatusConflict {
		t.Errorf("retry pending = %d, want 409", status)
	}
	if status, _ := do(t, http.MethodPost, srv.URL+"/delivery/intents/nope/retry", nil); status != http.StatusNotFound {
		t.Errorf("retry unknown = %d, want 404", status)
	}
}

func TestCancelDeliveryIntent(t *testing.T) {
	repo := newIntentRepo()
	seedIntent(t, repo, "int-1", domain.DeliveryEmail)
	seedIntent(t, repo, "int-2", domain.DeliveryEmail)
	srv := intentServer(t, repo, &auth.Principal{Scopes: []string{auth.ScopeAdmin}})

	status, body := do(t, http.MethodPost, srv.URL+"/delivery/intents/int-1/cancel", nil)
	if status != http.StatusOK {
		t.Fatalf("cancel = %d (%s)", status, body)
	}
	var view map[string]any
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view["status"] != "CANCELLED" {
		t.Errorf("cancelled view = %v", view)
	}
	// Idempotent: the caller asked for a state that already holds.
	if status, _ := do(t, http.MethodPost, srv.URL+"/delivery/intents/int-1/cancel", nil); status != http.StatusOK {
		t.Errorf("second cancel = %d, want 200", status)
	}

	// A delivered intent cannot be un-sent.
	svc := app.NewDeliveryIntentService(repo, &intentIDs{}, intentClock{}, app.DeliveryIntentConfig{MaxAttempts: 2})
	if _, err := svc.RecordOutcome(context.Background(), repo.byID["int-2"], nil); err != nil {
		t.Fatalf("deliver int-2: %v", err)
	}
	if status, _ := do(t, http.MethodPost, srv.URL+"/delivery/intents/int-2/cancel", nil); status != http.StatusConflict {
		t.Errorf("cancel delivered = %d, want 409", status)
	}
	if status, _ := do(t, http.MethodPost, srv.URL+"/delivery/intents/nope/cancel", nil); status != http.StatusNotFound {
		t.Errorf("cancel unknown = %d, want 404", status)
	}
}

// A node that does no outward delivery is a valid deployment: the routes answer 501 rather
// than panicking on a nil service.
func TestDeliveryIntents_NotConfigured(t *testing.T) {
	pubs := newRepo()
	write := app.NewPublicationService(pubs, fakePositions{}, serializer.Default(), &ids{}, clk{})
	read := app.NewReadService(pubs, fakePositions{}, serializer.Default())
	srv := httptest.NewServer(commhttp.NewHandler(write, read).Router())
	t.Cleanup(srv.Close)

	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/delivery/intents"},
		{http.MethodGet, "/delivery/intents/int-1"},
		{http.MethodPost, "/delivery/intents/int-1/retry"},
		{http.MethodPost, "/delivery/intents/int-1/cancel"},
	} {
		if status, _ := do(t, r.method, srv.URL+r.path, nil); status != http.StatusNotImplemented {
			t.Errorf("%s %s unconfigured = %d, want 501", r.method, r.path, status)
		}
	}
}
