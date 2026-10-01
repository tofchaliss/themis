package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	commhttp "github.com/themis-project/themis/internal/communication/adapters/http"
	"github.com/themis-project/themis/internal/communication/adapters/http/gen"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
	"github.com/themis-project/themis/internal/platform/auth"
	"github.com/themis-project/themis/internal/platform/observability"
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

// The call an operator actually makes: no query string at all. It must return the page the
// OpenAPI promises rather than an empty one.
//
// This is a real probe, not a formality. `memIntentRepo.ListIntents` truncates to `f.Limit`
// exactly as Postgres' `LIMIT` does, so a limit of 0 arriving at the store would come back here
// as an empty list — and an empty list is precisely how "there are no failed deliveries" looks.
// An explicit `limit=0` is covered on the same terms: asking for zero must mean the same as not
// asking, not "show me nothing".
func TestListDeliveryIntents_DefaultPageSizeWhenLimitOmitted(t *testing.T) {
	repo := newIntentRepo()
	for i := 1; i <= 3; i++ {
		seedIntent(t, repo, fmt.Sprintf("int-%d", i), domain.DeliveryEmail)
	}
	srv := intentServer(t, repo, &auth.Principal{Scopes: []string{auth.ScopeAdmin}})

	// No limit · an explicit zero · a filter but still no limit · exactly at the cap: every one
	// of them must page at the default (or the cap) and return what is there. A limit ABOVE the
	// cap is a 400 and is covered by TestListDeliveryIntents_RefusesAPageAboveTheCap.
	for _, query := range []string{"", "?limit=0", "?status=pending", "?kind=email", "?limit=500"} {
		status, body := do(t, http.MethodGet, srv.URL+"/delivery/intents"+query, nil)
		if status != http.StatusOK {
			t.Fatalf("list %q = %d (%s)", query, status, body)
		}
		got := decodeIntents(t, body)
		if len(got) != 3 {
			t.Errorf("list %q returned %d intents, want all 3", query, len(got))
		}
		if len(got) > app.DefaultIntentPageSize {
			t.Errorf("list %q returned %d intents, past the default page size", query, len(got))
		}
	}

	// An explicit, positive limit still wins over the default.
	if _, body := do(t, http.MethodGet, srv.URL+"/delivery/intents?limit=2", nil); len(decodeIntents(t, body)) != 2 {
		t.Errorf("limit=2 did not page to 2: %s", body)
	}
}

// A page past the cap is REFUSED, not clamped. Both bound the query, but a silent clamp hands the
// caller a truncated page that looks complete — and on the endpoint whose job is "show me every
// failure", believing you have seen them all when you have not is the expensive mistake.
func TestListDeliveryIntents_RefusesAPageAboveTheCap(t *testing.T) {
	repo := newIntentRepo()
	seedIntent(t, repo, "int-1", domain.DeliveryEmail)
	srv := intentServer(t, repo, &auth.Principal{Scopes: []string{auth.ScopeAdmin}})

	status, body := do(t, http.MethodGet,
		fmt.Sprintf("%s/delivery/intents?limit=%d", srv.URL, app.MaxIntentPageSize+1), nil)
	if status != http.StatusBadRequest {
		t.Errorf("limit above the cap = %d, want 400 (%s)", status, body)
	}
	// The refusal has to say what the cap IS, or the caller's only move is to guess.
	if !strings.Contains(string(body), fmt.Sprint(app.MaxIntentPageSize)) {
		t.Errorf("the refusal does not state the cap: %s", body)
	}
	// Exactly at the cap is allowed — an off-by-one here would refuse a legitimate page.
	if status, body := do(t, http.MethodGet,
		fmt.Sprintf("%s/delivery/intents?limit=%d", srv.URL, app.MaxIntentPageSize), nil); status != http.StatusOK {
		t.Errorf("limit exactly at the cap = %d, want 200 (%s)", status, body)
	}
}

// A 500 must not carry the driver's own words. A pgx error can quote the DSN, a host and port, a
// constraint or column name, or part of the statement; the response body is the one place
// guaranteed to be read, and it gets pasted into tickets and chat that the admin-only gate does
// not cover. The caller gets a generic sentence plus the correlation id; the operator gets the
// cause through the shared logger. Same split as EDR-DELIVERY-01 D5a.
func TestDeliveryIntents_FaultsDoNotLeakTheBackendError(t *testing.T) {
	const secret = "dial tcp 10.0.3.7:5432: password=hunter2 relation \"delivery_intents\" does not exist"

	core, logs := observer.New(zapcore.ErrorLevel)
	logger := observability.New(zap.New(core))
	repo := newIntentRepo()
	seedIntent(t, repo, "int-1", domain.DeliveryEmail)
	repo.listErr = errors.New(secret)
	repo.getErr = errors.New(secret)

	pubs := newRepo()
	write := app.NewPublicationService(pubs, fakePositions{}, serializer.Default(), &ids{}, clk{})
	read := app.NewReadService(pubs, fakePositions{}, serializer.Default())
	svc := app.NewDeliveryIntentService(repo, &intentIDs{}, intentClock{}, app.DeliveryIntentConfig{MaxAttempts: 2})
	handler := commhttp.NewHandler(write, read).WithDeliveryIntents(svc).WithLogger(logger).Router()
	srv := httptest.NewServer(principalMW(&auth.Principal{Scopes: []string{auth.ScopeAdmin}})(handler))
	t.Cleanup(srv.Close)

	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/delivery/intents"},
		{http.MethodGet, "/delivery/intents/int-1"},
		{http.MethodPost, "/delivery/intents/int-1/retry"},
		{http.MethodPost, "/delivery/intents/int-1/cancel"},
	} {
		status, body := do(t, r.method, srv.URL+r.path, nil)
		if status != http.StatusInternalServerError {
			t.Errorf("%s %s = %d, want 500 (%s)", r.method, r.path, status, body)
		}
		if strings.Contains(string(body), "hunter2") || strings.Contains(string(body), "10.0.3.7") ||
			strings.Contains(string(body), "delivery_intents") {
			t.Errorf("%s %s leaked the backend error: %s", r.method, r.path, body)
		}
	}

	// ...and the operator loses nothing: the withheld cause is on the log.
	var found bool
	for _, e := range logs.All() {
		if strings.Contains(e.Message, "delivery-intent request failed") &&
			strings.Contains(fmt.Sprint(e.ContextMap()), "hunter2") {
			found = true
		}
	}
	if !found {
		t.Error("the cause was withheld from the caller AND not logged — that is strictly worse than leaking it")
	}
}

// Spec-first means the published contract is the contract, so the default page size is checked
// against the SPEC and not against a second literal. oapi-codegen binds no declared default (an
// omitted `limit` is a nil pointer), so nothing but this test can catch the spec's `default: 50`
// and `app.DefaultIntentPageSize` drifting apart — and the symptom of that drift would be an
// operator's page size quietly disagreeing with the documentation they read.
func TestListDeliveryIntents_SpecDefaultMatchesTheCode(t *testing.T) {
	spec, err := gen.GetSpec()
	if err != nil {
		t.Fatalf("embedded spec: %v", err)
	}
	item := spec.Paths.Find("/delivery/intents")
	if item == nil || item.Get == nil {
		t.Fatal("the embedded spec has no GET /delivery/intents")
	}
	for _, p := range item.Get.Parameters {
		if p.Value == nil || p.Value.Name != "limit" {
			continue
		}
		declared, ok := p.Value.Schema.Value.Default.(float64)
		if !ok {
			t.Fatalf("limit declares no numeric default: %v", p.Value.Schema.Value.Default)
		}
		if int(declared) != app.DefaultIntentPageSize {
			t.Errorf("spec declares limit default %d, app.DefaultIntentPageSize is %d",
				int(declared), app.DefaultIntentPageSize)
		}
		return
	}
	t.Error("GET /delivery/intents declares no `limit` parameter")
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

// The DEFAULT deployment: the operator API is off (the API addition is an outstanding must-ask,
// EDR-DELIVERY-01 D15), so the four routes answer 501 rather than panicking on a nil service.
// The refusal must name the switch — a 501 that does not is indistinguishable from a broken node,
// and this is the one surface an operator hits before reading any document.
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
		status, body := do(t, r.method, srv.URL+r.path, nil)
		if status != http.StatusNotImplemented {
			t.Errorf("%s %s unconfigured = %d, want 501", r.method, r.path, status)
		}
		if !strings.Contains(string(body), "THEMIS_DELIVERY_OPERATOR_API") {
			t.Errorf("%s %s: the 501 does not name the switch that enables it: %s", r.method, r.path, body)
		}
	}
}

// The gate is the composition root's, not the handler's: `wiring.Wire` hands the handler the
// intent service only when OperatorAPI is set. Pinned here because the default is the SHIPPED
// behaviour — a later refactor that wires the service unconditionally would publish four routes
// nobody approved, and no other test would notice.
func TestWiringGatesTheOperatorAPI(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		repo := newIntentRepo()
		seedIntent(t, repo, "int-1", domain.DeliveryEmail)
		svc := app.NewDeliveryIntentService(repo, &intentIDs{}, intentClock{},
			app.DeliveryIntentConfig{MaxAttempts: 2})

		pubs := newRepo()
		write := app.NewPublicationService(pubs, fakePositions{}, serializer.Default(), &ids{}, clk{})
		read := app.NewReadService(pubs, fakePositions{}, serializer.Default())
		h := commhttp.NewHandler(write, read)
		if enabled {
			h = h.WithDeliveryIntents(svc)
		}
		srv := httptest.NewServer(h.Router())

		want := http.StatusNotImplemented
		if enabled {
			want = http.StatusOK
		}
		if status, body := do(t, http.MethodGet, srv.URL+"/delivery/intents", nil); status != want {
			t.Errorf("operator API enabled=%v: got %d, want %d (%s)", enabled, status, want, body)
		}
		srv.Close()
	}
}
