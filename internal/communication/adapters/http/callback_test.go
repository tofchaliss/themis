package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	commhttp "github.com/themis-project/themis/internal/communication/adapters/http"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/platform/auth"
)

// intentsMem is the smallest app.DeliveryIntents the callback route needs: create and get.
type intentsMem struct {
	byID map[string]app.Intent
}

func (m *intentsMem) CreateIntent(_ context.Context, in app.Intent) (app.Intent, error) {
	m.byID[in.ID] = in
	return in, nil
}
func (m *intentsMem) GetIntent(_ context.Context, id string) (app.Intent, error) {
	in, ok := m.byID[id]
	if !ok {
		return app.Intent{}, app.ErrIntentNotFound
	}
	return in, nil
}
func (m *intentsMem) GetPendingForWork(context.Context, time.Time, int) ([]app.Intent, error) {
	return nil, nil
}
func (m *intentsMem) RecordAttempt(context.Context, app.Attempt) error               { return nil }
func (m *intentsMem) MarkDelivered(context.Context, string, map[string]string) error { return nil }
func (m *intentsMem) MarkDeadLetter(context.Context, string, string) error           { return nil }
func (m *intentsMem) CancelIntent(context.Context, string) error                     { return nil }
func (m *intentsMem) ListDeadLetters(context.Context, time.Time, int) ([]app.Intent, error) {
	return nil, nil
}
func (m *intentsMem) RetryIntent(context.Context, string) error { return nil }

// callbacksMem records callbacks per (intent, sbom).
type callbacksMem struct {
	rows []app.RebuildCallback
	err  error
}

func (c *callbacksMem) RecordCallback(_ context.Context, cb app.RebuildCallback) (app.RebuildCallback, error) {
	if c.err != nil {
		return app.RebuildCallback{}, c.err
	}
	for _, r := range c.rows {
		if r.IntentID == cb.IntentID && r.SBOMID == cb.SBOMID {
			return r, nil
		}
	}
	c.rows = append(c.rows, cb)
	return cb, nil
}
func (c *callbacksMem) ListCallbacks(_ context.Context, intentID string) ([]app.RebuildCallback, error) {
	var out []app.RebuildCallback
	for _, r := range c.rows {
		if r.IntentID == intentID {
			out = append(out, r)
		}
	}
	return out, nil
}

type cbIDs struct{ n int }

func (g *cbIDs) NewID() string { g.n++; return "int-" + string(rune('0'+g.n)) }

// postureCounter counts the Governance reads the renderer makes — the one outward-facing read a
// callback could conceivably trigger.
type postureCounter struct{ calls int }

func (p *postureCounter) ReleaseSeverity(context.Context, string) ([]app.ReleaseSeverityRow, error) {
	p.calls++
	return nil, nil
}

type callbackFixture struct {
	intents   *intentsMem
	callbacks *callbacksMem
	svc       *app.DeliveryIntentService
	posture   *postureCounter
	rebuildID string
	mailID    string
}

// callbackServer wires the route under the PRODUCTION middleware shape: the write floor with the
// callback exemption, and a principal injected per request as RequireAPIKey would.
func callbackServer(t *testing.T, fx *callbackFixture, scopes []string) *httptest.Server {
	t.Helper()
	repo := newRepo()
	write := app.NewPublicationService(repo, nil, serializer.Default(), &ids{}, clk{})
	read := app.NewReadService(repo, nil, serializer.Default())
	api := commhttp.NewHandler(write, read)
	if fx.svc != nil {
		api.WithRebuildCallbacks(fx.svc)
	}
	chain := commhttp.WriteFloorExcept(commhttp.CallbackRoutePath, auth.RequireWriteScope)(api.Router())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if scopes != nil {
			ctx = auth.WithPrincipal(ctx, auth.Principal{KeyID: "k-" + scopes[0], Name: scopes[0], Scopes: scopes})
		}
		chain.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newCallbackFixture(t *testing.T) *callbackFixture {
	t.Helper()
	fx := &callbackFixture{intents: &intentsMem{byID: map[string]app.Intent{}}, callbacks: &callbacksMem{}, posture: &postureCounter{}}
	fx.svc = app.NewDeliveryIntentService(fx.intents, &cbIDs{}, clk{}, app.DeliveryIntentConfig{}).
		WithPayloadRenderer(serializer.NewOutwardRenderer(fx.posture)).
		WithRebuildCallbacks(fx.callbacks)
	ctx := context.Background()
	rebuild, err := fx.svc.EnqueueCIRebuild(ctx, app.IntentLineage{}, "", "rel-1", "prod-1", "prj-1", "ev-1", []string{"CVE-2026-1"}, 1, nil)
	if err != nil {
		t.Fatalf("seed rebuild: %v", err)
	}
	mail, err := fx.svc.EnqueueDecisionMail(ctx, app.IntentLineage{}, "", "prop-1", "fnd-1", "rel-1", "", nil)
	if err != nil {
		t.Fatalf("seed mail: %v", err)
	}
	fx.rebuildID, fx.mailID = rebuild.ID, mail.ID
	fx.posture.calls = 0
	return fx
}

func callbackBody(intentID string, extra map[string]any) map[string]any {
	body := map[string]any{"intent_id": intentID, "sbom_id": "ev-2", "image_digest": "sha256:abc", "build_id": "77", "git_ref": "main@deadbeef"}
	for k, v := range extra {
		if v == nil {
			delete(body, k)
		} else {
			body[k] = v
		}
	}
	return body
}

// N-M2h: every scope but delivery:callback is refused (admin included — two keys, not one), the
// write floor does not stand in the callback key's way, a missing sbom_id or image_digest is a 400,
// an unknown intent a 404, a non-rebuild intent a 409, and a repeat is accepted without a second row.
func TestCIRebuildCallback_AuthAndBodySchema(t *testing.T) {
	fx := newCallbackFixture(t)
	for _, tc := range []struct {
		scopes []string
		want   int
	}{
		{[]string{auth.ScopeDeliveryCallback}, http.StatusAccepted},
		{[]string{auth.ScopeRead}, http.StatusForbidden},
		{[]string{auth.ScopeAdmin}, http.StatusForbidden},
		{[]string{"product:prod-1"}, http.StatusForbidden},
		{nil, http.StatusAccepted}, // auth off: no principal, the route is open like every other
	} {
		srv := callbackServer(t, fx, tc.scopes)
		if s, body := do(t, http.MethodPost, srv.URL+commhttp.CallbackRoutePath, callbackBody(fx.rebuildID, nil)); s != tc.want {
			t.Errorf("scopes %v: %d %s, want %d", tc.scopes, s, body, tc.want)
		}
	}
	if len(fx.callbacks.rows) != 1 {
		t.Fatalf("recorded %d callbacks, want exactly 1 — two accepted posts of one (intent, sbom) are one row", len(fx.callbacks.rows))
	}
	if r := fx.callbacks.rows[0]; r.ReportedBy != "key:k-delivery:callback" || r.BuildID != "77" || r.GitRef != "main@deadbeef" || r.ImageDigest != "sha256:abc" {
		t.Errorf("recorded = %+v", r)
	}
	// The write floor still guards every OTHER post for the callback key.
	srv := callbackServer(t, fx, []string{auth.ScopeDeliveryCallback})
	if s, _ := do(t, http.MethodPost, srv.URL+"/publications", map[string]any{"finding_id": "fnd-1", "artifact_type": "vex", "format": "openvex"}); s != http.StatusForbidden {
		t.Errorf("callback key on /publications: %d, want 403 from the write floor", s)
	}

	for name, tc := range map[string]struct {
		body any
		want int
	}{
		"missing sbom_id":      {callbackBody(fx.rebuildID, map[string]any{"sbom_id": nil}), http.StatusBadRequest},
		"blank image_digest":   {callbackBody(fx.rebuildID, map[string]any{"image_digest": "  "}), http.StatusBadRequest},
		"missing intent_id":    {callbackBody(fx.rebuildID, map[string]any{"intent_id": nil}), http.StatusBadRequest},
		"not json":             {"{not json", http.StatusBadRequest},
		"unknown intent":       {callbackBody("int-nope", nil), http.StatusNotFound},
		"not a rebuild intent": {callbackBody(fx.mailID, nil), http.StatusConflict},
	} {
		s, body := do(t, http.MethodPost, srv.URL+commhttp.CallbackRoutePath, tc.body)
		if s != tc.want {
			t.Errorf("%s: %d %s, want %d", name, s, body, tc.want)
		}
	}
	if len(fx.callbacks.rows) != 1 {
		t.Errorf("a refused callback was recorded: %+v", fx.callbacks.rows)
	}

	// The ack names what was recorded.
	s, body := do(t, http.MethodPost, srv.URL+commhttp.CallbackRoutePath, callbackBody(fx.rebuildID, map[string]any{"sbom_id": "ev-3"}))
	if s != http.StatusAccepted {
		t.Fatalf("second sbom: %d %s", s, body)
	}
	var ack struct {
		IntentID   string    `json:"intent_id"`
		SBOMID     string    `json:"sbom_id"`
		ReceivedAt time.Time `json:"received_at"`
	}
	if err := json.Unmarshal(body, &ack); err != nil || ack.IntentID != fx.rebuildID || ack.SBOMID != "ev-3" || ack.ReceivedAt.IsZero() {
		t.Errorf("ack = %s (%v)", body, err)
	}

	// Store failure is a 500; a node without delivery wired answers 503.
	fx.callbacks.err = errors.New("db down")
	if s, body := do(t, http.MethodPost, srv.URL+commhttp.CallbackRoutePath, callbackBody(fx.rebuildID, map[string]any{"sbom_id": "ev-4"})); s != http.StatusInternalServerError || !strings.Contains(string(body), "db down") {
		t.Errorf("store failure: %d %s", s, body)
	}
	fx.callbacks.err = nil
	off := callbackServer(t, &callbackFixture{}, []string{auth.ScopeDeliveryCallback})
	if s, _ := do(t, http.MethodPost, off.URL+commhttp.CallbackRoutePath, callbackBody("x", nil)); s != http.StatusServiceUnavailable {
		t.Errorf("delivery off: %d, want 503", s)
	}
	unwired := newCallbackFixture(t)
	unwired.svc = app.NewDeliveryIntentService(unwired.intents, &cbIDs{}, clk{}, app.DeliveryIntentConfig{})
	nocb := callbackServer(t, unwired, []string{auth.ScopeDeliveryCallback})
	if s, _ := do(t, http.MethodPost, nocb.URL+commhttp.CallbackRoutePath, callbackBody(unwired.rebuildID, nil)); s != http.StatusServiceUnavailable {
		t.Errorf("no callback store: %d, want 503", s)
	}
}

// N-M2h: a callback is evidence on the intent and nothing else — no intent is created, no
// payload rendered (so no Governance read), and the intent it names is untouched. Communication
// holds no Finding at all, which is the structural half; this is the behavioural half.
func TestCallback_NoFindingMutation(t *testing.T) {
	fx := newCallbackFixture(t)
	before := fx.intents.byID[fx.rebuildID]
	srv := callbackServer(t, fx, []string{auth.ScopeDeliveryCallback})
	for i := 0; i < 3; i++ {
		if s, body := do(t, http.MethodPost, srv.URL+commhttp.CallbackRoutePath, callbackBody(fx.rebuildID, nil)); s != http.StatusAccepted {
			t.Fatalf("callback %d: %d %s", i, s, body)
		}
	}
	if len(fx.intents.byID) != 2 {
		t.Errorf("intents = %d, want the two seeded ones — a callback creates nothing", len(fx.intents.byID))
	}
	if fx.posture.calls != 0 {
		t.Errorf("the callback caused %d Governance reads, want 0", fx.posture.calls)
	}
	if after := fx.intents.byID[fx.rebuildID]; after.State != before.State || after.Attempts != before.Attempts || string(after.PayloadBytes) != string(before.PayloadBytes) {
		t.Errorf("the intent changed: %+v → %+v", before, after)
	}
	if cbs, _ := fx.callbacks.ListCallbacks(context.Background(), fx.rebuildID); len(cbs) != 1 {
		t.Errorf("callbacks = %d, want 1", len(cbs))
	}
}

// The exemption is exact: the callback path only, POST only.
func TestWriteFloorExcept(t *testing.T) {
	hit := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit++; w.WriteHeader(http.StatusNoContent) })
	chain := commhttp.WriteFloorExcept("/api/v1"+commhttp.CallbackRoutePath, auth.RequireWriteScope)(next)
	readKey := auth.WithPrincipal(context.Background(), auth.Principal{KeyID: "k", Scopes: []string{auth.ScopeRead}})
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/api/v1" + commhttp.CallbackRoutePath, http.StatusNoContent},
		{http.MethodPost, "/api/v1" + commhttp.CallbackRoutePath + "/more", http.StatusForbidden},
		{http.MethodPost, "/api/v1/publications", http.StatusForbidden},
		{http.MethodDelete, "/api/v1" + commhttp.CallbackRoutePath, http.StatusForbidden},
		{http.MethodGet, "/api/v1/publications", http.StatusNoContent},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, nil).WithContext(readKey)
		chain.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
}
