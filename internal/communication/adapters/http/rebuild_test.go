package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	commhttp "github.com/themis-project/themis/internal/communication/adapters/http"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/platform/auth"
)

// rebuildFixture is a loop that opens cycles from decisions, behind the production middleware.
type rebuildFixture struct {
	*callbackFixture
	loop     *app.RebuildLoop
	cycles   *loopCycles
	requests *loopRequests
	intentID string
}

func newRebuildFixture(t *testing.T) *rebuildFixture {
	t.Helper()
	fx := &rebuildFixture{callbackFixture: &callbackFixture{intents: &intentsMem{byID: map[string]app.Intent{}}, callbacks: &callbacksMem{}},
		cycles: &loopCycles{}, requests: &loopRequests{}}
	fx.svc = app.NewDeliveryIntentService(fx.intents, &cbIDs{}, clk{}, app.DeliveryIntentConfig{
		WebhookRoutes: map[string]string{app.WebhookRebuildRequested: "builders"}, SignedAudiences: map[string]bool{"builders": true},
	}).WithRebuildCallbacks(fx.callbacks)
	fx.loop = app.NewRebuildLoop(fx.cycles, &postureCounter{}, fx.svc, clk{}, 2).WithDecisions(fx.requests, app.RebuildOpenFromDecision)
	out, err := fx.loop.Request(context.Background(), app.IntentLineage{EventID: "env-1"}, app.RebuildDecisionFacts{
		DecisionID: "dec-1", ReleaseID: "rel-1", ProductID: "prod-1", ProjectID: "prj-1", CVEs: []string{"CVE-2026-1"}, Raw: []byte(`{}`)})
	if err != nil || out.State != app.DecisionOpened {
		t.Fatalf("seed cycle: %+v %v", out, err)
	}
	fx.intentID = fx.requests.rows[0].IntentID
	return fx
}

func rebuildServer(t *testing.T, fx *rebuildFixture, wired bool, scopes []string) *httptest.Server {
	t.Helper()
	repo := newRepo()
	api := commhttp.NewHandler(app.NewPublicationService(repo, nil, serializer.Default(), &ids{}, clk{}), app.NewReadService(repo, nil, serializer.Default())).
		WithRebuildCallbacks(fx.svc)
	if wired {
		api.WithRebuildLoop(fx.loop)
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

func (fx *rebuildFixture) state() string { return fx.requests.rows[len(fx.requests.rows)-1].State }

// D28 item 2: the status call rides the callback route under the callback key, moves the request
// and nothing else, and says what it did.
func TestRebuildStatusCall(t *testing.T) {
	fx := newRebuildFixture(t)
	srv := rebuildServer(t, fx, true, []string{auth.ScopeDeliveryCallback})
	url := srv.URL + commhttp.CallbackRoutePath

	s, body := do(t, http.MethodPost, url, map[string]any{"intent_id": fx.intentID, "status": "submitted", "build_ref": "queue/12", "execution_started": true})
	var ack struct {
		IntentID string `json:"intent_id"`
		State    string `json:"state"`
	}
	if err := json.Unmarshal(body, &ack); s != http.StatusAccepted || err != nil || ack.IntentID != fx.intentID || ack.State != "submitted" {
		t.Fatalf("submitted: %d %s (%v)", s, body, err)
	}
	req := fx.requests.rows[0]
	if req.State != app.RequestSubmitted || req.BuildRef != "queue/12" || req.ExecutionStartedAt.IsZero() || req.ReportedBy != "key:k-delivery:callback" {
		t.Errorf("request = %+v", req)
	}
	if len(fx.callbacks.rows) != 0 {
		t.Error("a status call is not a build report")
	}
	for name, tc := range map[string]struct {
		body map[string]any
		want int
	}{
		"refused after submitted": {map[string]any{"intent_id": fx.intentID, "status": "refused"}, http.StatusConflict},
		"unknown status":          {map[string]any{"intent_id": fx.intentID, "status": "started"}, http.StatusBadRequest},
		"no intent":               {map[string]any{"intent_id": " ", "status": "submitted"}, http.StatusBadRequest},
		"unknown intent":          {map[string]any{"intent_id": "nope", "status": "submitted"}, http.StatusNotFound},
	} {
		if s, body := do(t, http.MethodPost, url, tc.body); s != tc.want {
			t.Errorf("%s: %d %s, want %d", name, s, body, tc.want)
		}
	}
	// Any other key is refused, as for the build report; a node with no loop answers 503.
	admin := rebuildServer(t, fx, true, []string{auth.ScopeAdmin})
	if s, _ := do(t, http.MethodPost, admin.URL+commhttp.CallbackRoutePath, map[string]any{"intent_id": fx.intentID, "status": "submitted"}); s != http.StatusForbidden {
		t.Errorf("admin key on the status call: %d", s)
	}
	off := rebuildServer(t, fx, false, []string{auth.ScopeDeliveryCallback})
	if s, _ := do(t, http.MethodPost, off.URL+commhttp.CallbackRoutePath, map[string]any{"intent_id": fx.intentID, "status": "submitted"}); s != http.StatusServiceUnavailable {
		t.Errorf("no loop: %d", s)
	}
}

// The build report for a request of a decision cycle is recorded and moves it to build_reported.
func TestRebuildBuildReportMovesTheRequest(t *testing.T) {
	fx := newRebuildFixture(t)
	srv := rebuildServer(t, fx, true, []string{auth.ScopeDeliveryCallback})
	s, body := do(t, http.MethodPost, srv.URL+commhttp.CallbackRoutePath, callbackBody(fx.intentID, nil))
	if s != http.StatusAccepted || !strings.Contains(string(body), `"state":"build_reported"`) || fx.state() != app.RequestBuildReported || len(fx.callbacks.rows) != 1 {
		t.Fatalf("report: %d %s state=%s", s, body, fx.state())
	}
	fx.requests.err = errors.New("db down")
	if s, body := do(t, http.MethodPost, srv.URL+commhttp.CallbackRoutePath, callbackBody(fx.intentID, map[string]any{"sbom_id": "ev-9"})); s != http.StatusInternalServerError || !strings.Contains(string(body), "request state not updated") {
		t.Errorf("state update failure: %d %s", s, body)
	}
}

func TestGetReleaseRebuildCycle(t *testing.T) {
	fx := newRebuildFixture(t)
	fx.requests.holds = map[string]app.RebuildHold{"rel-1": {ReleaseID: "rel-1", DecisionID: "dec-2", Reason: app.HoldCoolDown, RecordedAt: clk{}.Now(), Until: clk{}.Now()}}
	srv := rebuildServer(t, fx, true, []string{auth.ScopeRead})
	s, body := do(t, http.MethodGet, srv.URL+"/releases/rel-1/rebuild-cycle", nil)
	var view struct {
		ReleaseID string `json:"release_id"`
		Cycle     *struct {
			ID          int64    `json:"id"`
			Origin      string   `json:"origin"`
			State       string   `json:"state"`
			DecisionID  string   `json:"decision_id"`
			MaxAttempts int      `json:"max_attempts"`
			Targeted    []string `json:"targeted"`
		} `json:"cycle"`
		Requests []struct {
			IntentID string `json:"intent_id"`
			State    string `json:"state"`
			Channel  string `json:"channel"`
			Attempt  int    `json:"attempt"`
			Try      int    `json:"try"`
		} `json:"requests"`
		Hold *struct {
			Reason    string `json:"reason"`
			HeldUntil string `json:"held_until"`
		} `json:"hold"`
	}
	if err := json.Unmarshal(body, &view); s != http.StatusOK || err != nil {
		t.Fatalf("view: %d %s (%v)", s, body, err)
	}
	if view.ReleaseID != "rel-1" || view.Cycle == nil || view.Cycle.Origin != "decision" || view.Cycle.State != "open" || view.Cycle.DecisionID != "dec-1" ||
		view.Cycle.MaxAttempts != 2 || len(view.Cycle.Targeted) != 1 || len(view.Requests) != 1 || view.Requests[0].IntentID != fx.intentID ||
		view.Requests[0].State != "requested" || view.Requests[0].Channel != "webhook" || view.Requests[0].Attempt != 1 || view.Requests[0].Try != 1 ||
		view.Hold == nil || view.Hold.Reason != "cool_down" || view.Hold.HeldUntil == "" {
		t.Errorf("view = %s", body)
	}
	// A Release with nothing answers with both absent; a cycle the posture opened reads as such.
	if s, body := do(t, http.MethodGet, srv.URL+"/releases/rel-none/rebuild-cycle", nil); s != http.StatusOK || strings.Contains(string(body), `"cycle"`) || !strings.Contains(string(body), `"requests":[]`) {
		t.Errorf("empty view: %d %s", s, body)
	}
	fx.cycles.rows = append(fx.cycles.rows, &app.RebuildCycle{ID: 9, ReleaseID: "rel-old", State: app.CycleExhausted})
	if _, body := do(t, http.MethodGet, srv.URL+"/releases/rel-old/rebuild-cycle", nil); !strings.Contains(string(body), `"origin":"evaluation"`) || !strings.Contains(string(body), `"targeted":[]`) {
		t.Errorf("old cycle: %s", body)
	}
	fx.cycles.err = errors.New("db down")
	if s, _ := do(t, http.MethodGet, srv.URL+"/releases/rel-1/rebuild-cycle", nil); s != http.StatusInternalServerError {
		t.Errorf("store failure: %d", s)
	}
	off := rebuildServer(t, fx, false, []string{auth.ScopeRead})
	if s, _ := do(t, http.MethodGet, off.URL+"/releases/rel-1/rebuild-cycle", nil); s != http.StatusServiceUnavailable {
		t.Errorf("no loop: %d", s)
	}
}

// D22 and D24: a person settles, asks again or stops with an admin key or the Product's key; any
// other key is refused, and a read key never gets past the write floor.
func TestRebuildPersonActions(t *testing.T) {
	fx := newRebuildFixture(t)
	product := rebuildServer(t, fx, true, []string{"product:prod-1"})
	other := rebuildServer(t, fx, true, []string{"product:prod-2"})
	admin := rebuildServer(t, fx, true, []string{auth.ScopeAdmin})
	settle := "/rebuild-requests/" + fx.intentID + "/settle"

	if s, _ := do(t, http.MethodPost, product.URL+settle, map[string]any{"answer": "submitted", "actor": "pat"}); s != http.StatusConflict {
		t.Errorf("settling a request that is not uncertain: %d", s)
	}
	fx.requests.rows[0].State = app.RequestUncertain
	for name, tc := range map[string]struct {
		srv  *httptest.Server
		path string
		body any
		want int
	}{
		"another product's key": {other, settle, map[string]any{"answer": "submitted", "actor": "pat"}, http.StatusForbidden},
		"no actor":              {product, settle, map[string]any{"answer": "submitted", "actor": " "}, http.StatusBadRequest},
		"bad answer":            {product, settle, map[string]any{"answer": "maybe", "actor": "pat"}, http.StatusBadRequest},
		"not json":              {product, settle, "{", http.StatusBadRequest},
		"unknown request":       {product, "/rebuild-requests/nope/settle", map[string]any{"answer": "submitted", "actor": "pat"}, http.StatusNotFound},
	} {
		if s, body := do(t, http.MethodPost, tc.srv.URL+tc.path, tc.body); s != tc.want {
			t.Errorf("%s: %d %s, want %d", name, s, body, tc.want)
		}
	}
	s, body := do(t, http.MethodPost, product.URL+settle, map[string]any{"answer": "not_submitted", "actor": "pat", "note": "asked the build team"})
	if s != http.StatusOK || !strings.Contains(string(body), `"settled_by":"pat"`) || fx.state() != app.RequestNotSubmitted {
		t.Fatalf("settle: %d %s", s, body)
	}

	again := "/releases/rel-1/rebuild-cycle/request-again"
	if s, _ := do(t, http.MethodPost, other.URL+again, map[string]any{"actor": "pat"}); s != http.StatusForbidden {
		t.Errorf("request again with another product's key: %d", s)
	}
	if s, _ := do(t, http.MethodPost, admin.URL+again, map[string]any{"actor": ""}); s != http.StatusBadRequest {
		t.Errorf("request again with no actor: %d", s)
	}
	s, body = do(t, http.MethodPost, admin.URL+again, map[string]any{"actor": "pat"})
	if s != http.StatusCreated || !strings.Contains(string(body), `"try":2`) || len(fx.requests.rows) != 2 {
		t.Fatalf("request again: %d %s", s, body)
	}
	if s, _ := do(t, http.MethodPost, admin.URL+again, map[string]any{"actor": "pat"}); s != http.StatusConflict {
		t.Errorf("request again while one is on its way: %d", s)
	}

	stop := "/releases/rel-1/rebuild-cycle/stop"
	for name, tc := range map[string]struct {
		srv  *httptest.Server
		path string
		body any
		want int
	}{
		"not json":   {product, stop, "{", http.StatusBadRequest},
		"no cycle":   {admin, "/releases/rel-none/rebuild-cycle/stop", map[string]any{"actor": "pat"}, http.StatusNotFound},
		"no actor":   {product, stop, map[string]any{"actor": ""}, http.StatusBadRequest},
		"wrong key":  {other, stop, map[string]any{"actor": "pat"}, http.StatusForbidden},
		"a read key": {rebuildServer(t, fx, true, []string{auth.ScopeRead}), stop, map[string]any{"actor": "pat"}, http.StatusForbidden},
	} {
		if s, body := do(t, http.MethodPost, tc.srv.URL+tc.path, tc.body); s != tc.want {
			t.Errorf("stop, %s: %d %s, want %d", name, s, body, tc.want)
		}
	}
	s, body = do(t, http.MethodPost, product.URL+stop, map[string]any{"actor": "pat", "note": "mode is off now"})
	if s != http.StatusOK || !strings.Contains(string(body), `"state":"stopped"`) || !strings.Contains(string(body), `"closed_by":"pat"`) {
		t.Fatalf("stop: %d %s", s, body)
	}
	if s, _ := do(t, http.MethodPost, product.URL+stop, map[string]any{"actor": "pat"}); s != http.StatusNotFound {
		t.Errorf("stopping a stopped cycle: %d", s)
	}

	// Store failures are 500s; with auth off the routes are open; a node with no loop answers 503.
	fx.cycles.err = errors.New("db down")
	if s, _ := do(t, http.MethodPost, admin.URL+stop, map[string]any{"actor": "pat"}); s != http.StatusInternalServerError {
		t.Errorf("stop, store failure: %d", s)
	}
	fx.cycles.err = nil
	// Auth off: no principal, so no floor and no product check; the handler itself answers.
	repo := newRepo()
	bare := httptest.NewServer(commhttp.NewHandler(app.NewPublicationService(repo, nil, serializer.Default(), &ids{}, clk{}),
		app.NewReadService(repo, nil, serializer.Default())).WithRebuildLoop(fx.loop).Router())
	defer bare.Close()
	if s, _ := do(t, http.MethodPost, bare.URL+settle, map[string]any{"answer": "submitted", "actor": "pat"}); s != http.StatusConflict {
		t.Errorf("auth off reaches the handler: %d", s)
	}
	off := rebuildServer(t, fx, false, []string{auth.ScopeAdmin})
	for _, path := range []string{settle, again, stop} {
		if s, _ := do(t, http.MethodPost, off.URL+path, map[string]any{"actor": "pat", "answer": "submitted"}); s != http.StatusServiceUnavailable {
			t.Errorf("no loop, %s: %d", path, s)
		}
	}
}
