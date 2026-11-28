package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/platform/auth"
)

// memRebuild is the rebuild policy store in memory: one scope, versions counted from 1.
type memRebuild struct {
	history []app.RebuildPolicyRecord // oldest first
	err     error
}

func (m *memRebuild) RebuildPolicy(context.Context, string, string) (app.RebuildPolicyRecord, bool, error) {
	if m.err != nil || len(m.history) == 0 {
		return app.RebuildPolicyRecord{}, false, m.err
	}
	return m.history[len(m.history)-1], true, nil
}

func (m *memRebuild) PutRebuildPolicy(_ context.Context, r app.RebuildPolicyRecord) (app.RebuildPolicyRecord, error) {
	if m.err != nil {
		return app.RebuildPolicyRecord{}, m.err
	}
	r.Version = len(m.history) + 1
	m.history = append(m.history, r)
	return r, nil
}

func (m *memRebuild) RebuildPolicyHistory(context.Context, string, string) ([]app.RebuildPolicyRecord, error) {
	out := make([]app.RebuildPolicyRecord, 0, len(m.history))
	for i := len(m.history) - 1; i >= 0; i-- {
		out = append(out, m.history[i])
	}
	return out, m.err
}

// rebuildServer serves the router with the rebuild policy service wired (nil store = not wired)
// behind an injected principal (nil scopes = auth disabled).
func rebuildServer(t *testing.T, st *memRebuild, scopes []string) *httptest.Server {
	t.Helper()
	repo := newRepo()
	h := govhttp.NewHandler(app.NewFindingService(repo, &seqIDs{}, fixedClock{}), app.NewReadService(repo, fakeProjection{}, nil, 0))
	if st != nil {
		h = h.WithRebuildPolicy(app.NewRebuildPolicyService(st, fixedClock{}))
	}
	router := h.Router()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if scopes != nil {
			r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{KeyID: "k", Name: "t", Scopes: scopes}))
		}
		router.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func rebuildBody() map[string]any {
	return map[string]any{
		"fix_required": true, "severity_floor": "critical", "count_known_exploited": false,
		"skip_decided": true, "carrier_only": true, "cool_down_seconds": 3600, "mode": "auto",
		"updated_by": "alice",
	}
}

func TestRebuildPolicy_GetDefaultsPutAndHistory(t *testing.T) {
	srv := rebuildServer(t, &memRebuild{}, []string{auth.ScopeAdmin})
	code, body := do(t, http.MethodGet, srv.URL+"/rebuild-policy", nil)
	var rec gen.RebuildPolicyRecord
	if code != http.StatusOK || json.Unmarshal(body, &rec) != nil || rec.Version != 0 || rec.ScopeKind != "installation" ||
		!rec.FixRequired || rec.SeverityFloor != "high" || !rec.CountKnownExploited || !rec.SkipDecided || !rec.CarrierOnly ||
		rec.CoolDownSeconds != 86400 || rec.Mode != "ask" || rec.UpdatedAt != nil {
		t.Fatalf("defaults: %d %s", code, body)
	}
	if code, body = do(t, http.MethodGet, srv.URL+"/rebuild-policy/history", nil); code != http.StatusOK || strings.TrimSpace(string(body)) != "[]" {
		t.Fatalf("empty history: %d %s", code, body)
	}

	code, body = do(t, http.MethodPut, srv.URL+"/rebuild-policy", rebuildBody())
	rec = gen.RebuildPolicyRecord{}
	if code != http.StatusOK || json.Unmarshal(body, &rec) != nil || rec.Version != 1 || rec.Mode != "auto" ||
		rec.SeverityFloor != "critical" || rec.CountKnownExploited || rec.CoolDownSeconds != 3600 ||
		rec.UpdatedBy == nil || *rec.UpdatedBy != "alice" || rec.UpdatedAt == nil {
		t.Fatalf("put: %d %s", code, body)
	}
	second := rebuildBody()
	second["mode"], second["updated_by"] = "off", "bob"
	if code, _ = do(t, http.MethodPut, srv.URL+"/rebuild-policy", second); code != http.StatusOK {
		t.Fatalf("second put: %d", code)
	}

	// A read key reads the policy in force and its history, newest first.
	reader := rebuildServer(t, &memRebuild{}, []string{auth.ScopeRead})
	if code, _ = do(t, http.MethodGet, reader.URL+"/rebuild-policy", nil); code != http.StatusOK {
		t.Fatalf("read scope get: %d", code)
	}
	_, body = do(t, http.MethodGet, srv.URL+"/rebuild-policy", nil)
	rec = gen.RebuildPolicyRecord{}
	_ = json.Unmarshal(body, &rec)
	if rec.Version != 2 || rec.Mode != "off" {
		t.Fatalf("read back: %s", body)
	}
	_, body = do(t, http.MethodGet, srv.URL+"/rebuild-policy/history", nil)
	var hist []gen.RebuildPolicyRecord
	if json.Unmarshal(body, &hist) != nil || len(hist) != 2 || hist[0].Version != 2 || *hist[0].UpdatedBy != "bob" || hist[1].Version != 1 {
		t.Fatalf("history: %s", body)
	}
}

func TestRebuildPolicy_PutRefusals(t *testing.T) {
	for _, scopes := range [][]string{{auth.ScopeRead}, {auth.ProductScopePrefix + "prod-1"}, {auth.ScopeDeliveryCallback}} {
		st := &memRebuild{}
		srv := rebuildServer(t, st, scopes)
		if code, _ := do(t, http.MethodPut, srv.URL+"/rebuild-policy", rebuildBody()); code != http.StatusForbidden || len(st.history) != 0 {
			t.Fatalf("%v: %d, want 403 and nothing stored", scopes, code)
		}
	}
	st := &memRebuild{}
	srv := rebuildServer(t, st, nil) // auth disabled (dev) is already open
	if code, _ := do(t, http.MethodPut, srv.URL+"/rebuild-policy", rebuildBody()); code != http.StatusOK {
		t.Fatalf("auth off: %d", code)
	}
	bad := map[string]func(map[string]any){
		"unknown mode":       func(b map[string]any) { b["mode"] = "always" },
		"unknown floor":      func(b map[string]any) { b["severity_floor"] = "severe" },
		"negative cool-down": func(b map[string]any) { b["cool_down_seconds"] = -1 },
		"cool-down too long": func(b map[string]any) { b["cool_down_seconds"] = 31536001 },
		"blank actor":        func(b map[string]any) { b["updated_by"] = "  " },
		"wrong type":         func(b map[string]any) { b["fix_required"] = "yes" },
		"no fix_required":    func(b map[string]any) { delete(b, "fix_required") },
		"no skip_decided":    func(b map[string]any) { delete(b, "skip_decided") },
		"no carrier_only":    func(b map[string]any) { delete(b, "carrier_only") },
		"no known_exploited": func(b map[string]any) { delete(b, "count_known_exploited") },
		"no severity_floor":  func(b map[string]any) { delete(b, "severity_floor") },
		"no cool_down":       func(b map[string]any) { delete(b, "cool_down_seconds") },
		"no mode":            func(b map[string]any) { delete(b, "mode") },
		"no actor":           func(b map[string]any) { delete(b, "updated_by") },
	}
	for name, mutate := range bad {
		b := rebuildBody()
		mutate(b)
		if code, _ := do(t, http.MethodPut, srv.URL+"/rebuild-policy", b); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
	if len(st.history) != 1 {
		t.Fatalf("a refused change stored something: %d versions", len(st.history))
	}
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/rebuild-policy", strings.NewReader("{not json"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad json: %v %v", resp, err)
	}
	_ = resp.Body.Close()
}

// errBody fails on read, the way a client that hangs up mid-request does.
type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, errors.New("connection reset") }
func (errBody) Close() error             { return nil }

func TestRebuildPolicy_UnwiredAndStoreErrors(t *testing.T) {
	unwired := rebuildServer(t, nil, nil)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/rebuild-policy"}, {http.MethodGet, "/rebuild-policy/history"}, {http.MethodPut, "/rebuild-policy"},
	} {
		if code, _ := do(t, c.method, unwired.URL+c.path, rebuildBody()); code != http.StatusServiceUnavailable {
			t.Errorf("unwired %s %s: %d, want 503", c.method, c.path, code)
		}
	}
	failing := rebuildServer(t, &memRebuild{err: errors.New("db down")}, nil)
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/rebuild-policy"}, {http.MethodGet, "/rebuild-policy/history"}, {http.MethodPut, "/rebuild-policy"},
	} {
		if code, _ := do(t, c.method, failing.URL+c.path, rebuildBody()); code != http.StatusInternalServerError {
			t.Errorf("store error %s %s: %d, want 500", c.method, c.path, code)
		}
	}

	// A body that cannot be read is a bad request, not a stored policy.
	st := &memRebuild{}
	h := govhttp.NewHandler(app.NewFindingService(newRepo(), &seqIDs{}, fixedClock{}), app.NewReadService(newRepo(), fakeProjection{}, nil, 0)).
		WithRebuildPolicy(app.NewRebuildPolicyService(st, fixedClock{}))
	w := httptest.NewRecorder()
	h.PutRebuildPolicy(w, httptest.NewRequest(http.MethodPut, "/rebuild-policy", errBody{}))
	if w.Code != http.StatusBadRequest || len(st.history) != 0 {
		t.Fatalf("unreadable body: %d", w.Code)
	}
}
