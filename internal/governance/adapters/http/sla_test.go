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

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

type memSLA struct {
	recs   []app.SLAPolicyRecord
	getErr error
	putErr error
}

func (m *memSLA) SLAPolicies(context.Context) ([]app.SLAPolicyRecord, error) { return m.recs, m.getErr }
func (m *memSLA) PutSLAPolicy(_ context.Context, r app.SLAPolicyRecord) error {
	if m.putErr != nil {
		return m.putErr
	}
	m.recs = append(m.recs, r)
	return nil
}
func (m *memSLA) SLAFactsForRelease(context.Context, string) ([]app.SLAFacts, error) { return nil, nil }
func (m *memSLA) RunningSLAFacts(context.Context, string, int) ([]app.SLAFacts, error) {
	return nil, nil
}
func (m *memSLA) RecordSLABreach(context.Context, domain.FindingID, time.Time, app.OutboxNote) (bool, error) {
	return false, nil
}

// slaServer serves the router with the SLA service wired (nil store = not wired) behind an
// injected principal (nil scopes = auth disabled).
func slaServer(t *testing.T, st *memSLA, scopes []string) *httptest.Server {
	t.Helper()
	repo := newRepo()
	h := govhttp.NewHandler(app.NewFindingService(repo, &seqIDs{}, fixedClock{}), app.NewReadService(repo, fakeProjection{}, nil, 0))
	if st != nil {
		h = h.WithSLA(app.NewSLAService(st, nil, fixedClock{}))
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

func policyBody(scope string, criticalDays int) map[string]any {
	t := func(d int) map[string]any { return map[string]any{"days": d, "enforce": true} }
	return map[string]any{"scope": scope, "critical": t(criticalDays), "high": t(30), "medium": t(90), "low": t(180), "updated_by": "alice"}
}

func TestSLAPolicy_GetDefaultsPutAndReadBack(t *testing.T) {
	srv := slaServer(t, &memSLA{}, []string{auth.ScopeAdmin})
	code, body := do(t, http.MethodGet, srv.URL+"/sla-policy", nil)
	var set gen.SLAPolicySet
	if code != http.StatusOK || json.Unmarshal(body, &set) != nil || set.Estate.Critical.Days != 7 || set.Estate.UpdatedAt != nil || len(set.Overrides) != 0 {
		t.Fatalf("defaults: %d %s", code, body)
	}
	if code, body = do(t, http.MethodPut, srv.URL+"/sla-policy", policyBody("prod-1", 3)); code != http.StatusOK || !strings.Contains(string(body), `"updated_by":"alice"`) {
		t.Fatalf("put override: %d %s", code, body)
	}
	if code, _ = do(t, http.MethodPut, srv.URL+"/sla-policy", map[string]any{"critical": map[string]any{"days": 5, "enforce": true},
		"high": map[string]any{"days": 30, "enforce": true}, "medium": map[string]any{"days": 90, "enforce": true},
		"low": map[string]any{"days": 0, "enforce": false}, "updated_by": "alice"}); code != http.StatusOK {
		t.Fatalf("put estate without scope: %d", code)
	}
	_, body = do(t, http.MethodGet, srv.URL+"/sla-policy", nil)
	set = gen.SLAPolicySet{}
	_ = json.Unmarshal(body, &set)
	if set.Estate.Critical.Days != 5 || set.Estate.Low.Enforce || len(set.Overrides) != 1 || set.Overrides[0].Scope != "prod-1" || set.Overrides[0].Critical.Days != 3 {
		t.Fatalf("read back: %s", body)
	}
}

func TestSLAPolicy_PutRefusals(t *testing.T) {
	for _, scopes := range [][]string{{auth.ScopeRead}, {auth.ProductScopePrefix + "prod-1"}, {auth.ScopeDeliveryCallback}} {
		srv := slaServer(t, &memSLA{}, scopes)
		if code, _ := do(t, http.MethodPut, srv.URL+"/sla-policy", policyBody("prod-1", 3)); code != http.StatusForbidden {
			t.Fatalf("%v: %d, want 403", scopes, code)
		}
	}
	srv := slaServer(t, &memSLA{}, nil) // auth disabled (dev) is already open
	if code, _ := do(t, http.MethodPut, srv.URL+"/sla-policy", policyBody("", 7)); code != http.StatusOK {
		t.Fatalf("auth off: %d", code)
	}
	if code, _ := do(t, http.MethodPut, srv.URL+"/sla-policy", policyBody("", 0)); code != http.StatusBadRequest {
		t.Fatalf("enforced 0 days: %d", code)
	}
	noActor := policyBody("", 7)
	delete(noActor, "updated_by")
	if code, _ := do(t, http.MethodPut, srv.URL+"/sla-policy", noActor); code != http.StatusBadRequest {
		t.Fatalf("no actor: %d", code)
	}
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/sla-policy", strings.NewReader("{not json"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad json: %v %v", resp, err)
	}
	_ = resp.Body.Close()

	failing := slaServer(t, &memSLA{putErr: errors.New("db down"), getErr: errors.New("db down")}, nil)
	if code, _ := do(t, http.MethodPut, failing.URL+"/sla-policy", policyBody("", 7)); code != http.StatusInternalServerError {
		t.Fatalf("store error on put: %d", code)
	}
	if code, _ := do(t, http.MethodGet, failing.URL+"/sla-policy", nil); code != http.StatusInternalServerError {
		t.Fatalf("store error on get: %d", code)
	}
	unwired := slaServer(t, nil, nil)
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		if code, _ := do(t, m, unwired.URL+"/sla-policy", policyBody("", 7)); code != http.StatusServiceUnavailable {
			t.Fatalf("%s unwired: %d", m, code)
		}
	}
}

func TestPosture_CarriesSLA(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	running := domain.SLAStatus{State: domain.SLABreached, Bucket: "high", CurrentBucket: "critical", BucketChanged: true,
		PeriodStart: t0, Due: t0.Add(30 * 24 * time.Hour), DaysLeft: -2, TotalAge: 32 * 24 * time.Hour,
		UnderAcceptance: 24 * time.Hour, AcceptancePeriods: []domain.SLAPeriod{{Start: t0, End: t0.Add(24 * time.Hour), PositionVersion: 1}, {Start: t0.Add(48 * time.Hour), PositionVersion: 3}}}
	stopped := domain.SLAStatus{State: domain.SLAMet, Bucket: "low", PeriodStart: t0, Due: t0.Add(180 * 24 * time.Hour), StoppedAt: t0.Add(time.Hour)}
	proj := fakeProjection{posture: []app.PostureEntry{{FindingID: "a", SLA: &running}, {FindingID: "b", SLA: &stopped}, {FindingID: "c"}}}
	srv := server(t, newRepo(), proj)
	code, body := do(t, http.MethodGet, srv.URL+"/releases/rel-1/posture", nil)
	var rows []gen.PostureEntry
	if code != http.StatusOK || json.Unmarshal(body, &rows) != nil || len(rows) != 3 {
		t.Fatalf("posture: %d %s", code, body)
	}
	a := rows[0].Sla
	if a == nil || a.State != "breached" || *a.DaysLeft != -2 || *a.CurrentBucket != "critical" || !a.BucketChanged ||
		a.AgeDays != 32 || a.DaysUnderAcceptance != 1 || len(*a.AcceptancePeriods) != 2 || (*a.AcceptancePeriods)[1].End != nil {
		t.Fatalf("running sla: %+v", a)
	}
	b := rows[1].Sla
	if b == nil || b.State != "met" || b.DaysLeft != nil || b.StoppedAt == nil || b.CurrentBucket != nil || b.AcceptancePeriods != nil {
		t.Fatalf("stopped sla: %+v", b)
	}
	if rows[2].Sla != nil {
		t.Fatalf("no clock: %+v", rows[2].Sla)
	}
}
