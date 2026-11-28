package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/platform/auth"
)

// memRebuild is the rebuild policy store in memory: per scope, the policy in force and its
// history, versions counted from 1 across removals.
type memRebuild struct {
	cur  map[string]app.RebuildPolicyRecord
	hist map[string][]app.RebuildPolicyRecord // oldest first
	err  error
}

func (m *memRebuild) stored() int {
	n := 0
	for _, h := range m.hist {
		n += len(h)
	}
	return n
}

func (m *memRebuild) RebuildPolicy(_ context.Context, kind, id string) (app.RebuildPolicyRecord, bool, error) {
	rec, ok := m.cur[kind+"/"+id]
	return rec, ok && m.err == nil, m.err
}

func (m *memRebuild) add(r app.RebuildPolicyRecord) app.RebuildPolicyRecord {
	if m.hist == nil {
		m.cur, m.hist = map[string]app.RebuildPolicyRecord{}, map[string][]app.RebuildPolicyRecord{}
	}
	key := r.ScopeKind + "/" + r.ScopeID
	r.Version = len(m.hist[key]) + 1
	m.hist[key] = append(m.hist[key], r)
	return r
}

func (m *memRebuild) PutRebuildPolicy(_ context.Context, r app.RebuildPolicyRecord) (app.RebuildPolicyRecord, error) {
	if m.err != nil {
		return app.RebuildPolicyRecord{}, m.err
	}
	r = m.add(r)
	m.cur[r.ScopeKind+"/"+r.ScopeID] = r
	return r, nil
}

func (m *memRebuild) RemoveRebuildPolicy(_ context.Context, kind, id string, at time.Time, by string) (app.RebuildPolicyRecord, bool, error) {
	r, ok := m.cur[kind+"/"+id]
	if m.err != nil || !ok {
		return app.RebuildPolicyRecord{}, false, m.err
	}
	delete(m.cur, kind+"/"+id)
	r.UpdatedAt, r.UpdatedBy, r.Removed = at, by, true
	return m.add(r), true, nil
}

func (m *memRebuild) RebuildPolicyHistory(_ context.Context, kind, id string) ([]app.RebuildPolicyRecord, error) {
	h := m.hist[kind+"/"+id]
	out := make([]app.RebuildPolicyRecord, 0, len(h))
	for i := len(h) - 1; i >= 0; i-- {
		out = append(out, h[i])
	}
	return out, m.err
}

func (m *memRebuild) RebuildPolicies(context.Context) ([]app.RebuildPolicyRecord, error) {
	var out []app.RebuildPolicyRecord
	for _, kind := range []string{app.RebuildScopeInstallation, app.RebuildScopeProduct, app.RebuildScopeRelease} {
		var group []app.RebuildPolicyRecord
		for _, r := range m.cur {
			if r.ScopeKind == kind {
				group = append(group, r)
			}
		}
		sort.Slice(group, func(i, j int) bool { return group[i].ScopeID < group[j].ScopeID })
		out = append(out, group...)
	}
	return out, m.err
}

// rebuildOwners is both Registry seams over one map: release -> product.
type rebuildOwners struct {
	byRelease map[string]string
	err       error
}

func (o rebuildOwners) ProductOfRelease(_ context.Context, releaseID string) (string, error) {
	if o.err != nil {
		return "", o.err
	}
	p, ok := o.byRelease[releaseID]
	if !ok {
		return "", errors.New("no such release")
	}
	return p, nil
}

func (o rebuildOwners) ProductAndProjectOfRelease(ctx context.Context, releaseID string) (string, string, error) {
	p, err := o.ProductOfRelease(ctx, releaseID)
	return p, "proj-1", err
}

// rebuildServer serves the router with the rebuild policy service wired (nil store = not wired)
// behind an injected principal (nil scopes = auth disabled). owners nil = no Registry seam.
func rebuildServerWith(t *testing.T, st *memRebuild, owners *rebuildOwners, scopes []string) *httptest.Server {
	t.Helper()
	repo := newRepo()
	h := govhttp.NewHandler(app.NewFindingService(repo, &seqIDs{}, fixedClock{}), app.NewReadService(repo, fakeProjection{}, nil, 0))
	svc := app.NewRebuildPolicyService(st, fixedClock{})
	if owners != nil {
		h = h.WithProductResolver(*owners)
		svc = svc.WithIdentity(*owners)
	}
	if st != nil {
		h = h.WithRebuildPolicy(svc)
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

func rebuildServer(t *testing.T, st *memRebuild, scopes []string) *httptest.Server {
	t.Helper()
	return rebuildServerWith(t, st, nil, scopes)
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
		if code, _ := do(t, http.MethodPut, srv.URL+"/rebuild-policy", rebuildBody()); code != http.StatusForbidden || st.stored() != 0 {
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
	if st.stored() != 1 {
		t.Fatalf("a refused change stored something: %d versions", st.stored())
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
	if w.Code != http.StatusBadRequest || st.stored() != 0 {
		t.Fatalf("unreadable body: %d", w.Code)
	}
}

func getJSON[T any](t *testing.T, url string) (int, T) {
	t.Helper()
	var out T
	code, body := do(t, http.MethodGet, url, nil)
	if code == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("GET %s: %v in %s", url, err, body)
		}
	}
	return code, out
}

func TestRebuildPolicyOverrides_PutReadRemoveList(t *testing.T) {
	st := &memRebuild{}
	srv := rebuildServer(t, st, []string{auth.ScopeAdmin})

	if code, _ := do(t, http.MethodGet, srv.URL+"/products/prod-1/rebuild-policy", nil); code != http.StatusNotFound {
		t.Fatalf("no product policy yet: %d, want 404", code)
	}
	code, list := getJSON[[]gen.RebuildPolicyRecord](t, srv.URL+"/rebuild-policies")
	if code != http.StatusOK || len(list) != 1 || list[0].ScopeKind != "installation" || list[0].Version != 0 {
		t.Fatalf("empty list: %d %+v", code, list)
	}

	body := rebuildBody()
	body["mode"] = "off"
	if code, _ := do(t, http.MethodPut, srv.URL+"/products/prod-1/rebuild-policy", body); code != http.StatusOK {
		t.Fatalf("put product policy: %d", code)
	}
	if code, _ := do(t, http.MethodPut, srv.URL+"/releases/rel-1/rebuild-policy", rebuildBody()); code != http.StatusOK {
		t.Fatalf("put release policy: %d", code)
	}
	code, rec := getJSON[gen.RebuildPolicyRecord](t, srv.URL+"/products/prod-1/rebuild-policy")
	if code != http.StatusOK || rec.ScopeKind != "product" || rec.ScopeId != "prod-1" || rec.Version != 1 || rec.Mode != "off" || rec.Removed != nil {
		t.Fatalf("product policy: %d %+v", code, rec)
	}
	code, rec = getJSON[gen.RebuildPolicyRecord](t, srv.URL+"/releases/rel-1/rebuild-policy")
	if code != http.StatusOK || rec.ScopeKind != "release" || rec.ScopeId != "rel-1" || rec.Mode != "auto" {
		t.Fatalf("release policy: %d %+v", code, rec)
	}
	if _, list = getJSON[[]gen.RebuildPolicyRecord](t, srv.URL+"/rebuild-policies"); len(list) != 3 ||
		list[1].ScopeKind != "product" || list[2].ScopeKind != "release" {
		t.Fatalf("list: %+v", list)
	}

	// Removal: named, kept in the history, and the scope has no policy afterwards.
	if code, _ := do(t, http.MethodDelete, srv.URL+"/products/prod-1/rebuild-policy", nil); code != http.StatusBadRequest {
		t.Fatalf("remove without updated_by: %d, want 400", code)
	}
	if code, _ := do(t, http.MethodDelete, srv.URL+"/products/prod-1/rebuild-policy?updated_by=%20", nil); code != http.StatusBadRequest {
		t.Fatalf("remove with a blank actor: %d, want 400", code)
	}
	code, raw := do(t, http.MethodDelete, srv.URL+"/products/prod-1/rebuild-policy?updated_by=carol", nil)
	rec = gen.RebuildPolicyRecord{}
	if code != http.StatusOK || json.Unmarshal(raw, &rec) != nil || rec.Removed == nil || !*rec.Removed || rec.Version != 2 || *rec.UpdatedBy != "carol" {
		t.Fatalf("remove: %d %s", code, raw)
	}
	if code, _ := do(t, http.MethodGet, srv.URL+"/products/prod-1/rebuild-policy", nil); code != http.StatusNotFound {
		t.Fatalf("after removal: %d, want 404", code)
	}
	if code, _ := do(t, http.MethodDelete, srv.URL+"/products/prod-1/rebuild-policy?updated_by=carol", nil); code != http.StatusNotFound {
		t.Fatalf("second removal: %d, want 404", code)
	}
	code, hist := getJSON[[]gen.RebuildPolicyRecord](t, srv.URL+"/products/prod-1/rebuild-policy/history")
	if code != http.StatusOK || len(hist) != 2 || hist[0].Removed == nil || hist[1].Removed != nil {
		t.Fatalf("product history: %d %+v", code, hist)
	}
	if code, _ := do(t, http.MethodDelete, srv.URL+"/releases/rel-1/rebuild-policy?updated_by=carol", nil); code != http.StatusOK {
		t.Fatalf("remove release policy: %d", code)
	}
	if code, hist = getJSON[[]gen.RebuildPolicyRecord](t, srv.URL+"/releases/rel-1/rebuild-policy/history"); code != http.StatusOK || len(hist) != 2 {
		t.Fatalf("release history: %d %+v", code, hist)
	}
	// A blank id names no Product.
	if code, _ := do(t, http.MethodPut, srv.URL+"/products/%20/rebuild-policy", rebuildBody()); code != http.StatusBadRequest {
		t.Fatalf("blank product id: %d, want 400", code)
	}
	// A bad body is refused on an override exactly as on the installation policy.
	bad := rebuildBody()
	delete(bad, "carrier_only")
	if code, _ := do(t, http.MethodPut, srv.URL+"/releases/rel-1/rebuild-policy", bad); code != http.StatusBadRequest {
		t.Fatalf("override with a field left out: %d, want 400", code)
	}
	bad = rebuildBody()
	bad["mode"] = "always"
	if code, _ := do(t, http.MethodPut, srv.URL+"/releases/rel-1/rebuild-policy", bad); code != http.StatusBadRequest {
		t.Fatalf("override with an unknown mode: %d, want 400", code)
	}
}

// D11 item 5: admin, or the key of the Product concerned. For a Release the Product is read
// from Registry, and a Product that cannot be established refuses the change.
func TestRebuildPolicyOverrides_WhoMayChange(t *testing.T) {
	owners := &rebuildOwners{byRelease: map[string]string{"rel-1": "prod-1", "rel-9": "prod-9"}}
	own := []string{auth.ProductScopePrefix + "prod-1"}
	cases := []struct {
		name   string
		owners *rebuildOwners
		scopes []string
		path   string
		want   int
	}{
		{"admin on any product", owners, []string{auth.ScopeAdmin}, "/products/prod-9/rebuild-policy", http.StatusOK},
		{"admin on a release without Registry", nil, []string{auth.ScopeAdmin}, "/releases/rel-1/rebuild-policy", http.StatusOK},
		{"auth off", nil, nil, "/releases/rel-1/rebuild-policy", http.StatusOK},
		{"product key on its product", owners, own, "/products/prod-1/rebuild-policy", http.StatusOK},
		{"product key on its release", owners, own, "/releases/rel-1/rebuild-policy", http.StatusOK},
		{"product key on another product", owners, own, "/products/prod-9/rebuild-policy", http.StatusForbidden},
		{"product key on another product's release", owners, own, "/releases/rel-9/rebuild-policy", http.StatusForbidden},
		{"product key on an unknown release", owners, own, "/releases/rel-x/rebuild-policy", http.StatusForbidden},
		{"product key, Registry down", &rebuildOwners{err: errors.New("down")}, own, "/releases/rel-1/rebuild-policy", http.StatusForbidden},
		{"product key, no Registry seam", nil, own, "/releases/rel-1/rebuild-policy", http.StatusForbidden},
		{"read key", owners, []string{auth.ScopeRead}, "/products/prod-1/rebuild-policy", http.StatusForbidden},
		{"callback key", owners, []string{auth.ScopeDeliveryCallback}, "/releases/rel-1/rebuild-policy", http.StatusForbidden},
	}
	for _, c := range cases {
		st := &memRebuild{}
		srv := rebuildServerWith(t, st, c.owners, c.scopes)
		code, _ := do(t, http.MethodPut, srv.URL+c.path, rebuildBody())
		if code != c.want || (c.want != http.StatusOK && st.stored() != 0) {
			t.Errorf("%s: PUT %d, want %d (stored %d)", c.name, code, c.want, st.stored())
		}
		// Removal follows the same rule. Seed one policy as admin would, then try.
		seeded := &memRebuild{}
		kind, id := app.RebuildScopeProduct, strings.Split(c.path, "/")[2]
		if strings.HasPrefix(c.path, "/releases/") {
			kind = app.RebuildScopeRelease
		}
		if _, err := seeded.PutRebuildPolicy(context.Background(), app.RebuildPolicyRecord{ScopeKind: kind, ScopeID: id, UpdatedBy: "seed"}); err != nil {
			t.Fatal(err)
		}
		srv = rebuildServerWith(t, seeded, c.owners, c.scopes)
		code, _ = do(t, http.MethodDelete, srv.URL+c.path+"?updated_by=alice", nil)
		if code != c.want || (c.want != http.StatusOK && seeded.stored() != 1) {
			t.Errorf("%s: DELETE %d, want %d", c.name, code, c.want)
		}
	}
	// The policy in force and the list stay readable with a read key.
	srv := rebuildServerWith(t, &memRebuild{}, owners, []string{auth.ScopeRead})
	for _, path := range []string{"/rebuild-policies", "/releases/rel-1/rebuild-policy/in-force", "/products/prod-1/rebuild-policy/history"} {
		if code, _ := do(t, http.MethodGet, srv.URL+path, nil); code != http.StatusOK {
			t.Errorf("read key GET %s: %d", path, code)
		}
	}
}

func TestRebuildPolicyInForce_NearestWins(t *testing.T) {
	st := &memRebuild{}
	owners := &rebuildOwners{byRelease: map[string]string{"rel-1": "prod-1", "rel-2": "prod-1", "rel-3": "prod-2"}}
	srv := rebuildServerWith(t, st, owners, []string{auth.ScopeAdmin})

	code, got := getJSON[gen.RebuildPolicyInForce](t, srv.URL+"/releases/rel-1/rebuild-policy/in-force")
	if code != http.StatusOK || got.Policy.ScopeKind != "installation" || got.Policy.Version != 0 || got.ModeCeiling != "ask" ||
		got.ModeSetBy != "installation" || got.ProductId != "prod-1" || got.ReleaseId != "rel-1" || got.TagsApplied {
		t.Fatalf("defaults in force: %d %+v", code, got)
	}
	put := func(path, mode, floor string) {
		t.Helper()
		b := rebuildBody()
		b["mode"], b["severity_floor"] = mode, floor
		if code, raw := do(t, http.MethodPut, srv.URL+path, b); code != http.StatusOK {
			t.Fatalf("PUT %s: %d %s", path, code, raw)
		}
	}
	put("/rebuild-policy", "auto", "high")
	put("/products/prod-1/rebuild-policy", "ask", "medium")
	put("/releases/rel-2/rebuild-policy", "auto", "low")
	for _, c := range []struct{ release, kind, floor, ceiling, setBy string }{
		{"rel-1", "product", "medium", "ask", "policy"},
		{"rel-2", "release", "low", "auto", "installation"},
		{"rel-3", "installation", "high", "auto", "installation"},
	} {
		_, got := getJSON[gen.RebuildPolicyInForce](t, srv.URL+"/releases/"+c.release+"/rebuild-policy/in-force")
		if string(got.Policy.ScopeKind) != c.kind || string(got.Policy.SeverityFloor) != c.floor || string(got.ModeCeiling) != c.ceiling ||
			string(got.ModeSetBy) != c.setBy || got.InstallationMode != "auto" {
			t.Errorf("%s: %+v", c.release, got)
		}
	}
	// A Product that cannot be read is "cannot tell", never the installation policy.
	if code, _ := do(t, http.MethodGet, srv.URL+"/releases/rel-x/rebuild-policy/in-force", nil); code != http.StatusServiceUnavailable {
		t.Errorf("unknown release: %d, want 503", code)
	}
	noSeam := rebuildServer(t, &memRebuild{}, nil)
	if code, _ := do(t, http.MethodGet, noSeam.URL+"/releases/rel-1/rebuild-policy/in-force", nil); code != http.StatusServiceUnavailable {
		t.Errorf("no Registry seam: %d, want 503", code)
	}
}

func TestRebuildPolicyOverrides_UnwiredAndStoreErrors(t *testing.T) {
	owners := &rebuildOwners{byRelease: map[string]string{"rel-1": "prod-1"}}
	routes := []struct{ method, path string }{
		{http.MethodGet, "/rebuild-policies"},
		{http.MethodGet, "/products/prod-1/rebuild-policy"}, {http.MethodPut, "/products/prod-1/rebuild-policy"},
		{http.MethodDelete, "/products/prod-1/rebuild-policy?updated_by=alice"}, {http.MethodGet, "/products/prod-1/rebuild-policy/history"},
		{http.MethodGet, "/releases/rel-1/rebuild-policy"}, {http.MethodPut, "/releases/rel-1/rebuild-policy"},
		{http.MethodDelete, "/releases/rel-1/rebuild-policy?updated_by=alice"}, {http.MethodGet, "/releases/rel-1/rebuild-policy/history"},
		{http.MethodGet, "/releases/rel-1/rebuild-policy/in-force"},
	}
	unwired := rebuildServerWith(t, nil, owners, nil)
	failing := rebuildServerWith(t, &memRebuild{err: errors.New("db down")}, owners, nil)
	for _, c := range routes {
		var body any
		if c.method == http.MethodPut {
			body = rebuildBody()
		}
		if code, _ := do(t, c.method, unwired.URL+c.path, body); code != http.StatusServiceUnavailable {
			t.Errorf("unwired %s %s: %d, want 503", c.method, c.path, code)
		}
		if code, _ := do(t, c.method, failing.URL+c.path, body); code != http.StatusInternalServerError {
			t.Errorf("store error %s %s: %d, want 500", c.method, c.path, code)
		}
	}
}
