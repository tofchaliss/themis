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
	"github.com/themis-project/themis/internal/governance/adapters/store"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

// memWatchStore is the Watch store in memory; a missing id is the store's ErrNotFound, the way
// Postgres answers, so writeErr maps it to 404.
type memWatchStore struct {
	byID    map[string]domain.Watch
	order   []string
	saveErr error
	listErr error
}

func newMemWatchStore() *memWatchStore { return &memWatchStore{byID: map[string]domain.Watch{}} }

func (m *memWatchStore) SaveWatch(_ context.Context, w domain.Watch) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	if _, ok := m.byID[w.ID()]; !ok {
		m.order = append(m.order, w.ID())
	}
	m.byID[w.ID()] = w
	return nil
}

func (m *memWatchStore) GetWatch(_ context.Context, id string) (domain.Watch, error) {
	w, ok := m.byID[id]
	if !ok {
		return domain.Watch{}, store.ErrNotFound
	}
	return w, nil
}

func (m *memWatchStore) ListWatches(context.Context) ([]domain.Watch, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	var out []domain.Watch
	for i := len(m.order) - 1; i >= 0; i-- {
		if w, ok := m.byID[m.order[i]]; ok {
			out = append(out, w)
		}
	}
	return out, nil
}

func (m *memWatchStore) DeleteWatch(_ context.Context, id string) error {
	if _, ok := m.byID[id]; !ok {
		return store.ErrNotFound
	}
	delete(m.byID, id)
	return nil
}

// stubWatchKnowledge resolves CVEs to cards and advisories to CVE sets.
type stubWatchKnowledge struct {
	cards      map[string]app.FaultlineKnowledge
	advisories map[string][]string
	err        error
}

func (k stubWatchKnowledge) FaultlineByCVE(_ context.Context, cve string) (app.FaultlineKnowledge, bool, error) {
	if k.err != nil {
		return app.FaultlineKnowledge{}, false, k.err
	}
	c, ok := k.cards[cve]
	return c, ok, nil
}

func (k stubWatchKnowledge) FaultlinesByAdvisory(_ context.Context, adv string) ([]app.FaultlineKnowledge, error) {
	if k.err != nil {
		return nil, k.err
	}
	var out []app.FaultlineKnowledge
	for _, cve := range k.advisories[adv] {
		out = append(out, k.cards[cve])
	}
	return out, nil
}

// watchServer serves the handler with a Watch service; scopes nil = auth-off node, otherwise
// every request carries a principal with those scopes.
func watchServer(t *testing.T, repo *fakeRepo, ws *memWatchStore, kn app.WatchKnowledge, scopes []string) *httptest.Server {
	t.Helper()
	write := app.NewFindingService(repo, &seqIDs{}, fixedClock{})
	read := app.NewReadService(repo, fakeProjection{}, nil, 0)
	h := govhttp.NewHandler(write, read)
	if ws != nil {
		svc := app.NewWatchService(ws, repo, kn, &seqIDs{}, fixedClock{})
		h = h.WithWatches(svc)
	}
	router := h.Router()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if scopes != nil {
			r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{KeyID: "k-1", Name: "ci-key", Scopes: scopes}))
		}
		router.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The list: create (rejected tokens reported, creator from the key), get, add (append-only),
// delete (admin), 404 on a missing id, 400 on a bad body or nothing recognised.
func TestWatches_Lifecycle(t *testing.T) {
	ws := newMemWatchStore()
	srv := watchServer(t, newRepo(), ws, stubWatchKnowledge{}, []string{auth.ScopeAdmin})

	status, body := do(t, http.MethodPost, srv.URL+"/watches", map[string]any{"name": "wave", "identifiers": "cve-2026-0001, RHSA-2026:0001 junk", "notify": true})
	if status != http.StatusCreated {
		t.Fatalf("create status = %d: %s", status, body)
	}
	var created struct {
		Watch struct {
			ID          string   `json:"id"`
			Name        string   `json:"name"`
			CreatedBy   string   `json:"created_by"`
			Identifiers []string `json:"identifiers"`
			Resolved    []string `json:"resolved_cves"`
			Notify      bool     `json:"notify"`
		} `json:"watch"`
		Added    int      `json:"added"`
		Rejected []string `json:"rejected"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Watch.Name != "wave" || created.Watch.CreatedBy != "ci-key" || len(created.Watch.Identifiers) != 2 || created.Added != 2 ||
		len(created.Rejected) != 1 || created.Rejected[0] != "JUNK" || !created.Watch.Notify || created.Watch.Resolved == nil {
		t.Errorf("created = %+v", created)
	}
	id := created.Watch.ID

	if status, _ := do(t, http.MethodPost, srv.URL+"/watches", map[string]any{"name": "", "identifiers": "CVE-2026-0001"}); status != http.StatusBadRequest {
		t.Errorf("blank name status = %d", status)
	}
	if status, body := do(t, http.MethodPost, srv.URL+"/watches", map[string]any{"name": "x", "identifiers": "foo"}); status != http.StatusBadRequest || !strings.Contains(string(body), "FOO") {
		t.Errorf("nothing recognised = %d %s", status, body)
	}
	if status, _ := doRaw(t, srv.URL+"/watches", `{not json`); status != http.StatusBadRequest {
		t.Errorf("bad body status = %d", status)
	}

	status, body = do(t, http.MethodGet, srv.URL+"/watches", nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"name":"wave"`) {
		t.Errorf("list = %d %s", status, body)
	}
	if status, body := do(t, http.MethodGet, srv.URL+"/watches/"+id, nil); status != http.StatusOK || !strings.Contains(string(body), "RHSA-2026:0001") {
		t.Errorf("get = %d %s", status, body)
	}
	if status, _ := do(t, http.MethodGet, srv.URL+"/watches/ghost", nil); status != http.StatusNotFound {
		t.Errorf("get ghost status = %d", status)
	}

	status, body = do(t, http.MethodPost, srv.URL+"/watches/"+id+"/identifiers", map[string]any{"identifiers": "CVE-2026-0001 CVE-2026-0002 nope"})
	if status != http.StatusOK || !strings.Contains(string(body), `"added":1`) || !strings.Contains(string(body), `"rejected":["NOPE"]`) {
		t.Errorf("add = %d %s", status, body)
	}
	if status, _ := do(t, http.MethodPost, srv.URL+"/watches/ghost/identifiers", map[string]any{"identifiers": "CVE-2026-0002"}); status != http.StatusNotFound {
		t.Errorf("add to ghost status = %d", status)
	}
	if status, _ := doRaw(t, srv.URL+"/watches/"+id+"/identifiers", `{not json`); status != http.StatusBadRequest {
		t.Errorf("add bad body status = %d", status)
	}

	if status, _ := do(t, http.MethodDelete, srv.URL+"/watches/"+id, nil); status != http.StatusNoContent {
		t.Errorf("delete status = %d", status)
	}
	if status, _ := do(t, http.MethodDelete, srv.URL+"/watches/"+id, nil); status != http.StatusNotFound {
		t.Errorf("second delete status = %d", status)
	}

	// Store failures are 500s.
	ws.listErr = errors.New("db down")
	if status, _ := do(t, http.MethodGet, srv.URL+"/watches", nil); status != http.StatusInternalServerError {
		t.Errorf("list failure status = %d", status)
	}
	ws.saveErr = errors.New("db down")
	if status, _ := do(t, http.MethodPost, srv.URL+"/watches", map[string]any{"name": "x", "identifiers": "CVE-2026-0001"}); status != http.StatusInternalServerError {
		t.Errorf("create failure status = %d", status)
	}
}

// Authority: a non-admin key may create and grow but not delete; on an auth-off node the
// creator comes from the body and is required.
func TestWatches_Authority(t *testing.T) {
	ws := newMemWatchStore()
	srv := watchServer(t, newRepo(), ws, stubWatchKnowledge{}, []string{"product:P1"})
	status, body := do(t, http.MethodPost, srv.URL+"/watches", map[string]any{"name": "wave", "identifiers": "CVE-2026-0001", "created_by": "ignored"})
	if status != http.StatusCreated || !strings.Contains(string(body), `"created_by":"ci-key"`) {
		t.Fatalf("product key create = %d %s", status, body)
	}
	var created struct {
		Watch struct {
			ID string `json:"id"`
		} `json:"watch"`
	}
	if err := json.Unmarshal(body, &created); err != nil || created.Watch.ID == "" {
		t.Fatalf("created body %s: %v", body, err)
	}
	id := created.Watch.ID
	if status, _ := do(t, http.MethodDelete, srv.URL+"/watches/"+id, nil); status != http.StatusForbidden {
		t.Errorf("product key delete status = %d", status)
	}

	// A key with no name is recorded by its id.
	nameless := func() *httptest.Server {
		h := govhttp.NewHandler(app.NewFindingService(newRepo(), &seqIDs{}, fixedClock{}), app.NewReadService(newRepo(), fakeProjection{}, nil, 0)).
			WithWatches(app.NewWatchService(newMemWatchStore(), newRepo(), stubWatchKnowledge{}, &seqIDs{}, fixedClock{}))
		router := h.Router()
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			router.ServeHTTP(w, r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{KeyID: "k-9", Scopes: []string{auth.ScopeAdmin}})))
		}))
		t.Cleanup(s.Close)
		return s
	}()
	if status, body := do(t, http.MethodPost, nameless.URL+"/watches", map[string]any{"name": "wave", "identifiers": "CVE-2026-0001"}); status != http.StatusCreated || !strings.Contains(string(body), `"created_by":"k-9"`) {
		t.Errorf("nameless key create = %d %s", status, body)
	}

	open := watchServer(t, newRepo(), newMemWatchStore(), stubWatchKnowledge{}, nil)
	if status, _ := do(t, http.MethodPost, open.URL+"/watches", map[string]any{"name": "wave", "identifiers": "CVE-2026-0001"}); status != http.StatusBadRequest {
		t.Errorf("auth-off without created_by status = %d", status)
	}
	if status, body := do(t, http.MethodPost, open.URL+"/watches", map[string]any{"name": "wave", "identifiers": "CVE-2026-0001", "created_by": " alice "}); status != http.StatusCreated || !strings.Contains(string(body), `"created_by":"alice"`) {
		t.Errorf("auth-off create = %d %s", status, body)
	}
}

// The table on the wire: rows with names, state, packages, fixes; identifiers with what they
// resolved to; counts; the D5 note; 503 without the Knowledge seam; 500 on an outage.
func TestWatches_Status(t *testing.T) {
	repo := newRepo()
	f := identified(t, "a1", "rel-a", "fl-1", "CVE-2026-0001")
	if _, err := f.AbsorbComponent(domain.MatchedComponent{PURL: "pkg:rpm/redhat/kernel@1.el8", Name: "kernel", Version: "1.el8", Ecosystem: "rpm", ClaimClass: "carrier"}); err != nil {
		t.Fatal(err)
	}
	repo.seed(f)
	kn := stubWatchKnowledge{
		cards:      map[string]app.FaultlineKnowledge{"CVE-2026-0001": {FaultlineID: "fl-1", CVE: "CVE-2026-0001", Fixes: []app.FixedVersion{{Package: "kernel", Version: "0:3.el8", Ecosystem: "rpm"}}}},
		advisories: map[string][]string{"RHSA-2026:0001": {"CVE-2026-0001"}},
	}
	ws := newMemWatchStore()
	srv := watchServer(t, repo, ws, kn, []string{auth.ScopeRead})
	w, err := domain.NewWatch("w-1", "wave", "alice", []string{"RHSA-2026:0001", "CVE-2026-0404"}, fixedClock{}.Now())
	if err != nil {
		t.Fatal(err)
	}
	_ = ws.SaveWatch(context.Background(), w)

	status, body := do(t, http.MethodGet, srv.URL+"/watches/w-1/status", nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d: %s", status, body)
	}
	var view struct {
		Watch struct {
			Resolved   []string `json:"resolved_cves"`
			ResolvedAt string   `json:"resolved_at"`
		} `json:"watch"`
		Identifiers []struct {
			ID       string   `json:"id"`
			Kind     string   `json:"kind"`
			Cves     []string `json:"cves"`
			Resolved bool     `json:"resolved"`
		} `json:"identifiers"`
		Rows []struct {
			ReleaseID string   `json:"release_id"`
			CVE       string   `json:"cve"`
			FindingID string   `json:"finding_id"`
			State     string   `json:"state"`
			Packages  []string `json:"packages"`
			Fixes     []string `json:"fixes"`
		} `json:"rows"`
		Counts map[string]int `json:"counts"`
		Note   string         `json:"note"`
	}
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatal(err)
	}
	if len(view.Identifiers) != 2 || view.Identifiers[0].Kind != "advisory" || !view.Identifiers[0].Resolved || len(view.Identifiers[0].Cves) != 1 ||
		view.Identifiers[1].Resolved || view.Identifiers[1].Cves == nil {
		t.Errorf("identifiers = %+v", view.Identifiers)
	}
	if len(view.Rows) != 2 || view.Rows[0].ReleaseID != "rel-a" || view.Rows[0].State != "open_fix_available" || view.Rows[0].FindingID != "a1" ||
		len(view.Rows[0].Packages) != 1 || len(view.Rows[0].Fixes) != 1 || view.Rows[1].State != "unknown" || view.Rows[1].CVE != "CVE-2026-0404" || view.Rows[1].Packages == nil {
		t.Errorf("rows = %+v", view.Rows)
	}
	if view.Counts["open_fix_available"] != 1 || view.Counts["unknown"] != 1 || !strings.Contains(view.Note, "vendor's statement") {
		t.Errorf("counts %v note %q", view.Counts, view.Note)
	}
	if len(view.Watch.Resolved) != 1 || view.Watch.ResolvedAt == "" {
		t.Errorf("recorded resolution = %+v", view.Watch)
	}
	if status, _ := do(t, http.MethodGet, srv.URL+"/watches/ghost/status", nil); status != http.StatusNotFound {
		t.Errorf("ghost status = %d", status)
	}

	// Knowledge outage ⇒ 500, never an empty table.
	down := watchServer(t, repo, ws, stubWatchKnowledge{err: errors.New("knowledge down")}, []string{auth.ScopeRead})
	if status, _ := do(t, http.MethodGet, down.URL+"/watches/w-1/status", nil); status != http.StatusInternalServerError {
		t.Errorf("outage status = %d", status)
	}
	// No Knowledge seam ⇒ 503.
	noSeam := watchServer(t, repo, ws, nil, []string{auth.ScopeRead})
	if status, _ := do(t, http.MethodGet, noSeam.URL+"/watches/w-1/status", nil); status != http.StatusServiceUnavailable {
		t.Errorf("no seam status = %d", status)
	}
}

// No Watch service wired ⇒ every /watches route is a 503 (the delete's authority check still
// comes first).
func TestWatches_Unwired(t *testing.T) {
	srv := watchServer(t, newRepo(), nil, nil, []string{auth.ScopeAdmin})
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/watches"}, {http.MethodPost, "/watches"}, {http.MethodGet, "/watches/x"},
		{http.MethodDelete, "/watches/x"}, {http.MethodPost, "/watches/x/identifiers"}, {http.MethodGet, "/watches/x/status"},
	} {
		var body any
		if c.method == http.MethodPost {
			body = map[string]any{"name": "x", "identifiers": "CVE-2026-0001"}
		}
		if status, _ := do(t, c.method, srv.URL+c.path, body); status != http.StatusServiceUnavailable {
			t.Errorf("%s %s status = %d, want 503", c.method, c.path, status)
		}
	}
}
