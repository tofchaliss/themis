package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	knhttp "github.com/themis-project/themis/internal/knowledge/adapters/http"
	"github.com/themis-project/themis/internal/knowledge/app"
	"github.com/themis-project/themis/internal/knowledge/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

// bulletinMem is an in-memory register with the store's contract (one live bulletin ID / CVE).
type bulletinMem struct {
	rows    []domain.Bulletin
	removed map[string]bool
	hist    map[string][]app.BulletinChange
	err     error
}

func newBulletinMem() *bulletinMem {
	return &bulletinMem{removed: map[string]bool{}, hist: map[string][]app.BulletinChange{}}
}

func (m *bulletinMem) find(id string) int {
	for i, b := range m.rows {
		if b.ID == id && !m.removed[id] {
			return i
		}
	}
	return -1
}

func (m *bulletinMem) clash(b domain.Bulletin) bool {
	for _, o := range m.rows {
		if o.ID != b.ID && !m.removed[o.ID] && (o.BulletinID == b.BulletinID || (b.CVE != "" && o.CVE == b.CVE)) {
			return true
		}
	}
	return false
}

func (m *bulletinMem) ListBulletins(context.Context) ([]domain.Bulletin, error) {
	var out []domain.Bulletin
	for _, b := range m.rows {
		if !m.removed[b.ID] {
			out = append(out, b)
		}
	}
	return out, m.err
}

func (m *bulletinMem) GetBulletin(_ context.Context, id string) (domain.Bulletin, error) {
	if m.err != nil {
		return domain.Bulletin{}, m.err
	}
	i := m.find(id)
	if i < 0 {
		return domain.Bulletin{}, app.ErrBulletinNotFound
	}
	return m.rows[i], nil
}

func (m *bulletinMem) CreateBulletin(_ context.Context, b domain.Bulletin) error {
	if m.clash(b) {
		return app.ErrBulletinConflict
	}
	m.rows = append(m.rows, b)
	m.hist[b.ID] = append(m.hist[b.ID], app.BulletinChange{At: b.CreatedAt, Actor: b.CreatedBy, Action: app.BulletinCreated, After: &b})
	return nil
}

func (m *bulletinMem) UpdateBulletin(_ context.Context, before, after domain.Bulletin) error {
	if m.clash(after) {
		return app.ErrBulletinConflict
	}
	m.rows[m.find(after.ID)] = after
	m.hist[after.ID] = append(m.hist[after.ID], app.BulletinChange{At: after.UpdatedAt, Actor: after.UpdatedBy, Action: app.BulletinUpdated, Before: &before, After: &after})
	return nil
}

func (m *bulletinMem) RemoveBulletin(_ context.Context, b domain.Bulletin, actor string, at time.Time) error {
	m.removed[b.ID] = true
	m.hist[b.ID] = append(m.hist[b.ID], app.BulletinChange{At: at, Actor: actor, Action: app.BulletinRemoved, Before: &b})
	return nil
}

func (m *bulletinMem) BulletinHistory(_ context.Context, id string) ([]app.BulletinChange, error) {
	return m.hist[id], m.err
}

type seqIDs struct{ n int }

func (g *seqIDs) NewID() string { g.n++; return "b" + string(rune('0'+g.n)) }

// asKey stands in for the auth middleware: X-Test-Scope sets a principal with that scope.
func asKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := r.Header.Get("X-Test-Scope"); s != "" {
			r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{KeyID: "k-" + s, Scopes: []string{s}}))
		}
		next.ServeHTTP(w, r)
	})
}

func bulletinServer(t *testing.T, store app.BulletinStore, src app.PublishedSource) *httptest.Server {
	t.Helper()
	repo := fakeRepo{card: sampleCard(t), found: true}
	h := knhttp.NewHandler(app.NewReadService(repo, fakeProjection{}), app.NewFeedHealthService(fakeFeedStore{}, feedClock{}))
	if store != nil {
		h = h.WithBulletins(app.NewBulletinService(store, &seqIDs{}, feedClock{}))
	}
	if src != nil {
		pub := app.NewPublishedService(src, repo, feedClock{})
		h = h.WithPublished(pub).WithPSIRT(app.NewPSIRTService(pub, psirtEstate{}, psirtSBOMs{}, psirtInv{}, nil, feedClock{}))
	}
	srv := httptest.NewServer(asKey(h.Router()))
	t.Cleanup(srv.Close)
	return srv
}

func call(t *testing.T, method, url, scope, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if scope != "" {
		req.Header.Set("X-Test-Scope", scope)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

type bulletinOut struct {
	ID         string `json:"id"`
	BulletinID string `json:"bulletin_id"`
	Title      string `json:"title"`
	CVE        string `json:"cve"`
	Note       string `json:"note"`
	ReportDate string `json:"report_date"`
	Type       string `json:"type"`
	CreatedBy  string `json:"created_by"`
	UpdatedBy  string `json:"updated_by"`
}

// EDR-PSIRT-01 revision 3: an admin creates, edits and removes; the history keeps every change
// with the key that made it; auth off records "unauthenticated".
func TestBulletinRegister_Lifecycle(t *testing.T) {
	srv := bulletinServer(t, newBulletinMem(), nil)
	u := srv.URL + "/psirt/bulletins"

	s, raw := call(t, http.MethodPost, u, auth.ScopeAdmin, `{"bulletin_id":"BUL-0001","title":"A flaw","cve":"cve-2026-1","bulletin_url":"https://example.com/b/1","report_date":"2026-11-01"}`)
	var b bulletinOut
	if s != http.StatusCreated || json.Unmarshal(raw, &b) != nil || b.ID != "b1" || b.CVE != "CVE-2026-1" || b.Type != domain.BulletinTypeVulnerability ||
		b.ReportDate != "2026-11-01" || b.CreatedBy != "key:k-admin" {
		t.Fatalf("create = %d %s", s, raw)
	}
	if s, raw := call(t, http.MethodPost, u, "", `{"bulletin_id":"BUL-0002","title":"Key compromise"}`); s != http.StatusCreated ||
		!strings.Contains(string(raw), `"created_by":"unauthenticated"`) || !strings.Contains(string(raw), `"type":"Risk"`) {
		t.Errorf("auth off create = %d %s", s, raw)
	}
	s, raw = call(t, http.MethodPut, u+"/b1", auth.ScopeAdmin, `{"bulletin_id":"BUL-0001","title":"A worse flaw","cve":"CVE-2026-1","note":"patched","alert_url":"https://example.com/a"}`)
	if s != http.StatusOK || json.Unmarshal(raw, &b) != nil || b.Title != "A worse flaw" || b.Note != "patched" || b.ReportDate != "2026-11-01" {
		t.Errorf("update = %d %s", s, raw)
	}
	s, raw = call(t, http.MethodGet, u, auth.ScopeRead, "")
	var list []bulletinOut
	if s != http.StatusOK || json.Unmarshal(raw, &list) != nil || len(list) != 2 {
		t.Errorf("list = %d %s", s, raw)
	}
	if s, raw := call(t, http.MethodDelete, u+"/b1", auth.ScopeAdmin, ""); s != http.StatusNoContent {
		t.Errorf("remove = %d %s", s, raw)
	}
	s, raw = call(t, http.MethodGet, u+"/b1/history", auth.ScopeRead, "")
	var hist []struct {
		Action string       `json:"action"`
		Actor  string       `json:"actor"`
		Before *bulletinOut `json:"before"`
		After  *bulletinOut `json:"after"`
	}
	if s != http.StatusOK || json.Unmarshal(raw, &hist) != nil || len(hist) != 3 || hist[0].Before != nil || hist[0].After == nil ||
		hist[1].Before == nil || hist[1].After == nil || hist[2].Action != app.BulletinRemoved || hist[2].After != nil || hist[2].Actor != "key:k-admin" {
		t.Errorf("history = %d %s", s, raw)
	}
	if s, raw := call(t, http.MethodGet, u+"/none/history", "", ""); s != http.StatusOK || string(raw) != "[]\n" && string(raw) != "[]" {
		t.Errorf("history of none = %d %q", s, raw)
	}
}

// Refusals map to their statuses: 400 bad body / invalid, 403 non-admin, 404, 409, 503, 500.
func TestBulletinRegister_Refusals(t *testing.T) {
	mem := newBulletinMem()
	srv := bulletinServer(t, mem, nil)
	u := srv.URL + "/psirt/bulletins"
	ok := `{"bulletin_id":"BUL-0001","title":"t","cve":"CVE-2026-1"}`

	for name, c := range map[string]struct {
		method, path, scope, body string
		want                      int
	}{
		"create bad body":    {http.MethodPost, "", auth.ScopeAdmin, `{`, http.StatusBadRequest},
		"create invalid":     {http.MethodPost, "", auth.ScopeAdmin, `{"title":"t"}`, http.StatusBadRequest},
		"create by product":  {http.MethodPost, "", auth.ProductScopePrefix + "p1", ok, http.StatusForbidden},
		"update bad body":    {http.MethodPut, "/b1", auth.ScopeAdmin, `{`, http.StatusBadRequest},
		"update unknown":     {http.MethodPut, "/nope", auth.ScopeAdmin, ok, http.StatusNotFound},
		"update by read key": {http.MethodPut, "/b1", auth.ScopeRead, ok, http.StatusForbidden},
		"remove unknown":     {http.MethodDelete, "/nope", auth.ScopeAdmin, "", http.StatusNotFound},
		"remove by product":  {http.MethodDelete, "/b1", auth.ProductScopePrefix + "p1", "", http.StatusForbidden},
	} {
		if s, raw := call(t, c.method, u+c.path, c.scope, c.body); s != c.want {
			t.Errorf("%s = %d, want %d: %s", name, s, c.want, raw)
		}
	}
	if s, _ := call(t, http.MethodPost, u, auth.ScopeAdmin, ok); s != http.StatusCreated {
		t.Fatalf("create = %d", s)
	}
	if s, _ := call(t, http.MethodPost, u, auth.ScopeAdmin, `{"bulletin_id":"BUL-0002","title":"t","cve":"CVE-2026-1"}`); s != http.StatusConflict {
		t.Errorf("same CVE twice = %d, want 409", s)
	}

	mem.err = errors.New("db down")
	if s, _ := call(t, http.MethodGet, u, "", ""); s != http.StatusInternalServerError {
		t.Errorf("store down list = %d, want 500", s)
	}
	if s, _ := call(t, http.MethodGet, u+"/b1/history", "", ""); s != http.StatusInternalServerError {
		t.Errorf("store down history = %d, want 500", s)
	}

	none := bulletinServer(t, nil, nil).URL + "/psirt/bulletins"
	for name, c := range map[string][2]string{
		"list": {http.MethodGet, ""}, "create": {http.MethodPost, ""}, "update": {http.MethodPut, "/b1"},
		"remove": {http.MethodDelete, "/b1"}, "history": {http.MethodGet, "/b1/history"},
	} {
		if s, _ := call(t, c[0], none+c[1], "", ok); s != http.StatusServiceUnavailable {
			t.Errorf("unwired %s = %d, want 503", name, s)
		}
	}
}

// An alert row whose CVE has a live bulletin carries it; a register that cannot be read leaves
// the rows without one rather than failing the alert.
func TestPSIRTAlerts_CarryBulletin(t *testing.T) {
	mem := newBulletinMem()
	src := &fakePublishedSrc{rows: []app.PublishedCVE{
		{CVE: "CVE-2026-1", Published: time.Unix(1_700_000_000, 0).UTC(), Severity: "critical", Score: 9.8},
		{CVE: "CVE-2026-2", Published: time.Unix(1_700_000_000, 0).UTC(), Severity: "high", Score: 7.5},
	}}
	srv := bulletinServer(t, mem, src)
	if s, raw := call(t, http.MethodPost, srv.URL+"/psirt/bulletins", "", `{"bulletin_id":"BUL-0001","title":"A flaw","cve":"CVE-2026-1","bulletin_url":"https://example.com/b/1"}`); s != http.StatusCreated {
		t.Fatalf("create = %d %s", s, raw)
	}
	if s, raw := call(t, http.MethodPost, srv.URL+"/psirt/bulletins", "", `{"bulletin_id":"BUL-0002","title":"No CVE"}`); s != http.StatusCreated {
		t.Fatalf("create = %d %s", s, raw)
	}
	read := func() []struct {
		Cve      string `json:"cve"`
		Bulletin *struct {
			ID          string `json:"id"`
			BulletinID  string `json:"bulletin_id"`
			BulletinURL string `json:"bulletin_url"`
		} `json:"bulletin"`
	} {
		s, raw := get(t, srv.URL+"/psirt/alerts?days=7")
		var out struct {
			Alerts []struct {
				Cve      string `json:"cve"`
				Bulletin *struct {
					ID          string `json:"id"`
					BulletinID  string `json:"bulletin_id"`
					BulletinURL string `json:"bulletin_url"`
				} `json:"bulletin"`
			} `json:"alerts"`
		}
		if s != http.StatusOK || json.Unmarshal(raw, &out) != nil {
			t.Fatalf("alerts = %d %s", s, raw)
		}
		return out.Alerts
	}
	rows := read()
	if len(rows) != 2 || rows[0].Bulletin == nil || rows[0].Bulletin.BulletinID != "BUL-0001" || rows[0].Bulletin.BulletinURL != "https://example.com/b/1" ||
		rows[1].Bulletin != nil {
		t.Errorf("rows = %+v", rows)
	}
	mem.err = errors.New("db down")
	if rows := read(); len(rows) != 2 || rows[0].Bulletin != nil {
		t.Errorf("unreadable register: %+v", rows)
	}
}
