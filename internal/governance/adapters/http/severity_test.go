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
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

// sevStore is an in-memory OwnerSeverityStore for the route tests.
type sevStore struct {
	original app.OriginalSeverity
	history  map[domain.FindingID][]app.OwnerSeverityRecord
	err      error
}

func (m *sevStore) CurrentOwnerSeverities(_ context.Context, ids []domain.FindingID) (map[domain.FindingID]domain.OwnerSeverity, error) {
	out := map[domain.FindingID]domain.OwnerSeverity{}
	for _, id := range ids {
		for _, r := range m.history[id] {
			if r.EndedAt.IsZero() {
				out[id] = r.OwnerSeverity
			}
		}
	}
	return out, m.err
}

func (m *sevStore) OwnerSeverityHistory(_ context.Context, id domain.FindingID) ([]app.OwnerSeverityRecord, error) {
	return m.history[id], m.err
}

func (m *sevStore) OriginalSeverities(_ context.Context, ids []domain.FindingID) (map[domain.FindingID]app.OriginalSeverity, error) {
	out := map[domain.FindingID]app.OriginalSeverity{}
	for _, id := range ids {
		out[id] = m.original
	}
	return out, m.err
}

func (m *sevStore) end(id domain.FindingID, by, cause string, at time.Time) bool {
	rows := m.history[id]
	for i := range rows {
		if rows[i].EndedAt.IsZero() {
			rows[i].EndedAt, rows[i].EndedBy, rows[i].EndCause = at, by, cause
			return true
		}
	}
	return false
}

func (m *sevStore) SaveOwnerSeverities(_ context.Context, writes []app.OwnerSeverityWrite) error {
	for _, w := range writes {
		m.end(w.FindingID, w.Severity.Actor.ID, "replaced", w.Severity.SetAt)
		m.history[w.FindingID] = append(m.history[w.FindingID], app.OwnerSeverityRecord{OwnerSeverity: w.Severity})
	}
	return nil
}

func (m *sevStore) EndOwnerSeverity(_ context.Context, id domain.FindingID, by string, at time.Time) (bool, error) {
	return m.end(id, by, "removed", at), nil
}

func (m *sevStore) KeepOwnerSeverity(_ context.Context, id domain.FindingID, kept domain.SeverityKept) (bool, error) {
	rows := m.history[id]
	for i := range rows {
		if rows[i].EndedAt.IsZero() {
			k := kept
			rows[i].Kept = &k
			return true, nil
		}
	}
	return false, nil
}

type sevCandidates []domain.FindingID

func (c sevCandidates) CopyCandidates(context.Context, domain.FindingID) ([]app.CopyCandidate, error) {
	var out []app.CopyCandidate
	for _, id := range c {
		out = append(out, app.CopyCandidate{ScopeTarget: app.ScopeTarget{
			FindingID: id, ReleaseID: "rel-" + string(id), ProductID: "P1", ProjectID: "A", ProductName: "alpha", ProjectName: "project-a", Version: "1.0",
		}})
	}
	return out, nil
}

// severityServer serves the routes; scopes nil means authentication is disabled.
func severityServer(t *testing.T, st *sevStore, candidates app.SeverityCandidates, scopes []string) *httptest.Server {
	t.Helper()
	repo := newRepo()
	for _, id := range []domain.FindingID{"f1", "f2"} {
		repo.seed(domain.ReconstituteFinding(id, "rel-"+string(id), "fl", "CVE-2026-0001", nil, domain.StageIdentified, nil, nil, 1))
	}
	write := app.NewFindingService(repo, &seqIDs{}, fixedClock{})
	read := app.NewReadService(repo, fakeProjection{}, nil, 0)
	h := govhttp.NewHandler(write, read)
	if st != nil {
		h = h.WithSeverity(app.NewSeverityService(repo, st, candidates, fixedClock{}))
	}
	router := h.Router()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if scopes != nil {
			r = r.WithContext(auth.WithPrincipal(r.Context(), auth.Principal{KeyID: "k-1", Name: "ci", Scopes: scopes}))
		}
		router.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func sevDo(t *testing.T, method, url, body string, out any) int {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("%s %s: %v", method, url, err)
		}
	}
	return resp.StatusCode
}

type sevOwner struct {
	Kind       string   `json:"kind"`
	Level      string   `json:"level"`
	Vector     string   `json:"vector"`
	Score      float64  `json:"score"`
	Original   *float64 `json:"original_score"`
	Reason     string   `json:"reason"`
	SetBy      string   `json:"set_by"`
	PickedFrom string   `json:"picked_from"`
	EndCause   string   `json:"end_cause"`
	EndedBy    string   `json:"ended_by"`
	Review     string   `json:"review_reason"`
	KeptBy     string   `json:"kept_by"`
	OrigVector string   `json:"original_vector"`
}

type sevView struct {
	FindingID        string     `json:"finding_id"`
	CVE              string     `json:"cve"`
	OriginalScore    *float64   `json:"original_score"`
	OriginalSeverity string     `json:"original_severity"`
	OriginalVector   string     `json:"original_vector"`
	Owner            *sevOwner  `json:"owner"`
	History          []sevOwner `json:"history"`
}

func newSevStore() *sevStore {
	score := 9.8
	return &sevStore{
		original: app.OriginalSeverity{Score: &score, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		history:  map[domain.FindingID][]app.OwnerSeverityRecord{},
	}
}

func TestSeverityRoutesSetReadRemove(t *testing.T) {
	st := newSevStore()
	srv := severityServer(t, st, sevCandidates{"f2"}, nil)
	base := srv.URL + "/findings/f1/severity"

	var v sevView
	if code := sevDo(t, http.MethodGet, base, "", &v); code != http.StatusOK {
		t.Fatalf("read = %d", code)
	}
	if v.CVE != "CVE-2026-0001" || v.OriginalScore == nil || *v.OriginalScore != 9.8 || v.OriginalSeverity != "critical" ||
		v.OriginalVector == "" || v.Owner != nil || v.History == nil || len(v.History) != 0 {
		t.Fatalf("view = %+v", v)
	}

	var p struct {
		Kind   string  `json:"kind"`
		Level  string  `json:"level"`
		Score  float64 `json:"score"`
		Vector string  `json:"vector"`
	}
	if code := sevDo(t, http.MethodPost, base+"/preview", `{"vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"}`, &p); code != http.StatusOK ||
		p.Kind != "vector" || p.Score != 8.1 || p.Level != "high" || p.Vector == "" {
		t.Fatalf("vector preview = %d %+v", code, p)
	}
	p.Vector = ""
	if code := sevDo(t, http.MethodPost, base+"/preview", `{"level":"medium"}`, &p); code != http.StatusOK || p.Score != 6.9 || p.Vector != "" {
		t.Fatalf("level preview = %d %+v", code, p)
	}

	var res struct {
		Applied  int     `json:"applied"`
		Replaced int     `json:"replaced"`
		Severity sevView `json:"severity"`
	}
	body := `{"actor_id":"alice","reason":"not reachable","level":"medium","apply_to":["f2"]}`
	if code := sevDo(t, http.MethodPut, base, body, &res); code != http.StatusOK {
		t.Fatalf("set = %d", code)
	}
	o := res.Severity.Owner
	if res.Applied != 2 || res.Replaced != 0 || o == nil || o.Kind != "level" || o.Level != "medium" || o.Score != 6.9 ||
		o.SetBy != "dev:alice" || o.Reason != "not reachable" || o.Vector != "" || *o.Original != 9.8 {
		t.Fatalf("set result = %+v owner %+v", res, o)
	}

	var targets struct {
		Count   int `json:"count"`
		With    int `json:"with_owner_severity"`
		Targets []struct {
			FindingID   string    `json:"finding_id"`
			ProjectName string    `json:"project_name"`
			Owner       *sevOwner `json:"owner"`
		} `json:"targets"`
	}
	if code := sevDo(t, http.MethodGet, base+"/targets", "", &targets); code != http.StatusOK {
		t.Fatalf("targets = %d", code)
	}
	if targets.Count != 1 || targets.With != 1 || targets.Targets[0].FindingID != "f2" || targets.Targets[0].ProjectName != "project-a" ||
		targets.Targets[0].Owner == nil || targets.Targets[0].Owner.PickedFrom != "f1" {
		t.Fatalf("targets = %+v", targets)
	}

	// A changed vector replaces the level; then removal brings the original back.
	body = `{"actor_id":"alice","reason":"needs a login","vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"}`
	if code := sevDo(t, http.MethodPut, base, body, &res); code != http.StatusOK || res.Replaced != 1 || res.Severity.Owner.Vector == "" {
		t.Fatalf("vector set = %d %+v", code, res)
	}
	if code := sevDo(t, http.MethodPost, base+"/remove", `{"actor_id":"alice"}`, &v); code != http.StatusOK {
		t.Fatalf("remove = %d", code)
	}
	if v.Owner != nil || len(v.History) != 2 || v.History[0].EndCause != "replaced" || v.History[1].EndCause != "removed" || v.History[1].EndedBy != "dev:alice" {
		t.Fatalf("after remove = %+v", v)
	}
	if code := sevDo(t, http.MethodPost, base+"/remove", `{"actor_id":"alice"}`, nil); code != http.StatusNotFound {
		t.Fatalf("second remove = %d", code)
	}
}

func TestSeverityRoutesRefusals(t *testing.T) {
	st := newSevStore()
	srv := severityServer(t, st, sevCandidates{"f2"}, nil)
	base := srv.URL + "/findings/f1/severity"
	cases := []struct {
		name, method, url, body string
		want                    int
	}{
		{"no reason", http.MethodPut, base, `{"actor_id":"a","reason":" ","level":"low"}`, http.StatusBadRequest},
		{"level and vector", http.MethodPut, base, `{"actor_id":"a","reason":"r","level":"low","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}`, http.StatusBadRequest},
		{"unknown level", http.MethodPut, base, `{"actor_id":"a","reason":"r","level":"severe"}`, http.StatusBadRequest},
		{"bad vector", http.MethodPut, base, `{"actor_id":"a","reason":"r","vector":"CVSS:4.0/AV:N"}`, http.StatusBadRequest},
		{"pick outside the product", http.MethodPut, base, `{"actor_id":"a","reason":"r","level":"low","apply_to":["zz"]}`, http.StatusBadRequest},
		{"no actor", http.MethodPut, base, `{"actor_id":" ","reason":"r","level":"low"}`, http.StatusBadRequest},
		{"bad set body", http.MethodPut, base, `{`, http.StatusBadRequest},
		{"unknown finding", http.MethodPut, srv.URL + "/findings/nope/severity", `{"actor_id":"a","reason":"r","level":"low"}`, http.StatusNotFound},
		{"remove with no actor", http.MethodPost, base + "/remove", `{"actor_id":""}`, http.StatusBadRequest},
		{"bad remove body", http.MethodPost, base + "/remove", `{`, http.StatusBadRequest},
		{"keep with none in force", http.MethodPost, base + "/keep", `{"actor_id":"a"}`, http.StatusNotFound},
		{"keep with no actor", http.MethodPost, base + "/keep", `{"actor_id":""}`, http.StatusBadRequest},
		{"bad keep body", http.MethodPost, base + "/keep", `{`, http.StatusBadRequest},
		{"empty preview", http.MethodPost, base + "/preview", `{}`, http.StatusBadRequest},
		{"bad preview body", http.MethodPost, base + "/preview", `{`, http.StatusBadRequest},
		{"read unknown finding", http.MethodGet, srv.URL + "/findings/nope/severity", "", http.StatusNotFound},
		{"targets of unknown finding", http.MethodGet, srv.URL + "/findings/nope/severity/targets", "", http.StatusOK},
	}
	for _, c := range cases {
		if got := sevDo(t, c.method, c.url, c.body, nil); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
	if len(st.history) != 0 {
		t.Fatalf("a refused request recorded a severity: %+v", st.history)
	}
}

func TestSeverityRoutesAdminOnlyAndUnwired(t *testing.T) {
	set := `{"actor_id":"x","reason":"r","level":"low"}`

	// A read key and a product-scoped write key read and preview, and may not set or remove.
	for _, scopes := range [][]string{{auth.ScopeRead}, {"product:P1"}} {
		srv := severityServer(t, newSevStore(), nil, scopes)
		base := srv.URL + "/findings/f1/severity"
		if code := sevDo(t, http.MethodGet, base, "", nil); code != http.StatusOK {
			t.Errorf("%v read = %d", scopes, code)
		}
		if code := sevDo(t, http.MethodPost, base+"/preview", `{"level":"low"}`, nil); code != http.StatusOK {
			t.Errorf("%v preview = %d", scopes, code)
		}
		if code := sevDo(t, http.MethodPut, base, set, nil); code != http.StatusForbidden {
			t.Errorf("%v set = %d, want 403", scopes, code)
		}
		if code := sevDo(t, http.MethodPost, base+"/remove", `{"actor_id":"x"}`, nil); code != http.StatusForbidden {
			t.Errorf("%v remove = %d, want 403", scopes, code)
		}
		if code := sevDo(t, http.MethodPost, base+"/keep", `{"actor_id":"x"}`, nil); code != http.StatusForbidden {
			t.Errorf("%v keep = %d, want 403", scopes, code)
		}
	}

	// An admin key sets it, and the record names the key, not the declared actor.
	st := newSevStore()
	srv := severityServer(t, st, nil, []string{auth.ScopeAdmin})
	base := srv.URL + "/findings/f1/severity"
	var res struct {
		Severity sevView `json:"severity"`
	}
	if code := sevDo(t, http.MethodPut, base, set, &res); code != http.StatusOK || res.Severity.Owner == nil || res.Severity.Owner.SetBy != "key:k-1" {
		t.Fatalf("admin set = %d %+v", code, res.Severity.Owner)
	}
	// No Registry seam: the pick list is unavailable, and so is a request that picks.
	if code := sevDo(t, http.MethodGet, base+"/targets", "", nil); code != http.StatusServiceUnavailable {
		t.Errorf("targets with no seam = %d", code)
	}
	if code := sevDo(t, http.MethodPut, base, `{"actor_id":"x","reason":"r","level":"low","apply_to":["f2"]}`, nil); code != http.StatusServiceUnavailable {
		t.Errorf("pick with no seam = %d", code)
	}
	// A store failure is a 500, on every route.
	st.err = errors.New("boom")
	for _, c := range []struct{ method, url, body string }{
		{http.MethodGet, base, ""}, {http.MethodPost, base + "/preview", `{"level":"low"}`},
	} {
		if code := sevDo(t, c.method, c.url, c.body, nil); code != http.StatusInternalServerError {
			t.Errorf("%s %s with a failing store = %d", c.method, c.url, code)
		}
	}

	// Not wired: every route answers 503.
	unwired := severityServer(t, nil, nil, nil)
	ubase := unwired.URL + "/findings/f1/severity"
	for _, c := range []struct{ method, url, body string }{
		{http.MethodGet, ubase, ""}, {http.MethodPut, ubase, set}, {http.MethodPost, ubase + "/remove", `{"actor_id":"x"}`},
		{http.MethodPost, ubase + "/preview", `{"level":"low"}`}, {http.MethodGet, ubase + "/targets", ""},
		{http.MethodPost, ubase + "/keep", `{"actor_id":"x"}`},
	} {
		if code := sevDo(t, c.method, c.url, c.body, nil); code != http.StatusServiceUnavailable {
			t.Errorf("unwired %s %s = %d", c.method, c.url, code)
		}
	}
}

// OS6 over the wire: a changed original shows as review_reason on the severity in force and on
// the release posture; keep clears it and names who kept it.
func TestSeverityRoutesReviewAndKeep(t *testing.T) {
	st := newSevStore()
	srv := severityServer(t, st, nil, nil)
	base := srv.URL + "/findings/f1/severity"
	if code := sevDo(t, http.MethodPut, base, `{"actor_id":"alice","reason":"r","level":"medium"}`, nil); code != http.StatusOK {
		t.Fatalf("set = %d", code)
	}
	if code := sevDo(t, http.MethodPost, base+"/keep", `{"actor_id":"alice"}`, nil); code != http.StatusConflict {
		t.Fatalf("keep with nothing changed = %d, want 409", code)
	}
	lower := 7.5
	st.original.Score = &lower
	var v sevView
	if code := sevDo(t, http.MethodGet, base, "", &v); code != http.StatusOK || v.Owner == nil ||
		v.Owner.Review != "the original score changed from 9.8 to 7.5" || v.Owner.Score != 6.9 || v.Owner.OrigVector == "" {
		t.Fatalf("after the change = %d %+v", code, v.Owner)
	}
	v = sevView{}
	if code := sevDo(t, http.MethodPost, base+"/keep", `{"actor_id":"alice"}`, &v); code != http.StatusOK || v.Owner == nil ||
		v.Owner.Review != "" || v.Owner.KeptBy != "dev:alice" || v.Owner.Score != 6.9 {
		t.Fatalf("keep = %d %+v", code, v.Owner)
	}
}
