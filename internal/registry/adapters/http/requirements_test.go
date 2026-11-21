package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/platform/auth"
	reghttp "github.com/themis-project/themis/internal/registry/adapters/http"
	"github.com/themis-project/themis/internal/registry/adapters/http/gen"
	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

type memReqs struct {
	recs map[string][]domain.RequirementRecord
	err  error
}

func (m *memReqs) AppendRequirement(_ context.Context, r domain.RequirementRecord) error {
	if m.err != nil {
		return m.err
	}
	k := string(r.Level) + "/" + r.EntityID
	m.recs[k] = append([]domain.RequirementRecord{r}, m.recs[k]...)
	return nil
}

func (m *memReqs) RequirementHistory(_ context.Context, l domain.RequirementLevel, id string) ([]domain.RequirementRecord, error) {
	return m.recs[string(l)+"/"+id], m.err
}

func reqServer(t *testing.T, repo app.Repository, store app.RequirementStore, p *auth.Principal) *httptest.Server {
	t.Helper()
	svc := app.NewRegistryService(repo, &seqIDs{})
	if store != nil {
		svc.WithRequirements(store, func() time.Time { return time.Unix(1_700_000_000, 0) })
	}
	inner := reghttp.NewHandler(svc).Router()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p != nil {
			r = r.WithContext(auth.WithPrincipal(r.Context(), *p))
		}
		inner.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRequirements_RecordReadAndResolve(t *testing.T) {
	e := seedEstate(t)
	admin := auth.Principal{KeyID: "k-a", Name: "admin", Scopes: []string{auth.ScopeAdmin}}
	store := &memReqs{recs: map[string][]domain.RequirementRecord{}}
	srv := reqServer(t, e.repo, store, &admin)
	_, raw := post(t, srv.URL+"/releases", map[string]string{"project_id": e.p1Project, "version": "1.0"})
	rel := idOf(t, raw)

	code, body := post(t, srv.URL+"/products/"+e.p1+"/requirements", map[string]string{"cr": "L", "ir": "M", "reason": "baseline", "actor": "ops"})
	if code != http.StatusCreated {
		t.Fatalf("product = %d %s", code, body)
	}
	var rec gen.RequirementRecord
	if json.Unmarshal(body, &rec) != nil || rec.Cr != "L" || rec.Ar != "X" || rec.Via == nil || *rec.Via != "admin" {
		t.Errorf("record: %s", body)
	}
	if code, body := post(t, srv.URL+"/projects/"+e.p1Project+"/requirements", map[string]string{"ar": "H", "reason": "uptime", "actor": "ops"}); code != http.StatusCreated {
		t.Fatalf("project = %d %s", code, body)
	}
	if code, body := post(t, srv.URL+"/releases/"+rel+"/requirements", map[string]string{"cr": "H", "reason": "card data", "actor": "ops"}); code != http.StatusCreated {
		t.Fatalf("release = %d %s", code, body)
	}
	var hist gen.RequirementHistory
	if code := getJSON(t, srv.URL+"/releases/"+rel+"/requirements", &hist); code != 200 || hist.Current == nil || len(hist.History) != 1 {
		t.Errorf("history = %d %+v", code, hist)
	}
	var empty gen.RequirementHistory
	if code := getJSON(t, srv.URL+"/projects/"+e.alphaProject+"/requirements", &empty); code != 200 || empty.Current != nil || len(empty.History) != 0 {
		t.Errorf("empty = %d %+v", code, empty)
	}
	if code := getJSON(t, srv.URL+"/products/"+e.p1+"/requirements", nil); code != 200 {
		t.Errorf("product read = %d", code)
	}
	var res gen.ResolvedRequirements
	if code := getJSON(t, srv.URL+"/releases/"+rel+"/requirements/resolved", &res); code != 200 {
		t.Fatalf("resolved = %d", code)
	}
	if res.Cr.Value != "H" || res.Cr.Level != "release" || res.Ir.Value != "M" || res.Ir.Level != "product" ||
		res.Ar.Value != "H" || res.Ar.Level != "project" || res.Release == nil || res.Project == nil || res.Product == nil {
		t.Errorf("resolved: %+v", res)
	}
}

func TestRequirements_Refusals(t *testing.T) {
	e := seedEstate(t)
	store := &memReqs{recs: map[string][]domain.RequirementRecord{}}
	srv := reqServer(t, e.repo, store, nil)
	if code, _ := post(t, srv.URL+"/products/"+e.p1+"/requirements", map[string]string{"cr": "H", "actor": "ops"}); code != http.StatusBadRequest {
		t.Errorf("no reason = %d", code)
	}
	if code, _ := post(t, srv.URL+"/products/"+e.p1+"/requirements", "{"); code != http.StatusBadRequest {
		t.Errorf("bad body = %d", code)
	}
	if code, _ := post(t, srv.URL+"/products/missing/requirements", map[string]string{"reason": "r", "actor": "a"}); code != http.StatusNotFound {
		t.Errorf("unknown = %d", code)
	}
	if code := getJSON(t, srv.URL+"/releases/missing/requirements/resolved", nil); code != http.StatusNotFound {
		t.Errorf("unknown release = %d", code)
	}
	store.err = errors.New("db")
	if code, _ := post(t, srv.URL+"/products/"+e.p1+"/requirements", map[string]string{"reason": "r", "actor": "a"}); code != http.StatusInternalServerError {
		t.Errorf("store error = %d", code)
	}
	unwired := reqServer(t, e.repo, nil, nil)
	if code := getJSON(t, unwired.URL+"/products/"+e.p1+"/requirements", nil); code != http.StatusServiceUnavailable {
		t.Errorf("unwired = %d", code)
	}
	// A key scoped to another product cannot write this product's requirements.
	foreign := productKey(e.alpha)
	scoped := reqServer(t, e.repo, &memReqs{recs: map[string][]domain.RequirementRecord{}}, &foreign)
	for _, url := range []string{"/products/" + e.p1, "/projects/" + e.p1Project, "/releases/none"} {
		code, raw := post(t, scoped.URL+url+"/requirements", map[string]string{"reason": "r", "actor": "a"})
		wantForbidden(t, url, code, raw)
	}
}
