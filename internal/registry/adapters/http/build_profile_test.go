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

	"github.com/themis-project/themis/internal/platform/auth"
	reghttp "github.com/themis-project/themis/internal/registry/adapters/http"
	"github.com/themis-project/themis/internal/registry/adapters/http/gen"
	"github.com/themis-project/themis/internal/registry/app"
	"github.com/themis-project/themis/internal/registry/domain"
)

type memProfiles struct {
	recs map[string][]domain.BuildProfileRecord
	err  error
}

func (m *memProfiles) AppendBuildProfile(_ context.Context, r domain.BuildProfileRecord) (domain.BuildProfileRecord, error) {
	if m.err != nil {
		return domain.BuildProfileRecord{}, m.err
	}
	k := string(r.Level) + "/" + r.EntityID
	r.Revision = len(m.recs[k]) + 1
	m.recs[k] = append([]domain.BuildProfileRecord{r}, m.recs[k]...)
	return r, nil
}

func (m *memProfiles) BuildProfileHistory(_ context.Context, l domain.BuildProfileLevel, id string) ([]domain.BuildProfileRecord, error) {
	return m.recs[string(l)+"/"+id], m.err
}

func profileServer(t *testing.T, repo app.Repository, store app.BuildProfileStore, p *auth.Principal) *httptest.Server {
	t.Helper()
	svc := app.NewRegistryService(repo, &seqIDs{})
	if store != nil {
		svc.WithBuildProfiles(store, func() time.Time { return time.Unix(1_700_000_000, 0) })
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

func del(t *testing.T, url string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// D10, D16: a Project profile serves its Releases, a Release's own replaces it as a whole, a
// removal gives the Project's back, and the profile is served byte for byte as stored.
func TestBuildProfile_StoreReadResolveRemove(t *testing.T) {
	e := seedEstate(t)
	admin := auth.Principal{KeyID: "k-a", Name: "admin", Scopes: []string{auth.ScopeAdmin}}
	srv := profileServer(t, e.repo, &memProfiles{recs: map[string][]domain.BuildProfileRecord{}}, &admin)
	_, raw := post(t, srv.URL+"/releases", map[string]string{"project_id": e.p1Project, "version": "1.0"})
	rel := idOf(t, raw)

	var none gen.ResolvedBuildProfile
	if code := getJSON(t, srv.URL+"/releases/"+rel+"/build-profile/resolved", &none); code != 200 || none.Found || none.Scope != nil || none.Record != nil ||
		none.ReleaseId != rel || none.ProjectId != e.p1Project {
		t.Fatalf("nothing stored = %d %+v", code, none)
	}

	// Key order z before a must survive: the digest is over these bytes.
	code, body := put(t, srv.URL+"/projects/"+e.p1Project+"/build-profile",
		`{"profile": {"z": 1, "job": "team/build-image", "parameters": {"BRANCH": "release/1"}}, "actor": "alice"}`)
	if code != http.StatusOK {
		t.Fatalf("project put = %d %s", code, body)
	}
	const stored = `{"z":1,"job":"team/build-image","parameters":{"BRANCH":"release/1"}}`
	if !strings.Contains(string(body), `"profile":`+stored) {
		t.Errorf("profile not served as stored: %s", body)
	}
	var rec gen.BuildProfileRecord
	if json.Unmarshal(body, &rec) != nil || rec.Revision != 1 || rec.Level != "project" || rec.EntityId != e.p1Project || rec.Removed ||
		rec.Actor != "alice" || rec.Via == nil || *rec.Via != "admin" || rec.Sha256 == nil || len(*rec.Sha256) != 64 || rec.Profile == nil {
		t.Errorf("record: %s", body)
	}

	var res gen.ResolvedBuildProfile
	if code := getJSON(t, srv.URL+"/releases/"+rel+"/build-profile/resolved", &res); code != 200 || !res.Found || res.Scope == nil ||
		*res.Scope != "project" || res.Record == nil || string(*res.Record.Profile) != stored || *res.Record.Sha256 != *rec.Sha256 {
		t.Fatalf("inherited = %d %+v", code, res)
	}

	if code, body := put(t, srv.URL+"/releases/"+rel+"/build-profile", `{"profile":{"job":"team/special"},"actor":"bob"}`); code != http.StatusOK {
		t.Fatalf("release put = %d %s", code, body)
	}
	if code := getJSON(t, srv.URL+"/releases/"+rel+"/build-profile/resolved", &res); code != 200 || *res.Scope != "release" ||
		string(*res.Record.Profile) != `{"job":"team/special"}` {
		t.Fatalf("own = %d %+v", code, res)
	}

	code, body = del(t, srv.URL+"/releases/"+rel+"/build-profile?actor=bob")
	var gone gen.BuildProfileRecord
	if code != http.StatusOK || json.Unmarshal(body, &gone) != nil || !gone.Removed || gone.Revision != 2 || gone.Profile != nil || gone.Sha256 != nil {
		t.Fatalf("removal = %d %s", code, body)
	}
	if code := getJSON(t, srv.URL+"/releases/"+rel+"/build-profile/resolved", &res); code != 200 || *res.Scope != "project" {
		t.Fatalf("after removal = %d %+v", code, res)
	}
	var hist gen.BuildProfileHistory
	if code := getJSON(t, srv.URL+"/releases/"+rel+"/build-profile", &hist); code != 200 || hist.Current != nil || len(hist.History) != 2 || !hist.History[0].Removed {
		t.Errorf("release history = %d %+v", code, hist)
	}
	var phist gen.BuildProfileHistory
	if code := getJSON(t, srv.URL+"/projects/"+e.p1Project+"/build-profile", &phist); code != 200 || phist.Current == nil || phist.Current.Revision != 1 || len(phist.History) != 1 {
		t.Errorf("project history = %d %+v", code, phist)
	}
	if code, _ := del(t, srv.URL+"/releases/"+rel+"/build-profile?actor=bob"); code != http.StatusNotFound {
		t.Errorf("second removal = %d", code)
	}
	if code, _ := del(t, srv.URL+"/projects/"+e.p1Project+"/build-profile?actor=alice"); code != http.StatusOK {
		t.Errorf("project removal = %d", code)
	}
}

func TestBuildProfile_Refusals(t *testing.T) {
	e := seedEstate(t)
	store := &memProfiles{recs: map[string][]domain.BuildProfileRecord{}}
	srv := profileServer(t, e.repo, store, nil)
	url := srv.URL + "/projects/" + e.p1Project + "/build-profile"

	bad := map[string]string{
		"not json":      `{`,
		"no actor":      `{"profile":{"job":"a"}}`,
		"no profile":    `{"actor":"alice"}`,
		"profile array": `{"profile":["a"],"actor":"alice"}`,
		"secret key":    `{"profile":{"parameters":{"API_TOKEN":"x"}},"actor":"alice"}`,
		"too deep":      `{"profile":{"a":{"b":{"c":{"d":{"e":{}}}}}},"actor":"alice"}`,
		"too large":     `{"profile":{"a":"` + strings.Repeat("x", domain.MaxBuildProfileBytes) + `"},"actor":"alice"}`,
		"over the body": `{"profile":{"a":"` + strings.Repeat("x", 70*1024) + `"},"actor":"alice"}`,
	}
	for name, body := range bad {
		if code, raw := put(t, url, body); code != http.StatusBadRequest {
			t.Errorf("%s = %d %s", name, code, raw)
		}
	}
	// With auth off no key name is recorded.
	code, raw := put(t, url, `{"profile":{},"actor":"alice"}`)
	var rec gen.BuildProfileRecord
	if code != http.StatusOK || json.Unmarshal(raw, &rec) != nil || rec.Via != nil {
		t.Errorf("auth off = %d %s", code, raw)
	}
	if code, _ := put(t, srv.URL+"/projects/missing/build-profile", `{"profile":{},"actor":"alice"}`); code != http.StatusNotFound {
		t.Errorf("unknown project = %d", code)
	}
	if code, _ := put(t, srv.URL+"/releases/missing/build-profile", `{"profile":{},"actor":"alice"}`); code != http.StatusNotFound {
		t.Errorf("unknown release = %d", code)
	}
	if code, _ := del(t, url+"?actor=%20"); code != http.StatusBadRequest {
		t.Errorf("removal without actor = %d", code)
	}
	if code, _ := del(t, url); code != http.StatusBadRequest {
		t.Errorf("removal with no actor parameter = %d", code)
	}
	if code := getJSON(t, srv.URL+"/releases/missing/build-profile/resolved", nil); code != http.StatusNotFound {
		t.Errorf("unknown release resolve = %d", code)
	}
	if code := getJSON(t, srv.URL+"/projects/missing/build-profile", nil); code != http.StatusNotFound {
		t.Errorf("unknown project read = %d", code)
	}
	store.err = errors.New("db")
	if code, _ := put(t, url, `{"profile":{},"actor":"alice"}`); code != http.StatusInternalServerError {
		t.Errorf("store error = %d", code)
	}
	unwired := profileServer(t, e.repo, nil, nil)
	if code := getJSON(t, unwired.URL+"/projects/"+e.p1Project+"/build-profile", nil); code != http.StatusServiceUnavailable {
		t.Errorf("unwired = %d", code)
	}

	// A key scoped to another product cannot write or remove this product's profiles.
	foreign := productKey(e.alpha)
	scoped := profileServer(t, e.repo, &memProfiles{recs: map[string][]domain.BuildProfileRecord{}}, &foreign)
	for _, path := range []string{"/projects/" + e.p1Project, "/releases/none"} {
		code, raw := put(t, scoped.URL+path+"/build-profile", `{"profile":{},"actor":"alice"}`)
		wantForbidden(t, "put "+path, code, raw)
		code, raw = del(t, scoped.URL+path+"/build-profile?actor=alice")
		wantForbidden(t, "delete "+path, code, raw)
	}
	// Its own product's project it may write.
	own := productKey(e.p1)
	mine := profileServer(t, e.repo, &memProfiles{recs: map[string][]domain.BuildProfileRecord{}}, &own)
	if code, raw := put(t, mine.URL+"/projects/"+e.p1Project+"/build-profile", `{"profile":{},"actor":"alice"}`); code != http.StatusOK {
		t.Errorf("own product key = %d %s", code, raw)
	}
}
