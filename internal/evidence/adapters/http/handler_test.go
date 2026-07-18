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

	evhttp "github.com/themis-project/themis/internal/evidence/adapters/http"
	"github.com/themis-project/themis/internal/evidence/adapters/parser"
	"github.com/themis-project/themis/internal/evidence/adapters/store"
	"github.com/themis-project/themis/internal/evidence/app"
	"github.com/themis-project/themis/internal/evidence/domain"
	"github.com/themis-project/themis/internal/kernel/value"
)

type stubTrust struct {
	out app.TrustOutcome
	err error
}

func (s stubTrust) Admit(app.TrustInput) (app.TrustOutcome, error) { return s.out, s.err }

type stubParser struct {
	inv domain.Inventory
	err error
}

func (s stubParser) Parse(context.Context, string, string, []byte) (domain.Inventory, []string, error) {
	return s.inv, nil, s.err
}

type stubSubject struct{ ok bool }

func (s stubSubject) ReleaseExists(context.Context, string) (bool, error) { return s.ok, nil }

type memRepo struct {
	byID    map[domain.EvidenceID]domain.Evidence
	created bool
	getErr  error
	listErr error
}

func (m *memRepo) Save(_ context.Context, e domain.Evidence, _ []byte, _ domain.EvidenceRegistered) (domain.EvidenceID, bool, error) {
	m.byID[e.ID()] = e
	return e.ID(), m.created, nil
}
func (m *memRepo) GetByID(_ context.Context, id domain.EvidenceID) (domain.Evidence, error) {
	if m.getErr != nil {
		return domain.Evidence{}, m.getErr
	}
	e, ok := m.byID[id]
	if !ok {
		return domain.Evidence{}, store.ErrNotFound
	}
	return e, nil
}
func (m *memRepo) GetInventory(_ context.Context, id domain.EvidenceID) (domain.Inventory, error) {
	e, ok := m.byID[id]
	if !ok {
		return domain.Inventory{}, store.ErrNotFound
	}
	return e.Inventory(), nil
}
func (m *memRepo) ListByRelease(_ context.Context, releaseID string) ([]app.EvidenceSummary, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	var out []app.EvidenceSummary
	for _, e := range m.byID {
		if e.Subject().ReleaseID == releaseID {
			out = append(out, app.EvidenceSummary{ID: e.ID(), Kind: e.Kind(), Fingerprint: e.Fingerprint().String(), FiledAt: e.FiledAt()})
		}
	}
	return out, nil
}

type stubIDs struct{}

func (stubIDs) NewID() domain.EvidenceID { return "ev-1" }

type stubClock struct{}

func (stubClock) Now() time.Time { return time.Unix(1_700_000_000, 0) }

func inventory(t *testing.T) domain.Inventory {
	t.Helper()
	p, err := value.NewPURL("pkg:deb/debian/openssl@3.0.11")
	if err != nil {
		t.Fatal(err)
	}
	return domain.NewInventory([]domain.Component{{PURL: p, Name: "openssl", Version: "3.0.11", Ecosystem: "deb"}}, nil)
}

func acceptTrust() app.TrustOutcome {
	return app.TrustOutcome{Fingerprint: value.NewContentFingerprint([]byte("raw")), Status: domain.TrustAccepted}
}

func server(trust app.TrustGate, p app.Parser, subject app.SubjectRefValidator, repo app.Repository) http.Handler {
	svc := app.NewEvidenceService(trust, p, subject, repo, stubIDs{}, stubClock{})
	return evhttp.NewHandler(svc).Router()
}

func do(t *testing.T, h http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestRegister_Created(t *testing.T) {
	repo := &memRepo{byID: map[domain.EvidenceID]domain.Evidence{}, created: true}
	h := server(stubTrust{out: acceptTrust()}, stubParser{inv: inventory(t)}, stubSubject{ok: true}, repo)

	rec := do(t, h, http.MethodPost, "/evidence", `{"kind":"sbom","format":"cyclonedx","subject_release_id":"rel-1","document":"{}"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (%s)", rec.Code, rec.Body)
	}
	var resp struct {
		Id      string `json:"id"`
		Created bool   `json:"created"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Id != "ev-1" || !resp.Created {
		t.Errorf("body = %s", rec.Body)
	}
}

func TestRegister_Idempotent200(t *testing.T) {
	repo := &memRepo{byID: map[domain.EvidenceID]domain.Evidence{}, created: false}
	h := server(stubTrust{out: acceptTrust()}, stubParser{inv: inventory(t)}, stubSubject{ok: true}, repo)
	rec := do(t, h, http.MethodPost, "/evidence", `{"kind":"sbom","subject_release_id":"rel-1","document":"{}"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRegister_Errors(t *testing.T) {
	inv := inventory(t)
	repo := func() *memRepo { return &memRepo{byID: map[domain.EvidenceID]domain.Evidence{}, created: true} }

	t.Run("bad body", func(t *testing.T) {
		h := server(stubTrust{out: acceptTrust()}, stubParser{inv: inv}, stubSubject{ok: true}, repo())
		if rec := do(t, h, http.MethodPost, "/evidence", `{not json`); rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
	t.Run("unknown subject", func(t *testing.T) {
		h := server(stubTrust{out: acceptTrust()}, stubParser{inv: inv}, stubSubject{ok: false}, repo())
		if rec := do(t, h, http.MethodPost, "/evidence", `{"kind":"sbom","subject_release_id":"nope","document":"{}"}`); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("status = %d, want 422", rec.Code)
		}
	})
	t.Run("unsupported format", func(t *testing.T) {
		ufe := &parser.UnsupportedFormatError{Requested: "trivy", Supported: []parser.Format{parser.FormatCycloneDX, parser.FormatSPDX}}
		h := server(stubTrust{out: acceptTrust()}, stubParser{err: ufe}, stubSubject{ok: true}, repo())
		rec := do(t, h, http.MethodPost, "/evidence", `{"kind":"sbom","format":"trivy","subject_release_id":"rel-1","document":"{}"}`)
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "supported_formats") {
			t.Errorf("status = %d body = %s", rec.Code, rec.Body)
		}
	})
	t.Run("build error (zero fingerprint)", func(t *testing.T) {
		h := server(stubTrust{out: app.TrustOutcome{Status: domain.TrustAccepted}}, stubParser{inv: inv}, stubSubject{ok: true}, repo())
		if rec := do(t, h, http.MethodPost, "/evidence", `{"kind":"sbom","subject_release_id":"rel-1","document":"{}"}`); rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})
}

func TestReads(t *testing.T) {
	repo := &memRepo{byID: map[domain.EvidenceID]domain.Evidence{}, created: true}
	h := server(stubTrust{out: acceptTrust()}, stubParser{inv: inventory(t)}, stubSubject{ok: true}, repo)

	// Seed one via the register endpoint.
	if rec := do(t, h, http.MethodPost, "/evidence", `{"kind":"sbom","subject_release_id":"rel-1","document":"{}"}`); rec.Code != http.StatusCreated {
		t.Fatalf("seed status = %d", rec.Code)
	}

	if rec := do(t, h, http.MethodGet, "/evidence/ev-1", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "rel-1") {
		t.Errorf("get facts: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/evidence/ev-1/inventory", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "openssl") {
		t.Errorf("get inventory: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/evidence?release=rel-1", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ev-1") {
		t.Errorf("list: %d %s", rec.Code, rec.Body)
	}

	// Not found.
	if rec := do(t, h, http.MethodGet, "/evidence/nope", ""); rec.Code != http.StatusNotFound {
		t.Errorf("get nope: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/evidence/nope/inventory", ""); rec.Code != http.StatusNotFound {
		t.Errorf("inventory nope: %d", rec.Code)
	}
}

func TestReads_ServerErrors(t *testing.T) {
	boom := errors.New("boom")
	h := server(stubTrust{}, stubParser{}, stubSubject{}, &memRepo{byID: map[domain.EvidenceID]domain.Evidence{}, getErr: boom, listErr: boom})

	if rec := do(t, h, http.MethodGet, "/evidence/ev-1", ""); rec.Code != http.StatusInternalServerError {
		t.Errorf("get 500: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/evidence?release=rel-1", ""); rec.Code != http.StatusInternalServerError {
		t.Errorf("list 500: %d", rec.Code)
	}
}
