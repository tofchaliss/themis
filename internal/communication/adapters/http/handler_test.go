package http_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	commhttp "github.com/themis-project/themis/internal/communication/adapters/http"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/adapters/store"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// --- in-memory repo ------------------------------------------------------------------

type memRepo struct {
	pubs     map[domain.PublicationID]domain.Publication
	queue    []app.QueueEntry
	listErr  error
	queueErr error
}

func newRepo() *memRepo { return &memRepo{pubs: map[domain.PublicationID]domain.Publication{}} }

func (r *memRepo) CurrentPublication(context.Context, string, string, domain.ArtifactType, string) (domain.Publication, bool, error) {
	return domain.Publication{}, false, nil
}
func (r *memRepo) GetByID(_ context.Context, id domain.PublicationID) (domain.Publication, error) {
	p, ok := r.pubs[id]
	if !ok {
		return domain.Publication{}, store.ErrNotFound
	}
	return p, nil
}
func (r *memRepo) Save(_ context.Context, pub domain.Publication, _ *domain.Publication, _ int, _ []app.OutboxNote) error {
	r.pubs[pub.ID()] = pub
	return nil
}
func (r *memRepo) MarkPublishable(_ context.Context, e app.QueueEntry) error {
	r.queue = append(r.queue, e)
	return nil
}
func (r *memRepo) UndeliveredPublications(context.Context, int) ([]domain.Publication, error) {
	return nil, nil
}
func (r *memRepo) UpdateDelivery(_ context.Context, pub domain.Publication, _ int, _ []app.OutboxNote) error {
	r.pubs[pub.ID()] = pub
	return nil
}
func (r *memRepo) ListByRelease(_ context.Context, releaseID string) ([]domain.Publication, error) {
	if r.listErr != nil {
		return nil, r.listErr
	}
	var out []domain.Publication
	for _, p := range r.pubs {
		if p.Lineage().ReleaseID == releaseID {
			out = append(out, p)
		}
	}
	return out, nil
}
func (r *memRepo) PublishableQueue(context.Context) ([]app.QueueEntry, error) {
	if r.queueErr != nil {
		return nil, r.queueErr
	}
	return r.queue, nil
}
func (r *memRepo) PrunePayloads(context.Context, time.Time) (int, error) { return 0, nil }

type fakePositions struct {
	snap  domain.PositionSnapshot
	found bool
	err   error
}

func (f fakePositions) GetPosition(context.Context, string) (domain.PositionSnapshot, bool, error) {
	return f.snap, f.found, f.err
}

type ids struct{ n int }

func (g *ids) NewID() string { g.n++; return "pub-1" }

type clk struct{}

func (clk) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

func snapshot() domain.PositionSnapshot {
	return domain.PositionSnapshot{
		FindingID: "fnd-1", Version: 2, Stance: domain.StanceNotAffected, Rationale: "vendor VEX confirms",
		Lineage: domain.Lineage{ReleaseID: "rel-1", FindingID: "fnd-1", FaultlineID: "fl-1", CVE: "CVE-2024-1"},
	}
}

func server(t *testing.T, repo *memRepo, pos app.PositionReader) *httptest.Server {
	t.Helper()
	write := app.NewPublicationService(repo, pos, serializer.Default(), &ids{}, clk{})
	read := app.NewReadService(repo, pos, serializer.Default())
	srv := httptest.NewServer(commhttp.NewHandler(write, read).Router())
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, method, url string, body any) (int, []byte) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf [8192]byte
	n, _ := resp.Body.Read(buf[:])
	return resp.StatusCode, buf[:n]
}

// --- tests ---------------------------------------------------------------------------

func TestCreatePublication(t *testing.T) {
	repo := newRepo()
	srv := server(t, repo, fakePositions{snap: snapshot(), found: true})

	status, body := do(t, http.MethodPost, srv.URL+"/publications",
		map[string]any{"finding_id": "fnd-1", "artifact_type": "vex", "format": "openvex", "audience": "tooling", "channel": "export"})
	if status != http.StatusCreated {
		t.Fatalf("status = %d: %s", status, body)
	}
	var out struct {
		PublicationId string `json:"publication_id"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.PublicationId != "pub-1" {
		t.Errorf("response = %s err=%v", body, err)
	}

	// Invalid artifact type → 400.
	if status, _ := do(t, http.MethodPost, srv.URL+"/publications", map[string]any{"finding_id": "fnd-1", "artifact_type": "bogus", "format": "openvex"}); status != http.StatusBadRequest {
		t.Errorf("bad type status = %d, want 400", status)
	}
	// Malformed body → 400.
	if status, _ := doRaw(t, srv.URL+"/publications", "{not json"); status != http.StatusBadRequest {
		t.Errorf("malformed status = %d, want 400", status)
	}
	// Position not found → 404.
	nf := server(t, newRepo(), fakePositions{found: false})
	if status, _ := do(t, http.MethodPost, nf.URL+"/publications", map[string]any{"finding_id": "fnd-1", "artifact_type": "vex", "format": "openvex"}); status != http.StatusNotFound {
		t.Errorf("not-found status = %d, want 404", status)
	}
}

func TestGetAndListPublications(t *testing.T) {
	repo := newRepo()
	srv := server(t, repo, fakePositions{snap: snapshot(), found: true})
	// Create one.
	_, _ = do(t, http.MethodPost, srv.URL+"/publications", map[string]any{"finding_id": "fnd-1", "artifact_type": "vex", "format": "openvex", "audience": "tooling"})

	status, body := do(t, http.MethodGet, srv.URL+"/publications/pub-1", nil)
	if status != http.StatusOK {
		t.Fatalf("get status = %d: %s", status, body)
	}
	var v struct {
		Id      string `json:"id"`
		Stance  string `json:"stance"`
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if v.Id != "pub-1" || v.Stance != "not_affected" || v.Payload == "" {
		t.Errorf("view = %+v", v)
	}
	// Unknown → 404.
	if status, _ := do(t, http.MethodGet, srv.URL+"/publications/ghost", nil); status != http.StatusNotFound {
		t.Errorf("unknown status = %d, want 404", status)
	}

	// List by release.
	if status, listBody := do(t, http.MethodGet, srv.URL+"/publications?release=rel-1", nil); status != http.StatusOK {
		t.Errorf("list status = %d: %s", status, listBody)
	}
	// List error → 500.
	le := newRepo()
	le.listErr = errors.New("db down")
	leSrv := server(t, le, fakePositions{})
	if status, _ := do(t, http.MethodGet, leSrv.URL+"/publications?release=rel-1", nil); status != http.StatusInternalServerError {
		t.Errorf("list error status = %d, want 500", status)
	}
}

func TestPreview(t *testing.T) {
	srv := server(t, newRepo(), fakePositions{snap: snapshot(), found: true})

	status, body := do(t, http.MethodPost, srv.URL+"/previews", map[string]any{"finding_id": "fnd-1", "artifact_type": "advisory", "format": "markdown"})
	if status != http.StatusOK {
		t.Fatalf("preview status = %d: %s", status, body)
	}
	var v struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(body, &v); err != nil || v.Payload == "" {
		t.Errorf("preview = %s err=%v", body, err)
	}

	// Bad type → 400; malformed → 400.
	if status, _ := do(t, http.MethodPost, srv.URL+"/previews", map[string]any{"finding_id": "fnd-1", "artifact_type": "bogus", "format": "markdown"}); status != http.StatusBadRequest {
		t.Errorf("bad type status = %d, want 400", status)
	}
	if status, _ := doRaw(t, srv.URL+"/previews", "{oops"); status != http.StatusBadRequest {
		t.Errorf("malformed status = %d, want 400", status)
	}
	// No position → 404.
	nf := server(t, newRepo(), fakePositions{found: false})
	if status, _ := do(t, http.MethodPost, nf.URL+"/previews", map[string]any{"finding_id": "fnd-1", "artifact_type": "vex", "format": "openvex"}); status != http.StatusNotFound {
		t.Errorf("no-position status = %d, want 404", status)
	}
	// GetPosition error → 500.
	ee := server(t, newRepo(), fakePositions{err: errors.New("gov down")})
	if status, _ := do(t, http.MethodPost, ee.URL+"/previews", map[string]any{"finding_id": "fnd-1", "artifact_type": "vex", "format": "openvex"}); status != http.StatusInternalServerError {
		t.Errorf("position error status = %d, want 500", status)
	}
}

func TestPublishableQueue(t *testing.T) {
	repo := newRepo()
	repo.queue = []app.QueueEntry{{FindingID: "fnd-1", ReleaseID: "rel-1", Stance: domain.StanceAffected, Stale: true}}
	srv := server(t, repo, fakePositions{})

	status, body := do(t, http.MethodGet, srv.URL+"/publishable-positions", nil)
	if status != http.StatusOK {
		t.Fatalf("queue status = %d: %s", status, body)
	}
	var q []map[string]any
	if err := json.Unmarshal(body, &q); err != nil || len(q) != 1 {
		t.Errorf("queue = %v err=%v", q, err)
	}

	// Error → 500.
	qe := newRepo()
	qe.queueErr = errors.New("db down")
	qeSrv := server(t, qe, fakePositions{})
	if status, _ := do(t, http.MethodGet, qeSrv.URL+"/publishable-positions", nil); status != http.StatusInternalServerError {
		t.Errorf("queue error status = %d, want 500", status)
	}
}

func doRaw(t *testing.T, url, raw string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(url, "application/json", bytes.NewReader([]byte(raw)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf [4096]byte
	n, _ := resp.Body.Read(buf[:])
	return resp.StatusCode, buf[:n]
}
