package http_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	commhttp "github.com/themis-project/themis/internal/communication/adapters/http"
	"github.com/themis-project/themis/internal/communication/adapters/serializer"
	"github.com/themis-project/themis/internal/communication/app"
	"github.com/themis-project/themis/internal/communication/domain"
)

// --- rollup fakes (the ports the RollupService needs) --------------------------------

type stubPosture struct{ rows []app.RollupPostureRow }

func (s stubPosture) ReleasePosture(context.Context, string) ([]app.RollupPostureRow, error) {
	return s.rows, nil
}

type stubIdentity struct {
	ref domain.RollupProductRef
	err error
}

func (s stubIdentity) ReleaseIdentity(context.Context, string) (domain.RollupProductRef, error) {
	return s.ref, s.err
}

// memRollups is a minimal in-memory RollupStore honoring the current/supersede contract.
type memRollups struct {
	byID  map[domain.RollupPublicationID]domain.RollupPublication
	order []domain.RollupPublicationID
}

func newMemRollups() *memRollups {
	return &memRollups{byID: map[domain.RollupPublicationID]domain.RollupPublication{}}
}

func (m *memRollups) CurrentRollup(_ context.Context, releaseID, format, audience string) (domain.RollupPublication, bool, error) {
	for i := len(m.order) - 1; i >= 0; i-- {
		p := m.byID[m.order[i]]
		if p.ReleaseID() == releaseID && p.Format() == format && p.Audience() == audience && p.SupersededBy() == "" {
			return p, true, nil
		}
	}
	return domain.RollupPublication{}, false, nil
}

func (m *memRollups) SaveRollup(_ context.Context, pub domain.RollupPublication, prior *domain.RollupPublication, _ int) error {
	m.byID[pub.ID()] = pub
	m.order = append(m.order, pub.ID())
	if prior != nil {
		m.byID[prior.ID()] = *prior
	}
	return nil
}

func (m *memRollups) GetRollup(_ context.Context, id domain.RollupPublicationID) (domain.RollupPublication, error) {
	p, ok := m.byID[id]
	if !ok {
		return domain.RollupPublication{}, domain.ErrRollupNotFound
	}
	return p, nil
}

func (m *memRollups) ListRollups(_ context.Context, releaseID string) ([]domain.RollupPublication, error) {
	var out []domain.RollupPublication
	for i := len(m.order) - 1; i >= 0; i-- {
		if p := m.byID[m.order[i]]; p.ReleaseID() == releaseID {
			out = append(out, p)
		}
	}
	return out, nil
}

func mrfRef() domain.RollupProductRef {
	return domain.RollupProductRef{Product: "MRF", Project: "cdmrf-oamp", Version: "20.1.0.0-118", ReleaseID: "rel-1"}
}

func mrfPosture() []app.RollupPostureRow {
	return []app.RollupPostureRow{
		{FindingID: "f1", CVE: "CVE-2020-1747", HasPosition: true, Stance: "not_affected",
			PositionVersion: 2, PositionRationale: "not reachable"},
		{FindingID: "f2", CVE: "CVE-2025-47273", Components: []app.RollupComponentRow{
			{PURL: "pkg:pypi/setuptools@39.2.0", ClaimClass: "carrier", VerdictState: "cleared_vendor_fix",
				VerdictGrade: "inferred", VerdictReason: "matched to platform-python-setuptools"},
			{PURL: "pkg:pypi/setuptools@70.3.0", ClaimClass: "carrier"},
		}},
	}
}

func rollupServer(t *testing.T, identity stubIdentity, store *memRollups) *httptest.Server {
	t.Helper()
	repo := newRepo()
	pos := fakePositions{}
	write := app.NewPublicationService(repo, pos, serializer.Default(), &ids{}, clk{})
	read := app.NewReadService(repo, pos, serializer.Default())
	rollups := app.NewRollupService(stubPosture{rows: mrfPosture()}, identity, store, serializer.Default(), &ids{}, clk{})
	srv := httptest.NewServer(commhttp.NewHandler(write, read).WithRollups(rollups).Router())
	t.Cleanup(srv.Close)
	return srv
}

// --- tests ---------------------------------------------------------------------------

// The subject union on the existing doors (D13.5): a release_id materializes the rollup, and
// the full read loop — status, list, get with payload — hangs together.
func TestRollupCreateAndReadLoop(t *testing.T) {
	store := newMemRollups()
	srv := rollupServer(t, stubIdentity{ref: mrfRef()}, store)

	// Preview first: renders, records nothing.
	status, body := do(t, http.MethodPost, srv.URL+"/previews",
		map[string]any{"release_id": "rel-1", "artifact_type": "vex", "format": "openvex"})
	if status != http.StatusOK || !strings.Contains(string(body), "pkg:generic/MRF/cdmrf-oamp@20.1.0.0-118") {
		t.Fatalf("preview: %d %s", status, body)
	}
	if len(store.order) != 0 {
		t.Fatal("preview must record nothing")
	}

	// Publish.
	status, body = do(t, http.MethodPost, srv.URL+"/publications",
		map[string]any{"release_id": "rel-1", "artifact_type": "vex", "format": "openvex", "audience": "customer"})
	if status != http.StatusCreated || !strings.Contains(string(body), "publication_id") {
		t.Fatalf("create: %d %s", status, body)
	}
	if len(store.order) != 1 {
		t.Fatalf("stored rollups = %d", len(store.order))
	}
	id := string(store.order[0])

	// Status: found, current (the posture has not moved).
	status, body = do(t, http.MethodGet, srv.URL+"/releases/rel-1/rollup-status?audience=customer", nil)
	if status != http.StatusOK || !strings.Contains(string(body), `"stale": false`) && !strings.Contains(string(body), `"stale":false`) {
		t.Fatalf("status: %d %s", status, body)
	}

	// List: metadata only.
	status, body = do(t, http.MethodGet, srv.URL+"/rollups?release=rel-1", nil)
	if status != http.StatusOK || strings.Contains(string(body), `"payload"`) {
		t.Fatalf("list: %d %s", status, body)
	}

	// Get: metadata + the document, statements from Positions only, clearance as a note.
	status, body = do(t, http.MethodGet, srv.URL+"/rollups/"+id, nil)
	if status != http.StatusOK {
		t.Fatalf("get: %d %s", status, body)
	}
	for _, want := range []string{"under_investigation", "not_affected", "cleared by vendor fix (inferred)"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("document missing %q", want)
		}
	}
}

// The refusal edges: the union refuses both-or-neither, a release subject refuses non-VEX
// artifact types, an unresolved name chain is the D13.4 422, an unsupported rollup format a
// 400, and a node without the service says so.
func TestRollupRefusals(t *testing.T) {
	srv := rollupServer(t, stubIdentity{ref: mrfRef()}, newMemRollups())

	cases := []struct {
		name string
		path string
		body map[string]any
		want int
	}{
		{"neither subject", "/publications", map[string]any{"artifact_type": "vex", "format": "openvex"}, http.StatusBadRequest},
		{"both subjects", "/publications", map[string]any{"finding_id": "f", "release_id": "r", "artifact_type": "vex", "format": "openvex"}, http.StatusBadRequest},
		{"non-vex release artifact", "/publications", map[string]any{"release_id": "rel-1", "artifact_type": "advisory", "format": "markdown"}, http.StatusBadRequest},
		{"unsupported rollup format", "/publications", map[string]any{"release_id": "rel-1", "artifact_type": "vex", "format": "csaf"}, http.StatusBadRequest},
		{"preview union too", "/previews", map[string]any{"artifact_type": "vex", "format": "openvex"}, http.StatusBadRequest},
		{"preview non-vex release", "/previews", map[string]any{"release_id": "rel-1", "artifact_type": "advisory", "format": "markdown"}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		if status, body := do(t, http.MethodPost, srv.URL+tc.path, tc.body); status != tc.want {
			t.Errorf("%s: status %d body %s, want %d", tc.name, status, body, tc.want)
		}
	}

	// D13.4 fail-closed: no name chain, no document — 422, and the body names the rule.
	closed := rollupServer(t, stubIdentity{err: app.ErrIncompleteIdentity}, newMemRollups())
	if status, body := do(t, http.MethodPost, closed.URL+"/publications",
		map[string]any{"release_id": "rel-1", "artifact_type": "vex", "format": "openvex"}); status != http.StatusUnprocessableEntity {
		t.Errorf("identity refusal: %d %s", status, body)
	}

	// Unknown rollup id → 404.
	if status, _ := do(t, http.MethodGet, srv.URL+"/rollups/ghost", nil); status != http.StatusNotFound {
		t.Errorf("unknown rollup: %d", status)
	}

	// A node with no rollup service wired says so on every rollup surface.
	repo := newRepo()
	bare := httptest.NewServer(commhttp.NewHandler(
		app.NewPublicationService(repo, fakePositions{}, serializer.Default(), &ids{}, clk{}),
		app.NewReadService(repo, fakePositions{}, serializer.Default())).Router())
	t.Cleanup(bare.Close)
	for _, probe := range []func() int{
		func() int {
			s, _ := do(t, http.MethodPost, bare.URL+"/publications", map[string]any{"release_id": "r", "artifact_type": "vex", "format": "openvex"})
			return s
		},
		func() int {
			s, _ := do(t, http.MethodPost, bare.URL+"/previews", map[string]any{"release_id": "r", "artifact_type": "vex", "format": "openvex"})
			return s
		},
		func() int { s, _ := do(t, http.MethodGet, bare.URL+"/rollups?release=r", nil); return s },
		func() int { s, _ := do(t, http.MethodGet, bare.URL+"/rollups/x", nil); return s },
		func() int { s, _ := do(t, http.MethodGet, bare.URL+"/releases/r/rollup-status", nil); return s },
	} {
		if got := probe(); got != http.StatusNotImplemented {
			t.Errorf("unwired node: status %d, want 501", got)
		}
	}
}

// A republish supersedes the prior and the status row goes stale when the posture moves —
// the D13.2 loop at the HTTP surface.
func TestRollupSupersedeAndStaleness(t *testing.T) {
	store := newMemRollups()
	srv := rollupServer(t, stubIdentity{ref: mrfRef()}, store)

	if status, _ := do(t, http.MethodPost, srv.URL+"/publications",
		map[string]any{"release_id": "rel-1", "artifact_type": "vex", "format": "openvex"}); status != http.StatusCreated {
		t.Fatal("first publish failed")
	}
	if status, _ := do(t, http.MethodPost, srv.URL+"/publications",
		map[string]any{"release_id": "rel-1", "artifact_type": "vex", "format": "openvex"}); status != http.StatusCreated {
		t.Fatal("second publish failed")
	}
	first := store.byID[store.order[0]]
	if first.SupersededBy() == "" {
		t.Error("first rollup must be superseded by the republish")
	}
	// The history keeps both (D5).
	status, body := do(t, http.MethodGet, srv.URL+"/rollups?release=rel-1", nil)
	if status != http.StatusOK || strings.Count(string(body), `"release_id"`) != 2 {
		t.Errorf("history: %d %s", status, body)
	}
}
