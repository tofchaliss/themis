package governance_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/themis-project/themis/internal/communication/adapters/governance"
	"github.com/themis-project/themis/internal/communication/domain"
)

// newGovernanceStub serves the Governance read-API shapes the client must handle. Shared so
// every test exercises the same fixtures rather than drifting copies.
func newGovernanceStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/findings/fnd-1":
			_, _ = w.Write([]byte(`{
				"id":"fnd-1","release_id":"rel-1","faultline_id":"fl-1","cve":"CVE-2024-1",
				"current_position":{"version":2,"stance":"not_affected","rationale":"vendor VEX confirms"}
			}`))
		case "/api/v1/findings/with-components":
			// Two real PURLs plus a blank entry and a whitespace-only one, which must be
			// dropped rather than become empty OpenVEX subcomponent ids.
			_, _ = w.Write([]byte(`{
				"id":"with-components","release_id":"rel-3","faultline_id":"fl-3","cve":"CVE-2024-3",
				"components":[{"purl":"pkg:pypi/urllib3@1.26.20"},{"purl":""},{"purl":"   "},{"purl":"pkg:npm/left-pad@1.3.0"}],
				"current_position":{"version":1,"stance":"affected","rationale":"in range"}
			}`))
		case "/api/v1/findings/no-position":
			_, _ = w.Write([]byte(`{"id":"no-position","release_id":"rel-2","faultline_id":"fl-2","cve":"CVE-2"}`))
		case "/api/v1/findings/bad-json":
			_, _ = w.Write([]byte(`{not json`))
		case "/api/v1/findings/boom":
			w.WriteHeader(http.StatusInternalServerError)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestGetPosition(t *testing.T) {
	srv := newGovernanceStub(t)
	defer srv.Close()

	c := governance.NewClient(srv.URL, srv.Client())
	ctx := context.Background()

	// Happy path.
	snap, found, err := c.GetPosition(ctx, "fnd-1")
	if err != nil || !found {
		t.Fatalf("get: found=%v err=%v", found, err)
	}
	if snap.Version != 2 || snap.Stance != domain.StanceNotAffected || snap.Rationale != "vendor VEX confirms" {
		t.Errorf("snapshot = %+v", snap)
	}
	if snap.Lineage.ReleaseID != "rel-1" || snap.Lineage.FaultlineID != "fl-1" || snap.Lineage.CVE != "CVE-2024-1" {
		t.Errorf("lineage = %+v", snap.Lineage)
	}

	// Finding exists but has no decision → not found.
	if _, found, err := c.GetPosition(ctx, "no-position"); err != nil || found {
		t.Errorf("no-position: found=%v err=%v", found, err)
	}
	// Unknown finding (404) → not found.
	if _, found, err := c.GetPosition(ctx, "unknown"); err != nil || found {
		t.Errorf("unknown: found=%v err=%v", found, err)
	}
	// Server error → error.
	if _, _, err := c.GetPosition(ctx, "boom"); err == nil {
		t.Error("server error: expected error")
	}
	// Malformed body → error.
	if _, _, err := c.GetPosition(ctx, "bad-json"); err == nil {
		t.Error("bad json: expected error")
	}
}

func TestGetPosition_TransportError(t *testing.T) {
	// A closed server yields a transport error.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	if _, _, err := governance.NewClient(url, nil).GetPosition(context.Background(), "fnd-1"); err == nil {
		t.Error("transport error: expected error")
	}
}

// The affected component PURLs must cross the seam: they are what a published OpenVEX document
// names as `subcomponents`, and without them a VEX statement identifies a release but nothing
// a consumer can act on (C6).
func TestGetPosition_CarriesComponentPURLs(t *testing.T) {
	srv := newGovernanceStub(t)
	defer srv.Close()
	c := governance.NewClient(srv.URL, srv.Client())

	snap, found, err := c.GetPosition(context.Background(), "with-components")
	if err != nil || !found {
		t.Fatalf("GetPosition: found=%v err=%v", found, err)
	}
	want := []string{"pkg:pypi/urllib3@1.26.20", "pkg:npm/left-pad@1.3.0"}
	if len(snap.Lineage.Components) != len(want) {
		t.Fatalf("components = %v, want %v — blank entries dropped, real ones kept", snap.Lineage.Components, want)
	}
	for i, p := range want {
		if snap.Lineage.Components[i] != p {
			t.Errorf("component %d = %q, want %q", i, snap.Lineage.Components[i], p)
		}
	}
}

// A Finding with no components yields nil rather than an empty slice, so the serializer omits
// `subcomponents` entirely instead of emitting an empty array.
func TestGetPosition_NoComponentsYieldsNil(t *testing.T) {
	srv := newGovernanceStub(t)
	defer srv.Close()
	c := governance.NewClient(srv.URL, srv.Client())

	snap, found, err := c.GetPosition(context.Background(), "fnd-1")
	if err != nil || !found {
		t.Fatalf("GetPosition: found=%v err=%v", found, err)
	}
	if snap.Lineage.Components != nil {
		t.Errorf("components = %v, want nil", snap.Lineage.Components)
	}
}

// The rollup's first read (D13.5): the posture rows decode with the decided half (stance,
// position version, rationale) and the per-component verdict fields the annotations are
// built from — and absent additive fields read as their zero values.
func TestReleasePosture(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/releases/rel-1/posture" {
			t.Errorf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`[
		  {"finding_id":"f1","faultline_id":"fl1","cve":"CVE-2020-1747","stance":"not_affected",
		   "has_position":true,"position_version":2,"position_rationale":"not reachable",
		   "components":[{"purl":"pkg:rpm/x@1","claim_class":"carrier"}]},
		  {"finding_id":"f2","faultline_id":"fl2","cve":"CVE-2025-47273",
		   "components":[{"purl":"pkg:pypi/setuptools@39.2.0","claim_class":"carrier",
		     "verdict_state":"cleared_vendor_fix","verdict_grade":"inferred","verdict_reason":"matched"}]}
		]`))
	}))
	defer srv.Close()

	rows, err := governance.NewClient(srv.URL, srv.Client()).ReleasePosture(context.Background(), "rel-1")
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	if !rows[0].HasPosition || rows[0].PositionVersion != 2 || rows[0].PositionRationale != "not reachable" {
		t.Errorf("decided row = %+v", rows[0])
	}
	c := rows[1].Components[0]
	if c.VerdictState != "cleared_vendor_fix" || c.VerdictGrade != "inferred" || c.VerdictReason != "matched" {
		t.Errorf("verdict fields = %+v", c)
	}
	if rows[1].HasPosition || rows[1].PositionVersion != 0 {
		t.Errorf("undecided row = %+v", rows[1])
	}
}

func TestReleasePosture_Errors(t *testing.T) {
	notOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer notOK.Close()
	if _, err := governance.NewClient(notOK.URL, notOK.Client()).ReleasePosture(context.Background(), "rel-1"); err == nil {
		t.Error("non-200 must error")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{`))
	}))
	defer bad.Close()
	if _, err := governance.NewClient(bad.URL, bad.Client()).ReleasePosture(context.Background(), "rel-1"); err == nil {
		t.Error("malformed JSON must error")
	}
	if _, err := governance.NewClient("http://127.0.0.1:1", nil).ReleasePosture(context.Background(), "rel-1"); err == nil {
		t.Error("transport failure must error")
	}
}
