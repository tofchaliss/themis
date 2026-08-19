package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/app"
)

// compareProjection serves a distinct posture per release id — the compare read joins two.
type compareProjection struct {
	postures map[string][]app.PostureEntry
	errFor   map[string]error
}

func (p compareProjection) ReleasePosture(_ context.Context, rel string) ([]app.PostureEntry, error) {
	if err := p.errFor[rel]; err != nil {
		return nil, err
	}
	return p.postures[rel], nil
}

func (p compareProjection) FaultlineBlastRadius(context.Context, string) ([]string, error) {
	return nil, nil
}

type fakeEvidence struct {
	has map[string]bool
	err error
}

func (f fakeEvidence) HasEvidence(_ context.Context, rel string) (bool, error) {
	return f.has[rel], f.err
}

func compareServer(t *testing.T, proj compareProjection, ev app.EvidencePresenceReader) *httptest.Server {
	t.Helper()
	repo := newRepo()
	write := app.NewFindingService(repo, &seqIDs{}, fixedClock{})
	read := app.NewReadService(repo, proj, nil, 0)
	if ev != nil {
		read = read.WithEvidence(ev)
	}
	srv := httptest.NewServer(govhttp.NewHandler(write, read).Router())
	t.Cleanup(srv.Close)
	return srv
}

func TestCompareReleases(t *testing.T) {
	proj := compareProjection{postures: map[string][]app.PostureEntry{
		"rel-a": {{CVE: "CVE-1", BaseScore: 90}, {CVE: "CVE-3", BaseScore: 50}},
		"rel-b": {{CVE: "CVE-3", BaseScore: 60}, {CVE: "CVE-4", BaseScore: 30}},
	}}
	srv := compareServer(t, proj, fakeEvidence{has: map[string]bool{"rel-a": true, "rel-b": true}})

	code, body := do(t, http.MethodGet, srv.URL+"/releases/rel-a/compare/rel-b", nil)
	if code != http.StatusOK {
		t.Fatalf("compare = %d %s", code, body)
	}
	var out struct {
		BaselineReleaseID  string           `json:"baseline_release_id"`
		CandidateReleaseID string           `json:"candidate_release_id"`
		Fixed              []map[string]any `json:"fixed"`
		New                []map[string]any `json:"new"`
		Persisting         []map[string]any `json:"persisting"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.BaselineReleaseID != "rel-a" || out.CandidateReleaseID != "rel-b" {
		t.Errorf("ids = %s / %s", out.BaselineReleaseID, out.CandidateReleaseID)
	}
	if len(out.Fixed) != 1 || out.Fixed[0]["cve"] != "CVE-1" {
		t.Errorf("fixed = %+v", out.Fixed)
	}
	if len(out.New) != 1 || out.New[0]["cve"] != "CVE-4" {
		t.Errorf("new = %+v", out.New)
	}
	// Persisting carries the candidate's state (base 60, not the baseline's 50).
	if len(out.Persisting) != 1 || out.Persisting[0]["cve"] != "CVE-3" || out.Persisting[0]["base_score"] != float64(60) {
		t.Errorf("persisting = %+v", out.Persisting)
	}
}

func TestCompareReleases_Refusals(t *testing.T) {
	proj := compareProjection{postures: map[string][]app.PostureEntry{}}

	// A side with no evidence ⇒ 422, naming the release.
	srv := compareServer(t, proj, fakeEvidence{has: map[string]bool{"rel-b": true}})
	code, body := do(t, http.MethodGet, srv.URL+"/releases/rel-a/compare/rel-b", nil)
	if code != http.StatusUnprocessableEntity {
		t.Errorf("no evidence = %d %s", code, body)
	}

	// Evidence unreachable ⇒ 502 (fail-closed), never a silent empty diff.
	srv = compareServer(t, proj, fakeEvidence{err: errors.New("down")})
	if code, body = do(t, http.MethodGet, srv.URL+"/releases/rel-a/compare/rel-b", nil); code != http.StatusBadGateway {
		t.Errorf("unreachable = %d %s", code, body)
	}

	// Seam not wired at all ⇒ the same honest refusal.
	srv = compareServer(t, proj, nil)
	if code, body = do(t, http.MethodGet, srv.URL+"/releases/rel-a/compare/rel-b", nil); code != http.StatusBadGateway {
		t.Errorf("unwired = %d %s", code, body)
	}

	// A posture read failure is a plain 500.
	srv = compareServer(t, compareProjection{errFor: map[string]error{"rel-a": errors.New("db down")}},
		fakeEvidence{has: map[string]bool{"rel-a": true, "rel-b": true}})
	if code, body = do(t, http.MethodGet, srv.URL+"/releases/rel-a/compare/rel-b", nil); code != http.StatusInternalServerError {
		t.Errorf("posture error = %d %s", code, body)
	}
}
