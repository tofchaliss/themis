package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

type outcomeReader struct {
	rec   app.UploadOutcomeRecord
	found bool
	err   error
}

func (o outcomeReader) LatestUploadOutcome(context.Context, string) (app.UploadOutcomeRecord, bool, error) {
	return o.rec, o.found, o.err
}

func outcomeServer(t *testing.T, r app.UploadOutcomeReader) *httptest.Server {
	t.Helper()
	repo := newRepo()
	read := app.NewReadService(repo, fakeProjection{}, nil, 0)
	if r != nil {
		read = read.WithUploadOutcomeReader(r)
	}
	srv := httptest.NewServer(govhttp.NewHandler(app.NewFindingService(repo, &seqIDs{}, fixedClock{}), read).Router())
	t.Cleanup(srv.Close)
	return srv
}

func TestGetReleaseUploadOutcome(t *testing.T) {
	at := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	full := outcomeReader{found: true, rec: app.UploadOutcomeRecord{SBOMID: "sb-2", EvaluatedAt: at, Outcome: domain.UploadOutcome{
		New: 1, Reappeared: 1, NoLongerPresent: 2, Unchanged: 5, NotJudged: 1, HasBaseline: true,
		NewCVEs: []string{"CVE-N"}, ReappearedCVEs: []string{"CVE-R"}, GoneCVEs: []string{"CVE-G1", "CVE-G2"},
	}}}
	code, body := do(t, http.MethodGet, outcomeServer(t, full).URL+"/releases/rel-1/upload-outcome", nil)
	var v gen.UploadOutcome
	if code != http.StatusOK || json.Unmarshal(body, &v) != nil || v.SbomId != "sb-2" || v.NoLongerPresent != 2 ||
		v.NewCves == nil || v.ReappearedCves == nil || len(*v.NoLongerPresentCves) != 2 || !v.HasBaseline {
		t.Fatalf("full = %d %s", code, body)
	}
	code, body = do(t, http.MethodGet, outcomeServer(t, outcomeReader{found: true, rec: app.UploadOutcomeRecord{SBOMID: "sb-1"}}).URL+"/releases/rel-1/upload-outcome", nil)
	v = gen.UploadOutcome{}
	if code != http.StatusOK || json.Unmarshal(body, &v) != nil || v.NewCves != nil || v.NoLongerPresentCves != nil {
		t.Fatalf("empty lists = %d %s", code, body)
	}
	for name, tc := range map[string]struct {
		r    app.UploadOutcomeReader
		want int
	}{
		"none":    {outcomeReader{}, http.StatusNotFound},
		"error":   {outcomeReader{err: errors.New("db")}, http.StatusInternalServerError},
		"unwired": {nil, http.StatusServiceUnavailable},
	} {
		if code, _ := do(t, http.MethodGet, outcomeServer(t, tc.r).URL+"/releases/rel-1/upload-outcome", nil); code != tc.want {
			t.Errorf("%s = %d, want %d", name, code, tc.want)
		}
	}
}
