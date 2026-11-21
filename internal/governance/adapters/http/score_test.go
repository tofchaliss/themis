package http_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	govhttp "github.com/themis-project/themis/internal/governance/adapters/http"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

type memScoreStore struct {
	comps  []app.ScoreRevision
	rollup *app.RollupRevision
	hist   []app.ScoreRevisionSummary
}

func (m *memScoreStore) CurrentScores(context.Context, string) ([]app.ScoreRevision, *app.RollupRevision, error) {
	return m.comps, m.rollup, nil
}
func (m *memScoreStore) AppendScores(context.Context, string, []app.ScoreRevision, *app.RollupRevision) error {
	return nil
}
func (m *memScoreStore) ScoreHistory(context.Context, string) ([]app.ScoreRevisionSummary, error) {
	return m.hist, nil
}
func (m *memScoreStore) FindingIDsAfter(context.Context, string, int) ([]string, error) {
	return nil, nil
}

func TestGetFindingScore(t *testing.T) {
	repo := newRepo()
	comp := domain.MatchedComponent{PURL: "pkg:npm/a@1", Name: "a"}
	repo.seed(domain.ReconstituteFinding("f1", "rel", "fl", "CVE-2026-0001", []domain.MatchedComponent{comp}, domain.StageIdentified, nil, nil, 1))
	at := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	score := 6.5
	ms := &memScoreStore{
		comps:  []app.ScoreRevision{{PURL: comp.PURL, Revision: 2, Cause: domain.CauseSourceAdded, RecordedAt: at, Snapshot: domain.ComponentScore{PURL: comp.PURL, Status: domain.ScoreFinal}}},
		rollup: &app.RollupRevision{Revision: 1, Cause: domain.CauseComponentAdded, RecordedAt: at, Snapshot: domain.FindingScore{State: domain.RollupScored, Score: &score}},
		hist:   []app.ScoreRevisionSummary{{PURL: comp.PURL, Revision: 2, Cause: domain.CauseSourceAdded, Status: domain.ScoreFinal, Score: &score, RecordedAt: at}},
	}
	write := app.NewFindingService(repo, &seqIDs{}, fixedClock{})
	read := app.NewReadService(repo, fakeProjection{}, nil, 0)
	unwired := httptest.NewServer(govhttp.NewHandler(write, read).Router())
	defer unwired.Close()
	resp, err := http.Get(unwired.URL + "/findings/f1/score")
	if err != nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unwired: %v %v", resp, err)
	}
	_ = resp.Body.Close()

	svc := app.NewScoreService(repo, nil, nil, nil, ms, fixedClock{})
	srv := httptest.NewServer(govhttp.NewHandler(write, read).WithScores(svc).Router())
	defer srv.Close()
	resp, err = http.Get(srv.URL + "/findings/f1/score")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("score: %v %v", resp, err)
	}
	var body struct {
		FindingID string `json:"finding_id"`
		Rollup    struct {
			Snapshot map[string]any `json:"snapshot"`
		} `json:"rollup"`
		Components []struct {
			Cause    string         `json:"cause"`
			Snapshot map[string]any `json:"snapshot"`
		} `json:"components"`
		History []struct {
			Score float64 `json:"score"`
		} `json:"history"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if body.FindingID != "f1" || body.Rollup.Snapshot["state"] != domain.RollupScored || len(body.Components) != 1 ||
		body.Components[0].Snapshot["score_status"] != domain.ScoreFinal || body.History[0].Score != 6.5 {
		t.Errorf("body %+v", body)
	}
	resp, _ = http.Get(srv.URL + "/findings/missing/score")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing finding: %d", resp.StatusCode)
	}
	_ = resp.Body.Close()
	// Not yet assessed: 200 with no rollup.
	ms.rollup, ms.comps = nil, nil
	resp, _ = http.Get(srv.URL + "/findings/f1/score")
	var empty map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&empty)
	_ = resp.Body.Close()
	if _, ok := empty["rollup"]; ok || resp.StatusCode != http.StatusOK {
		t.Errorf("unassessed: %v", empty)
	}
}
