package triage_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/triage"
)

func TestSubmitFalsePositiveCreatesVEX(t *testing.T) {
	vex := &memoryVEX{}
	handler := &triage.Handler{
		Repo: &memoryRepo{finding: domain.TriageFindingContext{
			FindingID: "f1", ComponentPURL: "pkg:npm/a@1", CVEID: "CVE-1",
			ArtifactID: "sbom-1", SBOMChecksum: "abc", RawSeverity: "high",
			EffectiveState: domain.EffectiveStateDetected,
		}},
		VEX: vex,
	}
	decision, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Decision: domain.TriageDecisionFalsePositive,
		Justification: "not reachable", Actor: "analyst",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.EffectiveState != domain.EffectiveStateFalsePositive {
		t.Fatalf("state = %q", decision.EffectiveState)
	}
	if vex.last.Assertion.Status != domain.VEXStatusNotAffected {
		t.Fatalf("vex status = %q", vex.last.Assertion.Status)
	}
}

func TestSubmitAcceptedRiskRequiresExpiry(t *testing.T) {
	handler := &triage.Handler{Repo: &memoryRepo{}, VEX: &memoryVEX{}}
	_, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Decision: domain.TriageDecisionAcceptedRisk,
		Justification: "mitigated", Actor: "analyst",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSubmitAcceptedRiskSetsExpiry(t *testing.T) {
	until := time.Now().Add(24 * time.Hour)
	repo := &memoryRepo{finding: domain.TriageFindingContext{
		FindingID: "f1", RawSeverity: "high", EffectiveState: domain.EffectiveStateDetected,
	}}
	handler := &triage.Handler{Repo: repo, VEX: &memoryVEX{}}
	_, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Decision: domain.TriageDecisionAcceptedRisk,
		Justification: "mitigated", AcceptedUntil: &until, Actor: "analyst",
	})
	if err != nil {
		t.Fatal(err)
	}
	if repo.updates[0].AcceptedUntil == nil {
		t.Fatal("accepted_until not stored")
	}
}

func TestSubmitMissingJustification(t *testing.T) {
	handler := &triage.Handler{Repo: &memoryRepo{}}
	_, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Decision: domain.TriageDecisionConfirmed, Actor: "analyst",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHistoryAppendOnly(t *testing.T) {
	repo := &memoryRepo{finding: domain.TriageFindingContext{
		FindingID: "f1", RawSeverity: "high", EffectiveState: domain.EffectiveStateDetected,
	}}
	handler := &triage.Handler{Repo: repo, VEX: &memoryVEX{}}
	for _, decision := range []string{domain.TriageDecisionConfirmed, domain.TriageDecisionFalsePositive} {
		if _, err := handler.Submit(context.Background(), domain.TriageDecision{
			FindingID: "f1", Decision: decision, Justification: "reason", Actor: "analyst",
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(repo.history) != 2 {
		t.Fatalf("history len = %d", len(repo.history))
	}
	if repo.updates[len(repo.updates)-1].EffectiveState != domain.EffectiveStateFalsePositive {
		t.Fatalf("latest state = %q", repo.updates[len(repo.updates)-1].EffectiveState)
	}
}

func TestProcessExpiredAcceptedRiskRevertsToDetected(t *testing.T) {
	repo := &memoryRepo{
		finding: domain.TriageFindingContext{
			FindingID: "f1", RawSeverity: "high", EffectiveState: domain.EffectiveStateAcceptedRisk,
		},
		expired: []string{"f1"},
		latest:  domain.TriageDecisionAcceptedRisk,
	}
	handler := &triage.Handler{Repo: repo}
	if err := handler.ProcessExpiredAcceptedRisk(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if repo.updates[len(repo.updates)-1].EffectiveState != domain.EffectiveStateDetected {
		t.Fatalf("state = %q", repo.updates[len(repo.updates)-1].EffectiveState)
	}
}

func TestEscalateSetsInTriage(t *testing.T) {
	repo := &memoryRepo{finding: domain.TriageFindingContext{
		FindingID: "f1", RawSeverity: "medium", EffectiveState: domain.EffectiveStateDetected,
	}}
	handler := &triage.Handler{Repo: repo, VEX: &memoryVEX{}}
	decision, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Decision: domain.TriageDecisionEscalate,
		Justification: "needs review", AssignedTo: "alice", Actor: "analyst",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.EffectiveState != domain.EffectiveStateInTriage {
		t.Fatalf("state = %q", decision.EffectiveState)
	}
	if repo.updates[0].AssignedTo != "alice" {
		t.Fatalf("assigned_to = %q", repo.updates[0].AssignedTo)
	}
}

func TestMapDecisionToEffectiveState(t *testing.T) {
	if triage.MapDecisionToEffectiveState(domain.TriageDecisionResolved) != domain.EffectiveStateResolved {
		t.Fatal("resolved mapping")
	}
}

func TestMapDecisionToVEXStatusEscalate(t *testing.T) {
	if _, ok := triage.MapDecisionToVEXStatus(domain.TriageDecisionEscalate); ok {
		t.Fatal("escalate should not generate vex")
	}
}

func TestComputeRiskScore(t *testing.T) {
	if triage.ComputeRiskScore("high", domain.EffectiveStateResolved) != 0 {
		t.Fatal("resolved score")
	}
}

func TestSubmitAllDecisionVEXStatuses(t *testing.T) {
	cases := map[string]string{
		domain.TriageDecisionFalsePositive: domain.VEXStatusNotAffected,
		domain.TriageDecisionConfirmed:     domain.VEXStatusAffected,
		domain.TriageDecisionResolved:      domain.VEXStatusFixed,
	}
	for decision, wantStatus := range cases {
		vex := &memoryVEX{}
		handler := &triage.Handler{
			Repo: &memoryRepo{finding: domain.TriageFindingContext{
				FindingID: "f1", ComponentPURL: "pkg:a", CVEID: "CVE-1",
				ArtifactID: "sbom", SBOMChecksum: "x", RawSeverity: "high",
			}},
			VEX: vex,
		}
		if _, err := handler.Submit(context.Background(), domain.TriageDecision{
			FindingID: "f1", Decision: decision, Justification: "ok", Actor: "a",
		}); err != nil {
			t.Fatalf("%s: %v", decision, err)
		}
		if vex.last.Assertion.Status != wantStatus {
			t.Fatalf("%s: status = %q", decision, vex.last.Assertion.Status)
		}
	}
}

func TestSubmitRepoGetFindingError(t *testing.T) {
	handler := &triage.Handler{Repo: &memoryRepo{findingErr: errors.New("boom")}}
	_, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Decision: domain.TriageDecisionConfirmed,
		Justification: "ok", Actor: "a",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSubmitAppendHistoryError(t *testing.T) {
	handler := &triage.Handler{Repo: &memoryRepo{
		finding:   domain.TriageFindingContext{FindingID: "f1", RawSeverity: "high"},
		appendErr: errors.New("append failed"),
	}}
	_, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Decision: domain.TriageDecisionConfirmed,
		Justification: "ok", Actor: "a",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSubmitUpdateRiskError(t *testing.T) {
	handler := &triage.Handler{Repo: &memoryRepo{
		finding:   domain.TriageFindingContext{FindingID: "f1", RawSeverity: "high"},
		updateErr: errors.New("update failed"),
	}, VEX: &memoryVEX{}}
	_, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Decision: domain.TriageDecisionConfirmed,
		Justification: "ok", Actor: "a",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSubmitVEXError(t *testing.T) {
	handler := &triage.Handler{
		Repo: &memoryRepo{finding: domain.TriageFindingContext{
			FindingID: "f1", ComponentPURL: "pkg:a", CVEID: "CVE-1",
			ArtifactID: "sbom", SBOMChecksum: "x", RawSeverity: "high",
		}},
		VEX: &memoryVEX{err: errors.New("vex failed")},
	}
	_, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Decision: domain.TriageDecisionConfirmed,
		Justification: "ok", Actor: "a",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSubmitMissingVEXGenerator(t *testing.T) {
	handler := &triage.Handler{Repo: &memoryRepo{finding: domain.TriageFindingContext{
		FindingID: "f1", RawSeverity: "high",
	}}}
	_, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Decision: domain.TriageDecisionConfirmed,
		Justification: "ok", Actor: "a",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHistoryDelegatesToRepo(t *testing.T) {
	repo := &memoryRepo{historyEntries: []domain.TriageHistoryEntry{{Decision: "confirmed"}}}
	handler := &triage.Handler{Repo: repo}
	items, _, err := handler.History(context.Background(), "f1", domain.PageRequest{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("len = %d", len(items))
	}
}

func TestProcessExpiredListError(t *testing.T) {
	handler := &triage.Handler{Repo: &memoryRepo{expiredErr: errors.New("list failed")}}
	if err := handler.ProcessExpiredAcceptedRisk(context.Background(), time.Now()); err == nil {
		t.Fatal("expected error")
	}
}

func TestProcessExpiredSkipsNonAcceptedLatest(t *testing.T) {
	repo := &memoryRepo{
		expired: []string{"f1"},
		latest:  domain.TriageDecisionFalsePositive,
		finding: domain.TriageFindingContext{FindingID: "f1", EffectiveState: domain.EffectiveStateFalsePositive},
	}
	handler := &triage.Handler{Repo: repo}
	if err := handler.ProcessExpiredAcceptedRisk(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(repo.updates) != 0 {
		t.Fatal("expected no updates")
	}
}

func TestProcessExpiredAlreadyDetected(t *testing.T) {
	repo := &memoryRepo{
		expired: []string{"f1"},
		latest:  domain.TriageDecisionAcceptedRisk,
		finding: domain.TriageFindingContext{FindingID: "f1", EffectiveState: domain.EffectiveStateDetected, RawSeverity: "high"},
	}
	handler := &triage.Handler{Repo: repo}
	if err := handler.ProcessExpiredAcceptedRisk(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(repo.updates) != 0 {
		t.Fatal("expected no updates")
	}
}

func TestValidateUnsupportedDecision(t *testing.T) {
	handler := &triage.Handler{Repo: &memoryRepo{}}
	_, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Decision: "unknown", Justification: "ok", Actor: "a",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateMissingDecision(t *testing.T) {
	handler := &triage.Handler{Repo: &memoryRepo{}}
	_, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Justification: "ok", Actor: "a",
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSubmitAcceptedRiskVEX(t *testing.T) {
	vex := &memoryVEX{}
	until := time.Now().Add(time.Hour)
	handler := &triage.Handler{
		Repo: &memoryRepo{finding: domain.TriageFindingContext{
			FindingID: "f1", ComponentPURL: "pkg:a", CVEID: "CVE-1",
			ArtifactID: "sbom", SBOMChecksum: "x", RawSeverity: "high",
		}},
		VEX: vex,
	}
	if _, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Decision: domain.TriageDecisionAcceptedRisk,
		Justification: "ok", AcceptedUntil: &until, Actor: "a",
	}); err != nil {
		t.Fatal(err)
	}
	if vex.last.Assertion.Status != domain.VEXStatusAffected {
		t.Fatalf("status = %q", vex.last.Assertion.Status)
	}
}

func TestSubmitAuditOnStateChange(t *testing.T) {
	audit := &memoryAudit{}
	handler := &triage.Handler{
		Repo: &memoryRepo{finding: domain.TriageFindingContext{
			FindingID: "f1", ComponentPURL: "pkg:a", CVEID: "CVE-1",
			ArtifactID: "sbom", SBOMChecksum: "x", RawSeverity: "high",
			EffectiveState: domain.EffectiveStateDetected,
		}},
		VEX:   &memoryVEX{},
		Audit: audit,
	}
	if _, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Decision: domain.TriageDecisionConfirmed,
		Justification: "ok", Actor: "a",
	}); err != nil {
		t.Fatal(err)
	}
	if len(audit.entries) < 2 {
		t.Fatalf("audit entries = %d", len(audit.entries))
	}
}

func TestProcessExpiredLatestDecisionError(t *testing.T) {
	handler := &triage.Handler{Repo: &memoryRepo{
		expired:   []string{"f1"},
		latestErr: errors.New("latest failed"),
	}}
	if err := handler.ProcessExpiredAcceptedRisk(context.Background(), time.Now()); err == nil {
		t.Fatal("expected error")
	}
}

func TestProcessExpiredGetFindingError(t *testing.T) {
	handler := &triage.Handler{Repo: &memoryRepo{
		expired:    []string{"f1"},
		latest:     domain.TriageDecisionAcceptedRisk,
		findingErr: errors.New("finding failed"),
	}}
	if err := handler.ProcessExpiredAcceptedRisk(context.Background(), time.Now()); err == nil {
		t.Fatal("expected error")
	}
}

func TestProcessExpiredUpdateError(t *testing.T) {
	handler := &triage.Handler{Repo: &memoryRepo{
		expired: []string{"f1"},
		latest:  domain.TriageDecisionAcceptedRisk,
		finding: domain.TriageFindingContext{
			FindingID: "f1", RawSeverity: "high", EffectiveState: domain.EffectiveStateAcceptedRisk,
		},
		updateErr: errors.New("update failed"),
	}}
	if err := handler.ProcessExpiredAcceptedRisk(context.Background(), time.Now()); err == nil {
		t.Fatal("expected error")
	}
}

func TestMapDecisionToEffectiveStateUnknown(t *testing.T) {
	if triage.MapDecisionToEffectiveState("unknown") != domain.EffectiveStateDetected {
		t.Fatal("expected detected default")
	}
}

func TestSubmitSameStateSkipsTransitionAudit(t *testing.T) {
	audit := &memoryAudit{}
	handler := &triage.Handler{
		Repo: &memoryRepo{finding: domain.TriageFindingContext{
			FindingID: "f1", ComponentPURL: "pkg:a", CVEID: "CVE-1",
			ArtifactID: "sbom", SBOMChecksum: "x", RawSeverity: "high",
			EffectiveState: domain.EffectiveStateConfirmed,
		}},
		VEX:   &memoryVEX{},
		Audit: audit,
	}
	if _, err := handler.Submit(context.Background(), domain.TriageDecision{
		FindingID: "f1", Decision: domain.TriageDecisionConfirmed,
		Justification: "ok", Actor: "a",
	}); err != nil {
		t.Fatal(err)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %d", len(audit.entries))
	}
}

func TestProcessExpiredWritesAudit(t *testing.T) {
	audit := &memoryAudit{}
	repo := &memoryRepo{
		expired: []string{"f1"},
		latest:  domain.TriageDecisionAcceptedRisk,
		finding: domain.TriageFindingContext{
			FindingID: "f1", RawSeverity: "high", EffectiveState: domain.EffectiveStateAcceptedRisk,
		},
	}
	handler := &triage.Handler{Repo: repo, Audit: audit}
	if err := handler.ProcessExpiredAcceptedRisk(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(audit.entries) == 0 {
		t.Fatal("expected audit entry")
	}
}

func TestComputeRiskScoreUnknownSeverity(t *testing.T) {
	if triage.ComputeRiskScore("info", domain.EffectiveStateDetected) != 0 {
		t.Fatal("unknown severity base score")
	}
}

type memoryRepo struct {
	finding        domain.TriageFindingContext
	findingErr     error
	appendErr      error
	updateErr      error
	expiredErr     error
	latestErr      error
	historyErr     error
	history        []domain.TriageHistoryRecord
	historyEntries []domain.TriageHistoryEntry
	updates        []domain.RiskContextTriageUpdate
	expired        []string
	latest         string
}

func (m *memoryRepo) GetFindingScope(context.Context, string) (string, error) {
	return "product", nil
}

func (m *memoryRepo) GetFindingContext(context.Context, string) (domain.TriageFindingContext, error) {
	if m.findingErr != nil {
		return domain.TriageFindingContext{}, m.findingErr
	}
	return m.finding, nil
}

func (m *memoryRepo) AppendHistory(_ context.Context, record domain.TriageHistoryRecord) error {
	if m.appendErr != nil {
		return m.appendErr
	}
	m.history = append(m.history, record)
	return nil
}

func (m *memoryRepo) ListHistory(context.Context, string, domain.PageRequest) ([]domain.TriageHistoryEntry, domain.PageResult, error) {
	if m.historyErr != nil {
		return nil, domain.PageResult{}, m.historyErr
	}
	return m.historyEntries, domain.PageResult{}, nil
}

func (m *memoryRepo) UpdateRiskContext(_ context.Context, update domain.RiskContextTriageUpdate) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	m.updates = append(m.updates, update)
	m.finding.EffectiveState = update.EffectiveState
	return nil
}

func (m *memoryRepo) ListExpiredAcceptedRiskFindings(context.Context, time.Time) ([]string, error) {
	if m.expiredErr != nil {
		return nil, m.expiredErr
	}
	return m.expired, nil
}

func (m *memoryRepo) LatestDecision(context.Context, string) (string, error) {
	if m.latestErr != nil {
		return "", m.latestErr
	}
	return m.latest, nil
}

type memoryVEX struct {
	last domain.GeneratedVEXInput
	err  error
}

func (m *memoryVEX) CreateFromDecision(_ context.Context, input domain.GeneratedVEXInput) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	m.last = input
	return "vex-1", nil
}

type memoryAudit struct {
	entries []domain.AuditEntry
}

func (m *memoryAudit) Record(_ context.Context, entry domain.AuditEntry) error {
	m.entries = append(m.entries, entry)
	return nil
}
