package triage_test

import (
	"context"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/testutil/gen"
	"github.com/themis-project/themis/internal/usecase/triage"
)

// countingVEX records how many themis-generated VEX documents were produced.
type countingVEX struct {
	count      int
	lastStatus string
}

func (c *countingVEX) CreateFromDecision(_ context.Context, input domain.GeneratedVEXInput) (string, error) {
	c.count++
	c.lastStatus = input.Assertion.Status
	return "vex-generated", nil
}

// TestTriageStateMachineProperty drives a random sequence of valid triage
// decisions against the handler and asserts the core invariants:
//   - triage history is append-only (grows by exactly one per decision);
//   - risk_context.effective_state always equals the latest decision mapping;
//   - the raw finding severity is never mutated (VEX overlay only);
//   - escalate never generates a VEX document.
func TestTriageStateMachineProperty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rawSev := rapid.SampledFrom([]string{"critical", "high", "medium", "low", "none"}).Draw(t, "raw_severity")
		repo := &memoryRepo{finding: domain.TriageFindingContext{
			FindingID:      "f1",
			ComponentPURL:  "pkg:npm/a@1",
			CVEID:          "CVE-1",
			SBOMDocumentID: "sbom-1",
			SBOMChecksum:   "checksum",
			RawSeverity:    rawSev,
			EffectiveState: domain.EffectiveStateDetected,
		}}
		vex := &countingVEX{}
		handler := &triage.Handler{Repo: repo, VEX: vex, Audit: &memoryAudit{}}

		steps := rapid.IntRange(1, 20).Draw(t, "steps")
		wantVEX := 0
		for i := 0; i < steps; i++ {
			decision := gen.ValidTriageDecision(t)
			var until *time.Time
			if decision == domain.TriageDecisionAcceptedRisk {
				u := time.Now().Add(time.Hour)
				until = &u
			}

			prevHistory := len(repo.history)
			out, err := handler.Submit(context.Background(), domain.TriageDecision{
				FindingID:     "f1",
				Decision:      decision,
				Justification: "reason",
				Actor:         "analyst",
				AcceptedUntil: until,
			})
			if err != nil {
				t.Fatalf("submit %q: %v", decision, err)
			}

			if len(repo.history) != prevHistory+1 {
				t.Fatalf("history not append-only: len=%d want=%d", len(repo.history), prevHistory+1)
			}
			if repo.history[len(repo.history)-1].Decision != decision {
				t.Fatalf("last history decision = %q want %q", repo.history[len(repo.history)-1].Decision, decision)
			}

			wantState := triage.MapDecisionToEffectiveState(decision)
			if out.EffectiveState != wantState {
				t.Fatalf("returned state = %q want %q", out.EffectiveState, wantState)
			}
			if repo.updates[len(repo.updates)-1].EffectiveState != wantState {
				t.Fatalf("risk_context state = %q want %q", repo.updates[len(repo.updates)-1].EffectiveState, wantState)
			}
			if repo.finding.RawSeverity != rawSev {
				t.Fatalf("raw severity mutated: %q want %q", repo.finding.RawSeverity, rawSev)
			}
			if got := repo.updates[len(repo.updates)-1].RiskScore; got != triage.ComputeRiskScore(rawSev, wantState) {
				t.Fatalf("risk score = %d want %d", got, triage.ComputeRiskScore(rawSev, wantState))
			}

			if _, has := triage.MapDecisionToVEXStatus(decision); has {
				wantVEX++
			}
			if vex.count != wantVEX {
				t.Fatalf("vex count = %d want %d (decision=%q)", vex.count, wantVEX, decision)
			}
		}

		if len(repo.history) != steps {
			t.Fatalf("final history len = %d want %d", len(repo.history), steps)
		}
	})
}
