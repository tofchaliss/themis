package app

// compare_releases@v1 (AI-CMP-1): the two-release Information capability over Governance's
// deterministic comparison read (EDR-GOVERNANCE-01 D16). These tests mirror the release-plan
// suite: same harness, same gates, a different projection.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

func sampleComparison() domain.ReleaseComparison {
	return domain.ReleaseComparison{
		BaselineID:  "rel-a",
		CandidateID: "rel-b",
		Fixed: []domain.PostureEntry{{
			FindingID: "f-old", CVE: "CVE-2024-0001", ResidualPriority: 90, EffectivePriority: 90,
			Components: []domain.PostureComponent{{Name: "libfoo", Version: "1.0", PURL: "pkg:rpm/libfoo@1.0"}},
		}},
		New: []domain.PostureEntry{{
			FindingID: "f-new", CVE: "CVE-2025-0002", ResidualPriority: 30, EffectivePriority: 30,
		}},
		Persisting: []domain.PostureEntry{{
			FindingID: "f-still", CVE: "CVE-2023-0003", ResidualPriority: 70, EffectivePriority: 70,
		}},
	}
}

func compareSel() domain.Selection {
	return domain.Selection{Type: domain.SelectionRelease, IDs: []string{"rel-a", "rel-b"}}
}

const compareRaw = `{"subject_id":"rel-b","evidence":[{"kind":"release","ref":"rel-b"},` +
	`{"kind":"cve","ref":"CVE-2023-0003"}],"reasoning":"The fix removed CVE-2024-0001; CVE-2023-0003 remains the next work."}`

// The two-release Selection reads the COMPARISON projection — never the per-release posture
// and never the per-Finding assessment (T10 rule 1).
func TestInvoke_CompareReadsTheComparisonProjection(t *testing.T) {
	proj := &releaseProjection{comparison: sampleComparison()}
	_, oc := releaseGateway(t, proj, compareRaw).Invoke(
		context.Background(), "compare_releases", compareSel(), "corr-1")

	if oc.Reason != ReasonOK {
		t.Fatalf("reason = %q detail = %q", oc.Reason, oc.Detail)
	}
	if oc.Produced {
		t.Error("an Information capability must produce no Proposal (T7)")
	}
	if oc.Information == "" || oc.DecidedBy != "llm:information" {
		t.Errorf("information=%q decided_by=%q", oc.Information, oc.DecidedBy)
	}
	if proj.assessN != 0 {
		t.Errorf("GetAssessment called %d times — the comparison path must not read it", proj.assessN)
	}
}

// The Selection contract (T9): exactly TWO ordered releases. One id — or three — is a
// mismatch refused at the door, before any read or spend.
func TestInvoke_CompareRequiresExactlyTwoReleases(t *testing.T) {
	for _, ids := range [][]string{{"rel-a"}, {"rel-a", "rel-b", "rel-c"}} {
		_, oc := releaseGateway(t, &releaseProjection{comparison: sampleComparison()}, compareRaw).Invoke(
			context.Background(), "compare_releases",
			domain.Selection{Type: domain.SelectionRelease, IDs: ids}, "corr-1")
		if oc.Reason != ReasonSelectionMismatch {
			t.Errorf("ids=%v: reason = %q, want selection-mismatch", ids, oc.Reason)
		}
	}
}

// A comparison the read refuses — Governance's honesty guard (evidence-less side, Evidence
// unreachable) or any transport failure — is a grounding failure, never a narration.
func TestInvoke_CompareProjectionUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		proj *releaseProjection
	}{
		{"guard or transport refusal", &releaseProjection{cmpErr: errors.New("status 422")}},
		{"empty answer", &releaseProjection{comparison: domain.ReleaseComparison{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, oc := releaseGateway(t, tc.proj, compareRaw).Invoke(
				context.Background(), "compare_releases", compareSel(), "corr-1")
			if oc.Reason != ReasonNoGrounding {
				t.Errorf("reason = %q, want no-grounding", oc.Reason)
			}
		})
	}
}

// Two releases with empty postures is a REAL answer, given deterministically — no model call,
// no tokens, decided_by names the rule.
func TestInvoke_CompareEmptyBucketsAnswersDeterministically(t *testing.T) {
	proj := &releaseProjection{comparison: domain.ReleaseComparison{BaselineID: "rel-a", CandidateID: "rel-b"}}
	_, oc := releaseGateway(t, proj, compareRaw).Invoke(
		context.Background(), "compare_releases", compareSel(), "corr-1")
	if oc.Reason != ReasonOK || oc.DecidedBy != "rule:empty-comparison" {
		t.Fatalf("reason=%q decided_by=%q", oc.Reason, oc.DecidedBy)
	}
	if !strings.Contains(oc.Information, "no security difference") {
		t.Errorf("information = %q", oc.Information)
	}
	if oc.TokensUsed != 0 {
		t.Errorf("tokens = %d, want 0 — the rule answer must not spend", oc.TokensUsed)
	}
}

// Grounding Verification is the only gate on the Information path (T8): a citation naming a
// CVE in neither bucket discards the narration.
func TestInvoke_CompareOutputIsGrounded(t *testing.T) {
	bogus := `{"subject_id":"rel-b","evidence":[{"kind":"cve","ref":"CVE-2099-9999"}],"reasoning":"x"}`
	_, oc := releaseGateway(t, &releaseProjection{comparison: sampleComparison()}, bogus).Invoke(
		context.Background(), "compare_releases", compareSel(), "corr-1")
	if oc.Reason != ReasonBusinessInvalid {
		t.Fatalf("reason = %q, want business-invalid", oc.Reason)
	}
	if !strings.Contains(oc.Detail, "CVE-2099-9999") {
		t.Errorf("detail = %q, want the ungrounded ref named", oc.Detail)
	}
}
