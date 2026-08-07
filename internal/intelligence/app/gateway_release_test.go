package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// releaseProjection serves the release-scoped Domain Projection and counts Finding reads, so a
// test can assert the runtime asks for the projection its capability declared and nothing else.
type releaseProjection struct {
	posture domain.ReleasePosture
	err     error
	assessN int
}

func (r *releaseProjection) GetAssessment(context.Context, string) (domain.FindingAssessment, error) {
	r.assessN++
	return domain.FindingAssessment{}, nil
}

func (r *releaseProjection) GetReleasePosture(context.Context, string) (domain.ReleasePosture, error) {
	return r.posture, r.err
}

func outstandingPosture() domain.ReleasePosture {
	return domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{{
		FindingID: "f1", CVE: "CVE-2007-4559", ResidualPriority: 97,
		Components: []domain.PostureComponent{{
			PURL: "pkg:rpm/rocky/python3-ply@3.9", Name: "python3-ply",
			Version: "3.9", Ecosystem: "rpm", Source: "python-ply",
		}},
	}}}
}

func releaseGateway(t *testing.T, proj ProjectionReader, raw string) *Gateway {
	t.Helper()
	g, err := NewGateway(GatewayConfig{
		Registry: domain.DefaultRegistry(), Projection: proj, Prompt: fakePrompt{},
		Engines: []Engine{&fakeEngine{replies: []engineReply{{raw: raw}}}},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	return g
}

func releaseSel() domain.Selection {
	return domain.Selection{Type: domain.SelectionRelease, IDs: []string{"rel-1"}}
}

const planRaw = `{"subject_id":"rel-1","evidence":[{"kind":"cve","ref":"CVE-2007-4559"}],` +
	`"reasoning":"Upgrade python-ply first."}`

// A capability whose Selection Type is Release reads the RELEASE projection — and never the
// per-Finding one. Reaching for a second projection to complete the first is the orchestration
// T10 rule 1 forbids.
func TestInvoke_ReleaseSubjectReadsTheReleaseProjection(t *testing.T) {
	proj := &releaseProjection{posture: outstandingPosture()}
	_, oc := releaseGateway(t, proj, planRaw).Invoke(
		context.Background(), "plan_remediation", releaseSel(), "corr-1")

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
		t.Errorf("GetAssessment called %d times — the release path must not read it", proj.assessN)
	}
}

// An unreadable or unknown release is a grounding failure, not a plan.
func TestInvoke_ReleaseProjectionUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name string
		proj *releaseProjection
	}{
		{"read error", &releaseProjection{err: errors.New("governance down")}},
		{"unknown release", &releaseProjection{posture: domain.ReleasePosture{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, oc := releaseGateway(t, tc.proj, planRaw).Invoke(
				context.Background(), "plan_remediation", releaseSel(), "corr-1")
			if oc.Reason != ReasonNoGrounding {
				t.Errorf("reason = %q, want no-grounding", oc.Reason)
			}
		})
	}
}

// Grounding Verification is the ONLY gate on the Information path (T8): no Governance stage
// follows, so a citation naming something the projection never held has nothing else to catch it.
func TestInvoke_InformationOutputIsGrounded(t *testing.T) {
	bogus := `{"subject_id":"rel-1","evidence":[{"kind":"cve","ref":"CVE-2099-0001"}],"reasoning":"x"}`
	_, oc := releaseGateway(t, &releaseProjection{posture: outstandingPosture()}, bogus).Invoke(
		context.Background(), "plan_remediation", releaseSel(), "corr-1")

	if oc.Reason != ReasonBusinessInvalid {
		t.Fatalf("reason = %q, want the ungrounded citation refused", oc.Reason)
	}
	if oc.Information != "" {
		t.Errorf("information = %q, want none — a refused answer is not shown", oc.Information)
	}
	if oc.Detail == "" {
		t.Error("detail must name what was ungrounded (TRUST-6)")
	}
}

// Prose cannot be schema-checked, and an Information Response is read as-is, so an invented
// identifier is flagged INSIDE the text — a caveat stored elsewhere is one a reader can miss.
func TestInvoke_InformationProseMentionsAreFlaggedInline(t *testing.T) {
	raw := `{"subject_id":"rel-1","evidence":[{"kind":"cve","ref":"CVE-2007-4559"}],` +
		`"reasoning":"Upgrade python-ply, which also fixes CVE-2099-9999."}`
	_, oc := releaseGateway(t, &releaseProjection{posture: outstandingPosture()}, raw).Invoke(
		context.Background(), "plan_remediation", releaseSel(), "corr-1")

	if oc.Reason != ReasonOK {
		t.Fatalf("reason = %q — a warned plan is still a valid answer", oc.Reason)
	}
	if !strings.Contains(oc.Information, "UNVERIFIED MENTIONS") ||
		!strings.Contains(oc.Information, "CVE-2099-9999") {
		t.Errorf("information = %q, want the invented CVE flagged inline", oc.Information)
	}
}

// A release with nothing outstanding is a real answer, and giving it deterministically is both
// faster and more truthful than asking a model to say "nothing to do".
func TestInvoke_NothingOutstandingAnswersWithoutTheModel(t *testing.T) {
	decided := domain.ReleasePosture{ReleaseID: "rel-1", Entries: []domain.PostureEntry{
		{FindingID: "f1", CVE: "CVE-1", ResidualPriority: 0},
	}}
	eng := &fakeEngine{replies: []engineReply{{raw: planRaw}}}
	g, err := NewGateway(GatewayConfig{
		Registry: domain.DefaultRegistry(), Projection: &releaseProjection{posture: decided},
		Prompt: fakePrompt{}, Engines: []Engine{eng},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	_, oc := g.Invoke(context.Background(), "plan_remediation", releaseSel(), "corr-1")
	if oc.Reason != ReasonOK || !strings.Contains(oc.Information, "No outstanding Findings") {
		t.Fatalf("reason=%q information=%q", oc.Reason, oc.Information)
	}
	if eng.calls != 0 {
		t.Errorf("engine called %d times — there is nothing to plan", eng.calls)
	}
	if oc.DecidedBy != "rule:nothing-outstanding" {
		t.Errorf("decided_by = %q, want the rule that answered", oc.DecidedBy)
	}
}
