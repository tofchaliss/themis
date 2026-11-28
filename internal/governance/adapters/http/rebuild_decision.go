package http

import (
	"errors"
	"net/http"

	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// The rebuild triggers and decisions of one Release (EDR-REBUILD-01 step R2 part 2): a read of
// what was recorded. It judges nothing and starts nothing.

// WithRebuildDecisions attaches the read behind /releases/{id}/rebuild-decisions.
func (h *Handler) WithRebuildDecisions(r *app.RebuildDecisionReader) *Handler {
	h.rebuildDecisions = r
	return h
}

// GetReleaseRebuildDecisions serves the triggers of the Release, newest first.
func (h *Handler) GetReleaseRebuildDecisions(w http.ResponseWriter, r *http.Request, releaseID string, params gen.GetReleaseRebuildDecisionsParams) {
	limit := 0
	if params.Limit != nil {
		limit = *params.Limit
	}
	recs, err := h.rebuildDecisions.ForRelease(r.Context(), releaseID, limit)
	switch {
	case errors.Is(err, app.ErrRebuildDecisionsUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, "rebuild decisions unavailable",
			"the rebuild decisions are not wired on this node")
	case err != nil:
		writeProblem(w, http.StatusInternalServerError, "rebuild decisions unavailable",
			"the rebuild decisions could not be read")
	default:
		out := gen.RebuildTriggerList{Items: make([]gen.RebuildTriggerRecord, 0, len(recs))}
		for _, rec := range recs {
			out.Items = append(out.Items, toRebuildTriggerRecord(rec))
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func toRebuildTriggerRecord(rec app.RebuildTriggerRecord) gen.RebuildTriggerRecord {
	out := gen.RebuildTriggerRecord{
		TriggerId: rec.TriggerID, TriggerSource: rec.Source,
		TriggerType: gen.RebuildTriggerRecordTriggerType(rec.Type),
		ReleaseId:   rec.ReleaseID, ReceivedAt: rec.ReceivedAt, Settled: rec.Settled,
		Considered: rec.Result.Considered, TargetedCount: rec.Result.Targeted,
	}
	if !rec.Settled {
		return out
	}
	res := rec.Result
	settledAt := res.SettledAt
	outcome := gen.RebuildTriggerRecordOutcome(res.Outcome)
	out.SettledAt, out.Outcome = &settledAt, &outcome
	if res.Reason != "" {
		reason := gen.RebuildTriggerRecordReason(res.Reason)
		out.Reason = &reason
	}
	if res.EffectiveMode != "" {
		mode := gen.RebuildTriggerRecordEffectiveMode(res.EffectiveMode)
		setBy := gen.RebuildTriggerRecordEffectiveModeSetBy(res.ModeSetBy)
		out.EffectiveMode, out.EffectiveModeSetBy = &mode, &setBy
	}
	if rec.Decision != nil {
		d := toRebuildDecision(*rec.Decision)
		out.Decision = &d
	}
	return out
}

func toRebuildDecision(d domain.RebuildDecision) gen.RebuildDecision {
	out := gen.RebuildDecision{
		DecisionId: d.DecisionID, Outcome: gen.RebuildDecisionOutcome(d.Outcome), DecidedAt: d.DecidedAt,
		ProductId: d.ProductID, ProjectId: d.ProjectID,
		InstallationMode:   gen.RebuildDecisionInstallationMode(d.InstallationMode),
		EffectiveMode:      gen.RebuildDecisionEffectiveMode(d.EffectiveMode),
		EffectiveModeSetBy: gen.RebuildDecisionEffectiveModeSetBy(d.EffectiveModeSetBy),
		Tag:                d.Tag, TagLevel: d.TagLevel,
		Considered: d.Considered, Skipped: d.Skipped,
		Targeted: toRebuildDecisionEntries(d.Targeted), OtherStream: toRebuildDecisionEntries(d.OtherStream),
	}
	if out.Skipped == nil {
		out.Skipped = map[string]int{}
	}
	if d.RecommendReason != "" {
		why := gen.RebuildDecisionRecommendReason(d.RecommendReason)
		out.RecommendReason = &why
	}
	// The build profile is served as it was frozen, and not read (D10). It is the same JSON
	// value as stored in Registry; the key order may differ, so the digest names the revision.
	if d.BuildProfile != nil {
		build := d.Build
		out.Build = &build
		out.BuildProfile = &struct {
			Revision int                                  `json:"revision"`
			Scope    gen.RebuildDecisionBuildProfileScope `json:"scope"`
			Sha256   string                               `json:"sha256"`
		}{Revision: d.BuildProfile.Revision, Scope: gen.RebuildDecisionBuildProfileScope(d.BuildProfile.Scope), Sha256: d.BuildProfile.SHA256}
	}
	if d.Supersedes != "" {
		out.Supersedes = strptr(d.Supersedes)
	}
	p := d.Policy
	out.Policy.ScopeKind = gen.RebuildDecisionPolicyScopeKind(p.ScopeKind)
	out.Policy.ScopeId = p.ScopeID
	out.Policy.Version = p.Version
	out.Policy.FixRequired = p.FixRequired
	out.Policy.SeverityFloor = p.SeverityFloor
	out.Policy.CountKnownExploited = p.CountKnownExploited
	out.Policy.SkipDecided = p.SkipDecided
	out.Policy.CarrierOnly = p.CarrierOnly
	out.Policy.CoolDownSeconds = p.CoolDownSeconds
	out.Policy.Mode = gen.RebuildDecisionPolicyMode(p.Mode)
	return out
}

// toRebuildDecisionEntries serves frozen entries in the shape of the judgement read.
func toRebuildDecisionEntries(entries []domain.RebuildDecisionEntry) []gen.RebuildTargetEntry {
	out := make([]gen.RebuildTargetEntry, 0, len(entries))
	for _, t := range entries {
		e := gen.RebuildTargetEntry{
			FindingId: t.FindingID, Cve: t.CVE, Purl: t.PURL,
			CurrentVersion: t.CurrentVersion, FixedVersions: t.FixedVersions,
			Severity: t.Severity, Score: t.Score,
			ScoreSource:    gen.RebuildTargetEntryScoreSource(t.ScoreSource),
			KnownExploited: t.KnownExploited,
			ClaimClass:     gen.RebuildTargetEntryClaimClass(t.ClaimClass),
			Position:       t.Position,
			CountedBecause: make([]gen.RebuildTargetEntryCountedBecause, 0, len(t.CountedBecause)),
		}
		if e.FixedVersions == nil {
			e.FixedVersions = []string{}
		}
		if t.FixSource != "" {
			e.FixSource = strptr(t.FixSource)
		}
		for _, b := range t.CountedBecause {
			e.CountedBecause = append(e.CountedBecause, gen.RebuildTargetEntryCountedBecause(b))
		}
		e.Assessment.State = gen.RebuildTargetEntryAssessmentState(t.AssessmentState)
		out = append(out, e)
	}
	return out
}
