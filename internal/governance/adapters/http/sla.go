package http

import (
	"errors"
	"net/http"
	"time"

	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

// The SLA policy surface (EDR-REMEDIATION-01 D1): read it with any key, change it with admin.

// GetSLAPolicy serves the estate policy (the shipped defaults when nothing is stored) and the
// per-Product overrides.
func (h *Handler) GetSLAPolicy(w http.ResponseWriter, r *http.Request) {
	if h.sla == nil {
		writeProblem(w, http.StatusServiceUnavailable, "SLA policy unavailable", "the SLA service is not wired on this node")
		return
	}
	set, err := h.sla.Policies(r.Context())
	if err != nil {
		writeErr(w, "read SLA policy", err)
		return
	}
	out := gen.SLAPolicySet{Estate: toSLAPolicyRecord(set.Estate), Overrides: []gen.SLAPolicyRecord{}}
	for _, o := range set.Overrides {
		out.Overrides = append(out.Overrides, toSLAPolicyRecord(o))
	}
	writeJSON(w, http.StatusOK, out)
}

// PutSLAPolicy stores the estate policy or one Product's override. Admin only: a policy sets the
// deadline for every Finding it covers, so a product-scoped key may not set even its own.
func (h *Handler) PutSLAPolicy(w http.ResponseWriter, r *http.Request) {
	if p, ok := auth.PrincipalFrom(r.Context()); ok && !p.IsAdmin() {
		writeProblem(w, http.StatusForbidden, "Forbidden", "changing the SLA policy requires "+auth.ScopeAdmin)
		return
	}
	if h.sla == nil {
		writeProblem(w, http.StatusServiceUnavailable, "SLA policy unavailable", "the SLA service is not wired on this node")
		return
	}
	var body gen.SLAPolicyPut
	if !decode(w, r, &body) {
		return
	}
	if body.UpdatedBy == "" {
		writeProblem(w, http.StatusBadRequest, "invalid SLA policy", "updated_by names the person changing the policy and is required")
		return
	}
	scope := ""
	if body.Scope != nil {
		scope = *body.Scope
	}
	policy := domain.SLAPolicy{
		Critical: fromSLATarget(body.Critical), High: fromSLATarget(body.High),
		Medium: fromSLATarget(body.Medium), Low: fromSLATarget(body.Low),
	}
	rec, err := h.sla.PutPolicy(r.Context(), scope, policy, body.UpdatedBy)
	if errors.Is(err, app.ErrInvalidSLAPolicy) {
		writeProblem(w, http.StatusBadRequest, "invalid SLA policy", "an enforced bucket needs at least 1 day, and days cannot be negative")
		return
	}
	if err != nil {
		writeErr(w, "store SLA policy", err)
		return
	}
	writeJSON(w, http.StatusOK, toSLAPolicyRecord(rec))
}

func fromSLATarget(t gen.SLATarget) domain.SLATarget {
	return domain.SLATarget{Days: t.Days, Enforce: t.Enforce}
}

func toSLATarget(t domain.SLATarget) gen.SLATarget {
	return gen.SLATarget{Days: t.Days, Enforce: t.Enforce}
}

func toSLAPolicyRecord(r app.SLAPolicyRecord) gen.SLAPolicyRecord {
	out := gen.SLAPolicyRecord{
		Scope: r.Scope, Critical: toSLATarget(r.Policy.Critical), High: toSLATarget(r.Policy.High),
		Medium: toSLATarget(r.Policy.Medium), Low: toSLATarget(r.Policy.Low),
	}
	if !r.UpdatedAt.IsZero() {
		at, by := r.UpdatedAt, r.UpdatedBy
		out.UpdatedAt, out.UpdatedBy = &at, &by
	}
	return out
}

func timeptrIf(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func toSLAStatus(s domain.SLAStatus) gen.SLAStatus {
	out := gen.SLAStatus{
		State: gen.SLAStatusState(s.State), Bucket: s.Bucket, BucketChanged: s.BucketChanged,
		PeriodStart: s.PeriodStart, KevDueApplied: s.KEVDueApplied,
		AgeDays: int(s.TotalAge / (24 * time.Hour)), DaysUnderAcceptance: int(s.UnderAcceptance / (24 * time.Hour)),
		Due: timeptrIf(s.Due), StoppedAt: timeptrIf(s.StoppedAt),
	}
	if s.CurrentBucket != "" {
		cb := s.CurrentBucket
		out.CurrentBucket = &cb
	}
	if !s.Due.IsZero() && s.StoppedAt.IsZero() && s.State != domain.SLANotApplicable {
		d := s.DaysLeft
		out.DaysLeft = &d
	}
	if len(s.AcceptancePeriods) > 0 {
		ps := make([]gen.SLAAcceptancePeriod, len(s.AcceptancePeriods))
		for i, p := range s.AcceptancePeriods {
			ps[i] = gen.SLAAcceptancePeriod{Start: p.Start, End: timeptrIf(p.End), PositionVersion: p.PositionVersion}
		}
		out.AcceptancePeriods = &ps
	}
	return out
}
