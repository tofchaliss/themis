package http

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/themis-project/themis/internal/governance/adapters/http/gen"
	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
	"github.com/themis-project/themis/internal/platform/auth"
)

// The rebuild policy surface (EDR-REBUILD-01 D2, D9; step R1): read it with any key, change it
// with admin. It serves the record only. Nothing here evaluates a Release or asks for a build.

const rebuildPolicyUnwired = "the rebuild policy service is not wired on this node"

// rebuildPolicyRequired are the fields a change must carry. A switch left out is refused: read
// as false it would silently loosen the policy.
var rebuildPolicyRequired = []string{
	"fix_required", "severity_floor", "count_known_exploited", "skip_decided", "carrier_only",
	"cool_down_seconds", "mode", "updated_by",
}

// GetRebuildPolicy serves the installation policy (the shipped defaults at version 0 when
// nothing is stored).
func (h *Handler) GetRebuildPolicy(w http.ResponseWriter, r *http.Request) {
	if h.rebuild == nil {
		writeProblem(w, http.StatusServiceUnavailable, "rebuild policy unavailable", rebuildPolicyUnwired)
		return
	}
	rec, err := h.rebuild.Installation(r.Context())
	if err != nil {
		writeErr(w, "read rebuild policy", err)
		return
	}
	writeJSON(w, http.StatusOK, toRebuildPolicyRecord(rec))
}

// GetRebuildPolicyHistory serves every stored version, newest first.
func (h *Handler) GetRebuildPolicyHistory(w http.ResponseWriter, r *http.Request) {
	if h.rebuild == nil {
		writeProblem(w, http.StatusServiceUnavailable, "rebuild policy unavailable", rebuildPolicyUnwired)
		return
	}
	recs, err := h.rebuild.InstallationHistory(r.Context())
	if err != nil {
		writeErr(w, "read rebuild policy history", err)
		return
	}
	out := make([]gen.RebuildPolicyRecord, 0, len(recs))
	for _, rec := range recs {
		out = append(out, toRebuildPolicyRecord(rec))
	}
	writeJSON(w, http.StatusOK, out)
}

// PutRebuildPolicy stores a new version of the installation policy. Admin only: this record
// decides when builds are asked for, so a product-scoped key may not change it.
func (h *Handler) PutRebuildPolicy(w http.ResponseWriter, r *http.Request) {
	if p, ok := auth.PrincipalFrom(r.Context()); ok && !p.IsAdmin() {
		writeProblem(w, http.StatusForbidden, "Forbidden", "changing the rebuild policy requires "+auth.ScopeAdmin)
		return
	}
	if h.rebuild == nil {
		writeProblem(w, http.StatusServiceUnavailable, "rebuild policy unavailable", rebuildPolicyUnwired)
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	var (
		present map[string]json.RawMessage
		body    gen.RebuildPolicyPut
	)
	if err := json.Unmarshal(raw, &present); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	for _, f := range rebuildPolicyRequired {
		if _, ok := present[f]; !ok {
			writeProblem(w, http.StatusBadRequest, "invalid rebuild policy", f+" is required")
			return
		}
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return
	}
	if body.CoolDownSeconds < 0 || body.CoolDownSeconds > int64(domain.RebuildCoolDownMax/time.Second) {
		writeProblem(w, http.StatusBadRequest, "invalid rebuild policy", "cool_down_seconds must be between 0 and one year")
		return
	}
	policy := domain.RebuildPolicy{
		FixRequired: body.FixRequired, SeverityFloor: string(body.SeverityFloor),
		CountKnownExploited: body.CountKnownExploited, SkipDecided: body.SkipDecided,
		CarrierOnly: body.CarrierOnly, CoolDown: time.Duration(body.CoolDownSeconds) * time.Second,
		Mode: domain.RebuildMode(body.Mode),
	}
	rec, err := h.rebuild.PutInstallation(r.Context(), policy, body.UpdatedBy)
	switch {
	case errors.Is(err, app.ErrRebuildPolicyActorRequired):
		writeProblem(w, http.StatusBadRequest, "invalid rebuild policy", "updated_by names the person changing the policy and is required")
	case errors.Is(err, app.ErrInvalidRebuildPolicy):
		writeProblem(w, http.StatusBadRequest, "invalid rebuild policy",
			"severity_floor is low, medium, high or critical, and mode is off, ask or auto")
	case err != nil:
		writeErr(w, "store rebuild policy", err)
	default:
		writeJSON(w, http.StatusOK, toRebuildPolicyRecord(rec))
	}
}

func toRebuildPolicyRecord(r app.RebuildPolicyRecord) gen.RebuildPolicyRecord {
	p := r.Policy
	out := gen.RebuildPolicyRecord{
		ScopeKind: r.ScopeKind, ScopeId: r.ScopeID, Version: r.Version,
		FixRequired: p.FixRequired, SeverityFloor: gen.RebuildPolicyRecordSeverityFloor(p.SeverityFloor),
		CountKnownExploited: p.CountKnownExploited, SkipDecided: p.SkipDecided, CarrierOnly: p.CarrierOnly,
		CoolDownSeconds: int64(p.CoolDown / time.Second), Mode: gen.RebuildPolicyRecordMode(p.Mode),
	}
	if !r.UpdatedAt.IsZero() {
		at, by := r.UpdatedAt, r.UpdatedBy
		out.UpdatedAt, out.UpdatedBy = &at, &by
	}
	return out
}
