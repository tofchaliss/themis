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
	writeJSON(w, http.StatusOK, toRebuildPolicyRecords(recs))
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
	policy, actor, ok := readRebuildPolicyPut(w, r)
	if !ok {
		return
	}
	rec, err := h.rebuild.PutInstallation(r.Context(), policy, actor)
	writeRebuildPolicyChange(w, rec, err)
}

// readRebuildPolicyPut reads the body of a policy change. It has already written the Problem
// envelope when ok is false.
func readRebuildPolicyPut(w http.ResponseWriter, r *http.Request) (policy domain.RebuildPolicy, actor string, ok bool) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return policy, "", false
	}
	var (
		present map[string]json.RawMessage
		body    gen.RebuildPolicyPut
	)
	if err := json.Unmarshal(raw, &present); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return policy, "", false
	}
	for _, f := range rebuildPolicyRequired {
		if _, found := present[f]; !found {
			writeProblem(w, http.StatusBadRequest, "invalid rebuild policy", f+" is required")
			return policy, "", false
		}
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid request body", err.Error())
		return policy, "", false
	}
	if body.CoolDownSeconds < 0 || body.CoolDownSeconds > int64(domain.RebuildCoolDownMax/time.Second) {
		writeProblem(w, http.StatusBadRequest, "invalid rebuild policy", "cool_down_seconds must be between 0 and one year")
		return policy, "", false
	}
	return domain.RebuildPolicy{
		FixRequired: body.FixRequired, SeverityFloor: string(body.SeverityFloor),
		CountKnownExploited: body.CountKnownExploited, SkipDecided: body.SkipDecided,
		CarrierOnly: body.CarrierOnly, CoolDown: time.Duration(body.CoolDownSeconds) * time.Second,
		Mode: domain.RebuildMode(body.Mode),
	}, body.UpdatedBy, true
}

// writeRebuildPolicyChange answers a change or a removal: the record, or the refusal.
func writeRebuildPolicyChange(w http.ResponseWriter, rec app.RebuildPolicyRecord, err error) {
	switch {
	case errors.Is(err, app.ErrRebuildPolicyActorRequired):
		writeProblem(w, http.StatusBadRequest, "invalid rebuild policy", "updated_by names the person changing the policy and is required")
	case errors.Is(err, app.ErrInvalidRebuildPolicy):
		writeProblem(w, http.StatusBadRequest, "invalid rebuild policy",
			"severity_floor is low, medium, high or critical, and mode is off, ask or auto")
	case errors.Is(err, app.ErrRebuildPolicyScopeInvalid):
		writeProblem(w, http.StatusBadRequest, "invalid rebuild policy", "the product or release id is required")
	case errors.Is(err, app.ErrRebuildPolicyNotFound):
		writeProblem(w, http.StatusNotFound, "no rebuild policy", "no rebuild policy is stored for this scope")
	case err != nil:
		writeErr(w, "store rebuild policy", err)
	default:
		writeJSON(w, http.StatusOK, toRebuildPolicyRecord(rec))
	}
}

func toRebuildPolicyRecord(r app.RebuildPolicyRecord) gen.RebuildPolicyRecord {
	p := r.Policy
	out := gen.RebuildPolicyRecord{
		ScopeKind: gen.RebuildPolicyRecordScopeKind(r.ScopeKind), ScopeId: r.ScopeID, Version: r.Version,
		FixRequired: p.FixRequired, SeverityFloor: gen.RebuildPolicyRecordSeverityFloor(p.SeverityFloor),
		CountKnownExploited: p.CountKnownExploited, SkipDecided: p.SkipDecided, CarrierOnly: p.CarrierOnly,
		CoolDownSeconds: int64(p.CoolDown / time.Second), Mode: gen.RebuildPolicyRecordMode(p.Mode),
	}
	if !r.UpdatedAt.IsZero() {
		at, by := r.UpdatedAt, r.UpdatedBy
		out.UpdatedAt, out.UpdatedBy = &at, &by
	}
	if r.Removed {
		removed := true
		out.Removed = &removed
	}
	return out
}

func toRebuildPolicyRecords(recs []app.RebuildPolicyRecord) []gen.RebuildPolicyRecord {
	out := make([]gen.RebuildPolicyRecord, 0, len(recs))
	for _, rec := range recs {
		out = append(out, toRebuildPolicyRecord(rec))
	}
	return out
}

// --- Product and Release policies (D11; step R1a) ---

// ListRebuildPolicies serves every policy in force on one page.
func (h *Handler) ListRebuildPolicies(w http.ResponseWriter, r *http.Request) {
	if h.rebuild == nil {
		writeProblem(w, http.StatusServiceUnavailable, "rebuild policy unavailable", rebuildPolicyUnwired)
		return
	}
	recs, err := h.rebuild.List(r.Context())
	if err != nil {
		writeErr(w, "list rebuild policies", err)
		return
	}
	writeJSON(w, http.StatusOK, toRebuildPolicyRecords(recs))
}

// authorizeRebuildOverrideWrite decides who may change a Product or Release policy (D11 item
// 5): admin, or the key of the Product concerned. For a Release the owning Product is read from
// Registry, and a Product that cannot be established refuses the write (fail-closed). As in
// authorizeGovernanceWrite the response states the rule and the log carries the detail.
func (h *Handler) authorizeRebuildOverrideWrite(w http.ResponseWriter, r *http.Request, level domain.RebuildPolicyLevel, id string) bool {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok || p.IsAdmin() {
		return true
	}
	refusal := writeRefusal{principal: p}
	if !p.HasScopePrefix(auth.ProductScopePrefix) {
		refusal.reason = "rebuild policy change: key holds neither admin nor a product scope"
		h.logRefusal(w, r, refusal)
		writeProblem(w, http.StatusForbidden, "Forbidden",
			"this change requires "+auth.ScopeAdmin+" or "+auth.ProductScopePrefix+"<product-id>")
		return false
	}
	productID := id
	if level == domain.RebuildLevelRelease {
		refusal.releaseID = id
		if h.products == nil {
			refusal.reason = "rebuild policy change: no Registry seam to resolve the product (fail-closed)"
			h.logRefusal(w, r, refusal)
			writeProblem(w, http.StatusForbidden, "Forbidden",
				"the product this release belongs to could not be established, so the change was refused")
			return false
		}
		var err error
		if productID, err = h.products.ProductOfRelease(r.Context(), id); err != nil {
			refusal.reason, refusal.err = "rebuild policy change: product could not be resolved (fail-closed)", err
			h.logRefusal(w, r, refusal)
			writeProblem(w, http.StatusForbidden, "Forbidden",
				"the product this release belongs to could not be established, so the change was refused")
			return false
		}
	}
	refusal.productID = productID
	if !p.HasProductScope(productID) {
		refusal.reason = "rebuild policy change: key is scoped to a different product"
		h.logRefusal(w, r, refusal)
		writeProblem(w, http.StatusForbidden, "Forbidden", "this key is not scoped to the product concerned")
		return false
	}
	return true
}

func (h *Handler) getRebuildOverride(w http.ResponseWriter, r *http.Request, level domain.RebuildPolicyLevel, id string) {
	if h.rebuild == nil {
		writeProblem(w, http.StatusServiceUnavailable, "rebuild policy unavailable", rebuildPolicyUnwired)
		return
	}
	rec, found, err := h.rebuild.Override(r.Context(), level, id)
	if err == nil && !found {
		err = app.ErrRebuildPolicyNotFound
	}
	writeRebuildPolicyChange(w, rec, err)
}

func (h *Handler) putRebuildOverride(w http.ResponseWriter, r *http.Request, level domain.RebuildPolicyLevel, id string) {
	if !h.authorizeRebuildOverrideWrite(w, r, level, id) {
		return
	}
	if h.rebuild == nil {
		writeProblem(w, http.StatusServiceUnavailable, "rebuild policy unavailable", rebuildPolicyUnwired)
		return
	}
	policy, actor, ok := readRebuildPolicyPut(w, r)
	if !ok {
		return
	}
	rec, err := h.rebuild.PutOverride(r.Context(), level, id, policy, actor)
	writeRebuildPolicyChange(w, rec, err)
}

func (h *Handler) deleteRebuildOverride(w http.ResponseWriter, r *http.Request, level domain.RebuildPolicyLevel, id, actor string) {
	if !h.authorizeRebuildOverrideWrite(w, r, level, id) {
		return
	}
	if h.rebuild == nil {
		writeProblem(w, http.StatusServiceUnavailable, "rebuild policy unavailable", rebuildPolicyUnwired)
		return
	}
	rec, err := h.rebuild.RemoveOverride(r.Context(), level, id, actor)
	writeRebuildPolicyChange(w, rec, err)
}

func (h *Handler) rebuildOverrideHistory(w http.ResponseWriter, r *http.Request, level domain.RebuildPolicyLevel, id string) {
	if h.rebuild == nil {
		writeProblem(w, http.StatusServiceUnavailable, "rebuild policy unavailable", rebuildPolicyUnwired)
		return
	}
	recs, err := h.rebuild.OverrideHistory(r.Context(), level, id)
	if err != nil {
		writeErr(w, "read rebuild policy history", err)
		return
	}
	writeJSON(w, http.StatusOK, toRebuildPolicyRecords(recs))
}

// GetProductRebuildPolicy serves one Product's own policy; 404 when it has none.
func (h *Handler) GetProductRebuildPolicy(w http.ResponseWriter, r *http.Request, productID string) {
	h.getRebuildOverride(w, r, domain.RebuildLevelProduct, productID)
}

// PutProductRebuildPolicy stores a new version of one Product's policy.
func (h *Handler) PutProductRebuildPolicy(w http.ResponseWriter, r *http.Request, productID string) {
	h.putRebuildOverride(w, r, domain.RebuildLevelProduct, productID)
}

// DeleteProductRebuildPolicy removes one Product's policy.
func (h *Handler) DeleteProductRebuildPolicy(w http.ResponseWriter, r *http.Request, productID string, params gen.DeleteProductRebuildPolicyParams) {
	h.deleteRebuildOverride(w, r, domain.RebuildLevelProduct, productID, params.UpdatedBy)
}

// GetProductRebuildPolicyHistory serves every version of one Product's policy.
func (h *Handler) GetProductRebuildPolicyHistory(w http.ResponseWriter, r *http.Request, productID string) {
	h.rebuildOverrideHistory(w, r, domain.RebuildLevelProduct, productID)
}

// GetReleaseRebuildPolicy serves one Release's own policy; 404 when it has none.
func (h *Handler) GetReleaseRebuildPolicy(w http.ResponseWriter, r *http.Request, releaseID string) {
	h.getRebuildOverride(w, r, domain.RebuildLevelRelease, releaseID)
}

// PutReleaseRebuildPolicy stores a new version of one Release's policy.
func (h *Handler) PutReleaseRebuildPolicy(w http.ResponseWriter, r *http.Request, releaseID string) {
	h.putRebuildOverride(w, r, domain.RebuildLevelRelease, releaseID)
}

// DeleteReleaseRebuildPolicy removes one Release's policy.
func (h *Handler) DeleteReleaseRebuildPolicy(w http.ResponseWriter, r *http.Request, releaseID string, params gen.DeleteReleaseRebuildPolicyParams) {
	h.deleteRebuildOverride(w, r, domain.RebuildLevelRelease, releaseID, params.UpdatedBy)
}

// GetReleaseRebuildPolicyHistory serves every version of one Release's policy.
func (h *Handler) GetReleaseRebuildPolicyHistory(w http.ResponseWriter, r *http.Request, releaseID string) {
	h.rebuildOverrideHistory(w, r, domain.RebuildLevelRelease, releaseID)
}

// GetReleaseRebuildPolicyInForce serves the policy that applies to one Release and the level it
// comes from. A Product that cannot be read answers 503: the installation policy must not be
// shown in place of a Product policy nobody could look up.
func (h *Handler) GetReleaseRebuildPolicyInForce(w http.ResponseWriter, r *http.Request, releaseID string) {
	if h.rebuild == nil {
		writeProblem(w, http.StatusServiceUnavailable, "rebuild policy unavailable", rebuildPolicyUnwired)
		return
	}
	res, err := h.rebuild.InForce(r.Context(), releaseID)
	switch {
	case errors.Is(err, app.ErrRebuildPolicyIdentityUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, "rebuild policy unavailable",
			"the product this release belongs to could not be established, so the policy in force is not known")
	case err != nil:
		writeRebuildPolicyChange(w, app.RebuildPolicyRecord{}, err)
	default:
		out := gen.RebuildPolicyInForce{
			ReleaseId: res.ReleaseID, ProductId: res.ProductID, Policy: toRebuildPolicyRecord(res.InForce),
			InstallationMode: gen.RebuildPolicyInForceInstallationMode(res.InstallationMode),
			ModeCeiling:      gen.RebuildPolicyInForceModeCeiling(res.ModeCeiling),
			ModeSetBy:        gen.RebuildPolicyInForceModeSetBy(res.ModeSetBy),
			TagsApplied:      res.TagsApplied,
		}
		if res.TagsApplied {
			tag := toRebuildTagMode(res.Tag)
			mode := gen.RebuildPolicyInForceEffectiveMode(res.EffectiveMode)
			setBy := gen.RebuildPolicyInForceEffectiveModeSetBy(res.EffectiveSetBy)
			out.ProjectId, out.Tag, out.EffectiveMode, out.EffectiveModeSetBy = strptr(res.ProjectID), &tag, &mode, &setBy
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// toRebuildTagMode maps what the tags say to the wire; the tag and its level are absent when
// the Release carries no rebuild tag on any level.
func toRebuildTagMode(t domain.RebuildTagMode) gen.RebuildTagMode {
	out := gen.RebuildTagMode{Mode: gen.RebuildTagModeMode(t.Mode)}
	if t.Tag != "" {
		level := gen.RebuildTagModeLevel(t.Level)
		out.Tag, out.Level = strptr(t.Tag), &level
	}
	return out
}

// GetReleaseRebuildEvaluation handles GET /releases/{releaseId}/rebuild-evaluation: what the
// rebuild policy says about the Release now (EDR-REBUILD-01 step R2 part 1). A dry run — it
// stores nothing, publishes nothing and starts nothing.
func (h *Handler) GetReleaseRebuildEvaluation(w http.ResponseWriter, r *http.Request, releaseID string) {
	if h.rebuildEval == nil {
		writeProblem(w, http.StatusServiceUnavailable, "rebuild evaluation unavailable", rebuildPolicyUnwired)
		return
	}
	res, err := h.rebuildEval.Evaluate(r.Context(), releaseID)
	switch {
	case errors.Is(err, app.ErrRebuildPolicyIdentityUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, "rebuild evaluation unavailable",
			"the product and the tags of this release could not be read, so its rebuild mode is not known")
	case errors.Is(err, app.ErrRebuildEvaluationUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, "rebuild evaluation unavailable",
			"the release tags cannot be read on this node (no Registry seam), so no rebuild mode can be established")
	case err != nil:
		writeRebuildPolicyChange(w, app.RebuildPolicyRecord{}, err)
	default:
		writeJSON(w, http.StatusOK, toRebuildEvaluation(res))
	}
}

func toRebuildEvaluation(res app.RebuildEvaluation) gen.RebuildEvaluation {
	pol := res.Policy
	out := gen.RebuildEvaluation{
		ReleaseId: pol.ReleaseID, ProductId: pol.ProductID, ProjectId: pol.ProjectID,
		EvaluatedAt: res.EvaluatedAt, Policy: toRebuildPolicyRecord(pol.InForce),
		InstallationMode:   gen.RebuildEvaluationInstallationMode(pol.InstallationMode),
		ModeCeiling:        gen.RebuildEvaluationModeCeiling(pol.ModeCeiling),
		Tag:                toRebuildTagMode(pol.Tag),
		EffectiveMode:      gen.RebuildEvaluationEffectiveMode(pol.EffectiveMode),
		EffectiveModeSetBy: gen.RebuildEvaluationEffectiveModeSetBy(pol.EffectiveSetBy),
		Outcome:            gen.RebuildEvaluationOutcome(res.Outcome),
		Considered:         res.Considered,
		FixVerdictsRead:    res.FixVerdictsRead,
	}
	out.Skipped.Decided = res.Skipped[domain.RebuildSkippedDecided]
	out.Skipped.ScopeComponent = res.Skipped[domain.RebuildSkippedScope]
	out.Skipped.NoFix = res.Skipped[domain.RebuildSkippedNoFix]
	out.Skipped.FixUnknown = res.Skipped[domain.RebuildSkippedFixUnknown]
	out.Skipped.BelowFloor = res.Skipped[domain.RebuildSkippedBelowFloor]
	out.Skipped.FixOtherStream = res.Skipped[domain.RebuildSkippedOtherStream]
	out.Targeted = toRebuildEntries(res.Targeted)
	out.OtherStream = toRebuildEntries(res.OtherStream)
	return out
}

func toRebuildEntries(entries []app.RebuildEvaluationEntry) []gen.RebuildTargetEntry {
	out := make([]gen.RebuildTargetEntry, 0, len(entries))
	for _, t := range entries {
		e := gen.RebuildTargetEntry{
			FindingId: string(t.FindingID), Cve: t.CVE, Purl: t.PURL,
			CurrentVersion: t.CurrentVersion, FixedVersions: t.FixedVersions,
			Severity: t.Severity, Score: t.Score,
			ScoreSource:    gen.RebuildTargetEntryScoreSource(t.ScoreSource),
			KnownExploited: t.KnownExploited,
			ClaimClass:     gen.RebuildTargetEntryClaimClass(rebuildClaimClass(t.ClaimClass)),
			Position:       rebuildPosition(t.Position),
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

// rebuildClaimClass is D34's claim class: `carrier`, `scope`, and `unknown` for everything else
// (an empty or unreadable class acts as carrier and is said to be unknown).
func rebuildClaimClass(c string) string {
	switch c {
	case "carrier", domain.ClaimScope:
		return c
	default:
		return "unknown"
	}
}

// rebuildPosition is D34's position: `none`, or the stance in force.
func rebuildPosition(s domain.Stance) string {
	if s == "" {
		return "none"
	}
	return string(s)
}
