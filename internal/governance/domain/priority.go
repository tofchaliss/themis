package domain

// Blast-radius risk amplification (EDR-ESTATE-01 C2), ported from the v0.3.x monolith's
// ComputeBlastRadiusScore. A Finding's release-scoped priority is the CVE-intrinsic base score
// scaled by how much of the enterprise estate it reaches (unique customers).
const (
	blastMultMin = 1.0
	blastMultMax = 2.0
	// DefaultBlastRadiusCap is the unique-customer count at/above which the multiplier saturates
	// to 2.0× when no operator override is set (the legacy monolith's fixed value). Configurable
	// via THEMIS_BLAST_RADIUS_CAP (parity with the legacy `intelligence.blast_radius_cap`).
	DefaultBlastRadiusCap = 10
)

// BlastMultiplier maps the count of unique customers a Finding's release reaches to a
// 1.0–2.0× risk multiplier. 0 or 1 customer ⇒ 1.0 (no amplification); each additional
// customer adds 0.1, saturating to 2.0× at `cap` customers. `cap` is supplied by the caller
// (the composition root reads it from config); it must be ≥ 2 — a smaller value is the caller's
// responsibility to normalize (see the wiring layer).
func BlastMultiplier(uniqueCustomers, cap int) float64 {
	if uniqueCustomers <= 1 {
		return blastMultMin
	}
	if uniqueCustomers >= cap {
		return blastMultMax
	}
	score := blastMultMin + 0.1*float64(uniqueCustomers-1)
	if score > blastMultMax {
		return blastMultMax // a cap > 11 would let the fixed +0.1/customer slope exceed 2.0×; clamp
	}
	return float64(int(score*100+0.5)) / 100 // round to 2 decimal places
}

// EffectivePriority scales a CVE-intrinsic base score (0–100) by the blast multiplier —
// how bad this is here, **regardless of what was decided** (D14).
//
// It is deliberately NOT clamped (D17 / GOV-15, measured 2026-08-08): the multiplier is a
// per-release CONSTANT, so within a release it can never reorder — but a 100-clamp is not
// order-preserving, and at a saturated estate it pinned every base ≥ 50 to 100, dropping the
// release's worst Finding out of the top three and handing `--ai N` an arbitrary N. The value
// is a RANKING NUMBER, not a percentage: range 0–200 (base ≤ 100 × multiplier ≤ 2.0, the
// saturation BlastMultiplier already guarantees).
func EffectivePriority(base int, mult float64) int {
	return roundPriority(float64(base) * mult)
}

// DefaultMitigatedWeight is the stance weight for `mitigated` when no operator override is set
// (EDR-GOVERNANCE-01 D14). It is the one weight D14 leaves configurable, because "mitigated"
// spans a real range — a compensating control may remove most of the risk or very little — while
// the others are structural: a terminal risk-removing or risk-accepted disposition is 0, and an
// open one is 1.0, in every enterprise.
const DefaultMitigatedWeight = 0.5

// StanceWeight is the deterministic disposition policy of D14: how much of a Finding's
// intrinsic priority still demands attention, given the stance of its current Position.
//
//   - not_affected / accepted_risk → 0    — terminal. The risk is removed, or knowingly owned.
//   - mitigated                    → mitigatedWeight (default 0.5) — reduced, not gone.
//   - deferred                     → 0.9  — still real; deliberately parked, so it slips only
//     slightly rather than dropping off the list.
//   - affected / under_investigation / no position → 1.0 — nothing has been decided yet.
//
// A zero weight is what makes `accepted_risk` safe to zero out: the acceptance does not delete
// the Finding or its intrinsic score, it removes it from the triage queue — and D14's
// re-evaluation watcher re-surfaces it when the premise drifts. An unrecognized stance weighs
// 1.0, failing **loud**: an unknown disposition must keep demanding attention, never silently
// suppress a Finding.
func StanceWeight(s Stance, mitigatedWeight float64) float64 {
	switch s {
	case StanceNotAffected, StanceAcceptedRisk:
		return 0
	case StanceMitigated:
		if mitigatedWeight < 0 || mitigatedWeight > 1 {
			return DefaultMitigatedWeight // an out-of-range override is a config error, not a licence to suppress
		}
		return mitigatedWeight
	case StanceDeferred:
		return 0.9
	default:
		return 1.0 // affected, under_investigation, no position, or anything unrecognized
	}
}

// ResidualPriority is the **triage** number of D14 — effective priority scaled by the stance
// weight. It answers "what still needs my attention?", where EffectivePriority answers "how bad
// is this here?". Keeping both is the whole point: a dispositioned Finding drops out of the top
// of the queue without losing the intrinsic severity that justifies revisiting it later.
// Like EffectivePriority it is unclamped (D17): weight ≤ 1.0 keeps residual ≤ effective, so the
// range is the same 0–200 and the ordering the weight produces is never flattened.
func ResidualPriority(effective int, weight float64) int {
	return roundPriority(float64(effective) * weight)
}

// roundPriority rounds to the nearest integer with a floor of 0 (defensive against a negative
// base). No upper clamp — that is the substance of D17.
func roundPriority(v float64) int {
	n := int(v + 0.5)
	if n < 0 {
		return 0
	}
	return n
}
