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

// EffectivePriority scales a CVE-intrinsic base score (0–100) by the blast multiplier and
// clamps to 100 — the release-scoped priority a human triages by.
func EffectivePriority(base int, mult float64) int {
	v := int(float64(base)*mult + 0.5)
	if v > 100 {
		return 100
	}
	if v < 0 {
		return 0
	}
	return v
}
