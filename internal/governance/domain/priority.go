package domain

// Blast-radius risk amplification (EDR-ESTATE-01 C2), ported verbatim from the v0.3.x
// monolith's ComputeBlastRadiusScore. A Finding's release-scoped priority is the CVE-intrinsic
// base score scaled by how much of the enterprise estate it reaches (unique customers).
const (
	blastMultMin = 1.0
	blastMultMax = 2.0
	blastMultCap = 10 // unique-customer count at/above which the multiplier saturates
)

// BlastMultiplier maps the count of unique customers a Finding's release reaches to a
// 1.0–2.0× risk multiplier. 0 or 1 customer ⇒ 1.0 (no amplification); each additional
// customer adds 0.1, capped at 10 customers (2.0×).
func BlastMultiplier(uniqueCustomers int) float64 {
	if uniqueCustomers <= 1 {
		return blastMultMin
	}
	if uniqueCustomers >= blastMultCap {
		return blastMultMax
	}
	score := blastMultMin + 0.1*float64(uniqueCustomers-1)
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
