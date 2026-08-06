package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/governance/domain"
)

func TestBlastMultiplier(t *testing.T) {
	tests := []struct {
		customers int
		cap       int
		want      float64
	}{
		// Default cap (10) — legacy-parity behavior, unchanged.
		{0, domain.DefaultBlastRadiusCap, 1.0},
		{1, domain.DefaultBlastRadiusCap, 1.0},
		{2, domain.DefaultBlastRadiusCap, 1.1},
		{5, domain.DefaultBlastRadiusCap, 1.4},
		{9, domain.DefaultBlastRadiusCap, 1.8},
		{10, domain.DefaultBlastRadiusCap, 2.0},
		{11, domain.DefaultBlastRadiusCap, 2.0},
		{1000, domain.DefaultBlastRadiusCap, 2.0},
		// A tighter configured cap saturates sooner (a small org reaches 2.0× at fewer customers).
		{3, 5, 1.2},
		{5, 5, 2.0},
		{4, 5, 1.3},
		// A wider cap: the fixed +0.1/customer slope is clamped so the multiplier never exceeds 2.0×.
		{15, 30, 2.0},
		{12, 30, 2.0}, // 1.0 + 0.1×11 = 2.1 → clamped to 2.0
	}
	for _, tt := range tests {
		if got := domain.BlastMultiplier(tt.customers, tt.cap); got != tt.want {
			t.Errorf("BlastMultiplier(%d, cap=%d) = %v, want %v", tt.customers, tt.cap, got, tt.want)
		}
	}
}

func TestEffectivePriority(t *testing.T) {
	tests := []struct {
		base int
		mult float64
		want int
	}{
		{90, 1.0, 90},   // no amplification
		{50, 1.4, 70},   // 50 × 1.4
		{80, 2.0, 100},  // 80 × 2.0 = 160 → clamped to 100
		{100, 1.0, 100}, // already max
		{0, 2.0, 0},     // zero base stays zero
		{33, 1.15, 38},  // rounds (37.95 → 38)
		{-5, 1.0, 0},    // a negative base clamps to 0 (defensive)
	}
	for _, tt := range tests {
		if got := domain.EffectivePriority(tt.base, tt.mult); got != tt.want {
			t.Errorf("EffectivePriority(%d, %v) = %d, want %d", tt.base, tt.mult, got, tt.want)
		}
	}
}

// StanceWeight is the deterministic disposition policy of EDR-GOVERNANCE-01 D14. The two
// classes that matter are asserted explicitly: a TERMINAL disposition (the risk is removed, or
// knowingly owned) zeroes the triage number, while anything still open keeps its full weight.
func TestStanceWeight(t *testing.T) {
	for _, tc := range []struct {
		name   string
		stance domain.Stance
		want   float64
	}{
		{"not_affected is terminal — the risk is gone", domain.StanceNotAffected, 0},
		{"accepted_risk is terminal — the risk is owned", domain.StanceAcceptedRisk, 0},
		{"mitigated is reduced, not gone", domain.StanceMitigated, domain.DefaultMitigatedWeight},
		{"deferred is parked, so it slips only slightly", domain.StanceDeferred, 0.9},
		{"affected is undecided — full weight", domain.StanceAffected, 1.0},
		{"under_investigation is undecided — full weight", domain.StanceUnderInvestigation, 1.0},
		{"no position at all — full weight", domain.Stance(""), 1.0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.StanceWeight(tc.stance, domain.DefaultMitigatedWeight); got != tc.want {
				t.Fatalf("StanceWeight(%q) = %v, want %v", tc.stance, got, tc.want)
			}
		})
	}
}

// An unrecognized stance must fail LOUD, not quiet. A stance this build does not know about —
// a newer node writing a value an older one has not learned — must keep demanding attention;
// weighing it 0 would silently drop a live Finding out of the triage queue.
func TestStanceWeight_UnknownStanceKeepsFullWeight(t *testing.T) {
	if got := domain.StanceWeight(domain.Stance("invented_later"), domain.DefaultMitigatedWeight); got != 1.0 {
		t.Fatalf("StanceWeight(unknown) = %v, want 1.0 — an unknown disposition must never suppress", got)
	}
}

// The mitigated weight is the one operator-tunable input (D14), so an out-of-range value must
// degrade to the default rather than be honored. A negative or >1 weight would either suppress
// a Finding outright or inflate it past its intrinsic priority.
func TestStanceWeight_OutOfRangeMitigatedWeightFallsBackToDefault(t *testing.T) {
	for _, w := range []float64{-0.5, 1.5} {
		if got := domain.StanceWeight(domain.StanceMitigated, w); got != domain.DefaultMitigatedWeight {
			t.Fatalf("StanceWeight(mitigated, %v) = %v, want the %v default", w, got, domain.DefaultMitigatedWeight)
		}
	}
	if got := domain.StanceWeight(domain.StanceMitigated, 0.25); got != 0.25 {
		t.Fatalf("StanceWeight(mitigated, 0.25) = %v, want the override honored", got)
	}
}

func TestResidualPriority(t *testing.T) {
	for _, tc := range []struct {
		name      string
		effective int
		weight    float64
		want      int
	}{
		{"a suppressed Finding leaves the queue", 70, 0, 0},
		{"an undecided Finding is unchanged", 70, 1.0, 70},
		{"mitigated halves it (rounded)", 70, 0.5, 35},
		{"deferred barely moves it", 70, 0.9, 63},
		{"clamped to 100", 100, 1.5, 100},
		{"never negative", 70, -1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.ResidualPriority(tc.effective, tc.weight); got != tc.want {
				t.Fatalf("ResidualPriority(%d, %v) = %d, want %d", tc.effective, tc.weight, got, tc.want)
			}
		})
	}
}

// The property that motivates keeping BOTH numbers (D14): suppressing a Finding must not erase
// how bad it actually is. Its residual drops to 0 while its effective priority is untouched —
// which is what lets the D14 re-evaluation watcher re-surface it later on the same evidence.
func TestResidualPriority_SuppressionDoesNotDestroyIntrinsicSeverity(t *testing.T) {
	const base, mult = 90, 1.5
	eff := domain.EffectivePriority(base, mult)
	res := domain.ResidualPriority(eff, domain.StanceWeight(domain.StanceNotAffected, domain.DefaultMitigatedWeight))
	if res != 0 {
		t.Fatalf("residual = %d, want 0 for a not_affected Finding", res)
	}
	if eff != 100 {
		t.Fatalf("effective = %d, want the intrinsic severity preserved (clamped 90 x 1.5)", eff)
	}
}
