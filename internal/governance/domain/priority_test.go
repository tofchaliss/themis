package domain_test

import (
	"testing"

	"github.com/themis-project/themis/internal/governance/domain"
)

func TestBlastMultiplier(t *testing.T) {
	tests := []struct {
		customers int
		want      float64
	}{
		{0, 1.0},
		{1, 1.0},
		{2, 1.1},
		{5, 1.4},
		{9, 1.8},
		{10, 2.0},
		{11, 2.0},
		{1000, 2.0},
	}
	for _, tt := range tests {
		if got := domain.BlastMultiplier(tt.customers); got != tt.want {
			t.Errorf("BlastMultiplier(%d) = %v, want %v", tt.customers, got, tt.want)
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
