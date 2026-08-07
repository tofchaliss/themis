package domain

import (
	"testing"

	"github.com/themis-project/themis/internal/kernel/value"
)

func cvss(t *testing.T, score float64) value.CVSS {
	t.Helper()
	c, err := value.NewCVSS(score, "")
	if err != nil {
		t.Fatalf("NewCVSS(%v): %v", score, err)
	}
	return c
}

func TestPriorityAndScore(t *testing.T) {
	z := value.CVSS{} // zero CVSS (no score supplied)
	cases := []struct {
		name     string
		v        EnterpriseView
		priority string
		score    int
	}{
		// --- Priority Layer-1 rules (first match) ---
		{"crit: c>=9 & KEV", EnterpriseView{Severity: value.SeverityCritical, CVSS: cvss(t, 9.8), KEV: true}, PriorityCritical, 100},
		{"high+: c>=9 & exploit", EnterpriseView{CVSS: cvss(t, 9.8), ExploitPublic: true}, PriorityHighPlus, 90},                         // sev derived from CVSS 9.8 -> critical base 90
		{"high: KEV & c<9", EnterpriseView{Severity: value.SeverityHigh, CVSS: cvss(t, 7.5), KEV: true}, PriorityHigh, 85},               // 70 + 15
		{"elevated: EPSS>=.5 & c>=7", EnterpriseView{Severity: value.SeverityHigh, CVSS: cvss(t, 7.5), EPSS: 0.6}, PriorityElevated, 83}, // 70 + 70*.6*.3 = 82.6
		{"high: c>=9 plain", EnterpriseView{Severity: value.SeverityHigh, CVSS: cvss(t, 9.1)}, PriorityHigh, 70},
		{"informational: low c", EnterpriseView{Severity: value.SeverityMedium, CVSS: cvss(t, 5.0)}, PriorityInformational, 40},

		// --- effectiveCVSS severity proxies (no CVSS) + effectiveSeverity return-set branch ---
		{"proxy high -> elevated", EnterpriseView{Severity: value.SeverityHigh, CVSS: z, EPSS: 0.6}, PriorityElevated, 83}, // c=7 proxy; 70 + 12.6
		{"proxy medium -> info", EnterpriseView{Severity: value.SeverityMedium, CVSS: z}, PriorityInformational, 40},
		{"proxy low -> info", EnterpriseView{Severity: value.SeverityLow, CVSS: z}, PriorityInformational, 10},
		{"proxy critical -> high", EnterpriseView{Severity: value.SeverityCritical, CVSS: z, EPSS: 0.2}, PriorityHigh, 95}, // c=9 proxy, no KEV -> rule5; 90 + 5.4

		// --- effectiveSeverity: derive from CVSS when headline none/unknown ---
		{"none sev + CVSS derives", EnterpriseView{Severity: value.SeverityNone, CVSS: cvss(t, 9.0)}, PriorityHigh, 90}, // derived critical base 90
		{"unknown sev no CVSS -> 0", EnterpriseView{Severity: value.SeverityUnknown, CVSS: z}, PriorityInformational, 0},

		// --- Score edges ---
		{"KEV bump + clamp", EnterpriseView{Severity: value.SeverityHigh, CVSS: cvss(t, 7.5), EPSS: 0.9, KEV: true}, PriorityHigh, 100}, // 70 + 18.9 + 15 = 103.9 -> 100
		// Was 65 (base 50 + KEV 15). Now floored to the high baseline, because the band calls it
		// `high` and a score beneath its own band tells a reader the opposite of the label
		// (KN-EPSS-BAND-1 (b)).
		{"unknown sev + KEV, floored to its band", EnterpriseView{Severity: value.SeverityUnknown, CVSS: z, KEV: true}, PriorityHigh, 70},
		{"unknown sev + exploit floor", EnterpriseView{Severity: value.SeverityUnknown, CVSS: z, ExploitPublic: true}, PriorityInformational, 25}, // base 25
		{"low baseline", EnterpriseView{Severity: value.SeverityLow, CVSS: cvss(t, 2.0)}, PriorityInformational, 10},
	}
	for _, c := range cases {
		if got := c.v.Priority(); got != c.priority {
			t.Errorf("%s: Priority() = %q, want %q", c.name, got, c.priority)
		}
		if got := c.v.Score(); got != c.score {
			t.Errorf("%s: Score() = %d, want %d", c.name, got, c.score)
		}
	}
}

// KN-EPSS-BAND-1. Measured on a live estate 2026-08-07: CVE-2021-45105 (log4j, CVSS 5.9,
// EPSS 99%) was banded `informational` — the label that tells an operator to do nothing, about a
// vulnerability FIRST rates near-certain to be attacked. EPSS reached the band only via the
// `elevated` rule, which also requires CVSS >= 7, so a medium-CVSS CVE fell through to the
// default arm however certain its exploitation.
func TestPriority_NearCertainEPSSLiftsALowCVSSOutOfInformational(t *testing.T) {
	for _, tc := range []struct {
		name string
		view EnterpriseView
		want string
	}{
		{
			name: "the measured case: medium CVSS, 99% EPSS",
			view: EnterpriseView{Severity: value.SeverityMedium, EPSS: 0.99},
			want: PriorityHigh,
		},
		{
			// The arm is for "already being exploited", not merely elevated probability, so it
			// sits far above `elevated`'s 0.5 floor. 0.6 must still land on the old rules.
			name: "elevated probability alone does not reach the new arm",
			view: EnterpriseView{Severity: value.SeverityMedium, EPSS: 0.6},
			want: PriorityInformational,
		},
		{
			// KEV is a CONFIRMED exploitation record; EPSS is a prediction. A critical KEV entry
			// must still band `critical`, so the new arm cannot overtake the KEV arms above it.
			name: "KEV still wins on a critical",
			view: EnterpriseView{Severity: value.SeverityCritical, EPSS: 0.99, KEV: true},
			want: PriorityCritical,
		},
		{
			// A high-CVSS CVE with high EPSS keeps its existing `elevated` band: that rule is
			// more specific (it also excludes KEV and public exploits) and still matches first.
			name: "high CVSS with high EPSS keeps elevated",
			view: EnterpriseView{Severity: value.SeverityHigh, EPSS: 0.95},
			want: PriorityElevated,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.view.Priority(); got != tc.want {
				t.Errorf("Priority() = %q, want %q", got, tc.want)
			}
		})
	}
}

// KN-EPSS-BAND-1 (b), decided 2026-08-07: the SCORE must not contradict the BAND.
//
// (a) made a near-certain-EPSS CVE band `high` however low its CVSS. The score still said 52,
// below a 0%-EPSS `high` at 70 — one artefact saying "treat this as high", the other sorting it
// beneath things it had just been declared equal to. The decision was NOT to let likelihood
// outrank severity in general; it was to stop the two numbers disagreeing.
func TestScore_DoesNotContradictTheBand(t *testing.T) {
	for _, tc := range []struct {
		name string
		view EnterpriseView
		want int
	}{
		{
			// The measured case: CVE-2021-45105, CVSS 5.9, EPSS 99.999%.
			name: "a near-certain medium is floored at the high baseline",
			view: EnterpriseView{Severity: value.SeverityMedium, EPSS: 0.99999},
			want: 70,
		},
		{
			// Below the near-certain threshold nothing changes: 40 + 40*0.6*0.3 = 47.
			name: "an elevated-probability medium keeps its computed score",
			view: EnterpriseView{Severity: value.SeverityMedium, EPSS: 0.6},
			want: 47,
		},
		{
			// The floor never LOWERS a score: a high with near-certain EPSS computes above 70.
			name: "a high with near-certain EPSS keeps its lift",
			view: EnterpriseView{Severity: value.SeverityHigh, EPSS: 0.99},
			want: 91,
		},
		{
			// Severity still dominates: a critical outranks any floored medium.
			name: "a critical is unaffected",
			view: EnterpriseView{Severity: value.SeverityCritical, EPSS: 0.0},
			want: 90,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.view.Score(); got != tc.want {
				t.Errorf("Score() = %d, want %d (band %q)", got, tc.want, tc.view.Priority())
			}
		})
	}

	// The invariant the floor exists to protect, stated directly: anything the band calls `high`
	// scores at least the high baseline. Within a band the score may still order by severity —
	// that is refinement, not contradiction. What is forbidden is a `high`-banded CVE scoring
	// beneath the band it was just assigned.
	//
	// Note while writing this: a plain high-severity CVE with NO exploit signals bands
	// `informational`, because the band is EXPLOITABILITY priority and not severity. That is the
	// documented design and the score carries severity — but "informational" is a poor word for
	// "no exploitability signal yet", and it is the same misreading KN-EPSS-BAND-1 (a) fixed one
	// case of. Filed as KN-BAND-NAME-1.
	for _, v := range []EnterpriseView{
		{Severity: value.SeverityMedium, EPSS: 0.99999},        // floored by the new arm
		{Severity: value.SeverityLow, KEV: true},               // banded high by the KEV arm
		{Severity: value.SeverityCritical, CVSS: cvss(t, 9.1)}, // banded high by the c>=9 arm
	} {
		if v.Priority() != PriorityHigh {
			t.Fatalf("fixture wrong: %+v bands %q, want high", v, v.Priority())
		}
		if got := v.Score(); got < severityBaseline(value.SeverityHigh) {
			t.Errorf("banded %q but scored %d, below the high baseline %d — the score contradicts the band",
				v.Priority(), got, severityBaseline(value.SeverityHigh))
		}
	}
}
