package domain_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

func TestRebuildModeValidAndLowest(t *testing.T) {
	for _, m := range []domain.RebuildMode{domain.RebuildModeOff, domain.RebuildModeAsk, domain.RebuildModeAuto} {
		if !m.Valid() {
			t.Fatalf("%q must be valid", m)
		}
	}
	if domain.RebuildMode("always").Valid() {
		t.Fatal("an unknown mode must not be valid")
	}
	cases := []struct {
		in   []domain.RebuildMode
		want domain.RebuildMode
	}{
		{nil, domain.RebuildModeOff},
		{[]domain.RebuildMode{domain.RebuildModeAuto}, domain.RebuildModeAuto},
		{[]domain.RebuildMode{domain.RebuildModeAuto, domain.RebuildModeAsk}, domain.RebuildModeAsk},
		{[]domain.RebuildMode{domain.RebuildModeAsk, domain.RebuildModeAuto}, domain.RebuildModeAsk},
		{[]domain.RebuildMode{domain.RebuildModeAuto, domain.RebuildModeAuto, domain.RebuildModeOff}, domain.RebuildModeOff},
		// A value this code cannot read never allows a build.
		{[]domain.RebuildMode{domain.RebuildModeAuto, "always"}, domain.RebuildModeOff},
		{[]domain.RebuildMode{"always"}, domain.RebuildModeOff},
	}
	for _, c := range cases {
		if got := domain.LowestRebuildMode(c.in...); got != c.want {
			t.Errorf("LowestRebuildMode(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDefaultRebuildPolicyIsD2(t *testing.T) {
	want := domain.RebuildPolicy{
		FixRequired: true, SeverityFloor: domain.SLABucketHigh, CountKnownExploited: true,
		SkipDecided: true, CarrierOnly: true, CoolDown: 24 * time.Hour, Mode: domain.RebuildModeAsk,
	}
	got := domain.DefaultRebuildPolicy()
	if got != want {
		t.Fatalf("default = %+v, want %+v", got, want)
	}
	if !got.Valid() {
		t.Fatal("the default policy must be valid")
	}
}

func TestRebuildPolicyValid(t *testing.T) {
	ok := domain.DefaultRebuildPolicy()
	for name, mutate := range map[string]func(*domain.RebuildPolicy){
		"unknown floor":      func(p *domain.RebuildPolicy) { p.SeverityFloor = "severe" },
		"empty floor":        func(p *domain.RebuildPolicy) { p.SeverityFloor = "" },
		"unknown mode":       func(p *domain.RebuildPolicy) { p.Mode = "always" },
		"negative cool-down": func(p *domain.RebuildPolicy) { p.CoolDown = -time.Second },
		"cool-down too long": func(p *domain.RebuildPolicy) { p.CoolDown = domain.RebuildCoolDownMax + time.Second },
	} {
		p := ok
		mutate(&p)
		if p.Valid() {
			t.Errorf("%s: must not be valid", name)
		}
	}
	for _, floor := range []string{domain.SLABucketLow, domain.SLABucketMedium, domain.SLABucketHigh, domain.SLABucketCritical} {
		p := ok
		p.SeverityFloor, p.CoolDown, p.Mode = floor, 0, domain.RebuildModeOff
		if !p.Valid() {
			t.Errorf("floor %q with no cool-down and mode off must be valid", floor)
		}
	}
}

// cand is a carrier component of an undecided High Finding with a known fix: it counts under
// the default policy. Each test changes one fact.
func cand(mutate func(*domain.RebuildCandidate)) domain.RebuildCandidate {
	c := domain.RebuildCandidate{
		FindingID: "f-1", CVE: "CVE-0000-0001", PURL: "pkg:rpm/example/lib@1.0",
		Severity: domain.SLABucketHigh, ClaimClass: "carrier", Fix: domain.RebuildFixKnown,
	}
	if mutate != nil {
		mutate(&c)
	}
	return c
}

func TestEvaluateRebuildDefaultPolicy(t *testing.T) {
	p := domain.DefaultRebuildPolicy()
	cases := []struct {
		name    string
		c       domain.RebuildCandidate
		because []string // nil = not counted
	}{
		{"high with a fix counts", cand(nil), []string{domain.RebuildCountedSeverityFloor}},
		{"critical counts", cand(func(c *domain.RebuildCandidate) { c.Severity = domain.SLABucketCritical }), []string{domain.RebuildCountedSeverityFloor}},
		{"medium is below the floor", cand(func(c *domain.RebuildCandidate) { c.Severity = domain.SLABucketMedium }), nil},
		{"no severity is below the floor", cand(func(c *domain.RebuildCandidate) { c.Severity = "" }), nil},
		{"medium but known exploited counts", cand(func(c *domain.RebuildCandidate) {
			c.Severity, c.KnownExploited = domain.SLABucketMedium, true
		}), []string{domain.RebuildCountedKnownExploited}},
		{"high and known exploited gives both reasons", cand(func(c *domain.RebuildCandidate) { c.KnownExploited = true }),
			[]string{domain.RebuildCountedSeverityFloor, domain.RebuildCountedKnownExploited}},
		{"no fix does not count", cand(func(c *domain.RebuildCandidate) { c.Fix = domain.RebuildFixNone }), nil},
		{"unknown fix is not a known fix", cand(func(c *domain.RebuildCandidate) { c.Fix = domain.RebuildFixUnknown }), nil},
		{"empty fix verdict is not a known fix", cand(func(c *domain.RebuildCandidate) { c.Fix = "" }), nil},
		{"not_affected is skipped", cand(func(c *domain.RebuildCandidate) { c.Position = domain.StanceNotAffected }), nil},
		{"accepted_risk is skipped", cand(func(c *domain.RebuildCandidate) { c.Position = domain.StanceAcceptedRisk }), nil},
		{"affected still counts", cand(func(c *domain.RebuildCandidate) { c.Position = domain.StanceAffected }), []string{domain.RebuildCountedSeverityFloor}},
		{"scope component is skipped", cand(func(c *domain.RebuildCandidate) { c.ClaimClass = domain.ClaimScope }), nil},
		{"scope with spaces is still scope", cand(func(c *domain.RebuildCandidate) { c.ClaimClass = " scope " }), nil},
		{"unknown claim class acts as carrier", cand(func(c *domain.RebuildCandidate) { c.ClaimClass = "" }), []string{domain.RebuildCountedSeverityFloor}},
	}
	for _, tc := range cases {
		v := domain.EvaluateRebuild(p, []domain.RebuildCandidate{tc.c})
		if tc.because == nil {
			if len(v.Targeted) != 0 || v.Worth() {
				t.Errorf("%s: counted %+v, want nothing", tc.name, v.Targeted)
			}
			continue
		}
		if len(v.Targeted) != 1 || !reflect.DeepEqual(v.Targeted[0].CountedBecause, tc.because) {
			t.Errorf("%s: targeted %+v, want one entry because %v", tc.name, v.Targeted, tc.because)
			continue
		}
		if v.Targeted[0].RebuildCandidate != tc.c || !v.Worth() {
			t.Errorf("%s: the entry must carry the candidate and be worth a rebuild", tc.name)
		}
	}
}

func TestEvaluateRebuildSwitchesOff(t *testing.T) {
	// Each switch, turned off, lets through what it held back.
	p := domain.DefaultRebuildPolicy()
	p.FixRequired = false
	if v := domain.EvaluateRebuild(p, []domain.RebuildCandidate{cand(func(c *domain.RebuildCandidate) { c.Fix = domain.RebuildFixUnknown })}); len(v.Targeted) != 1 {
		t.Error("fix_required off: a Finding with no known fix must count")
	}
	p = domain.DefaultRebuildPolicy()
	p.SkipDecided = false
	if v := domain.EvaluateRebuild(p, []domain.RebuildCandidate{cand(func(c *domain.RebuildCandidate) { c.Position = domain.StanceAcceptedRisk })}); len(v.Targeted) != 1 {
		t.Error("skip_decided off: an accepted Finding must count")
	}
	p = domain.DefaultRebuildPolicy()
	p.CarrierOnly = false
	if v := domain.EvaluateRebuild(p, []domain.RebuildCandidate{cand(func(c *domain.RebuildCandidate) { c.ClaimClass = domain.ClaimScope })}); len(v.Targeted) != 1 {
		t.Error("carrier_only off: a scope component must count")
	}
	p = domain.DefaultRebuildPolicy()
	p.CountKnownExploited = false
	if v := domain.EvaluateRebuild(p, []domain.RebuildCandidate{cand(func(c *domain.RebuildCandidate) {
		c.Severity, c.KnownExploited = domain.SLABucketLow, true
	})}); len(v.Targeted) != 0 {
		t.Error("count_known_exploited off: a low known-exploited Finding must not count")
	}
	p = domain.DefaultRebuildPolicy()
	p.SeverityFloor = domain.SLABucketLow
	if v := domain.EvaluateRebuild(p, []domain.RebuildCandidate{cand(func(c *domain.RebuildCandidate) { c.Severity = domain.SLABucketLow })}); len(v.Targeted) != 1 {
		t.Error("floor low: a low Finding must count")
	}
}

func TestEvaluateRebuildModeAndOrder(t *testing.T) {
	a := cand(nil)
	b := cand(func(c *domain.RebuildCandidate) { c.FindingID, c.Severity = "f-2", domain.SLABucketMedium })
	c := cand(func(c *domain.RebuildCandidate) { c.FindingID = "f-3" })

	p := domain.DefaultRebuildPolicy()
	v := domain.EvaluateRebuild(p, []domain.RebuildCandidate{a, b, c})
	if v.Mode != domain.RebuildModeAsk || len(v.Targeted) != 2 || v.Targeted[0].FindingID != "f-1" || v.Targeted[1].FindingID != "f-3" {
		t.Fatalf("verdict = %+v, want mode ask and f-1, f-3 in the order given", v)
	}

	// Mode off: the counted set is still reported, but a rebuild is not worth asking for.
	p.Mode = domain.RebuildModeOff
	if v := domain.EvaluateRebuild(p, []domain.RebuildCandidate{a}); len(v.Targeted) != 1 || v.Worth() {
		t.Fatalf("mode off: verdict = %+v, want one counted entry and not worth", v)
	}
	// A mode this code cannot read is treated as off.
	p.Mode = "always"
	if v := domain.EvaluateRebuild(p, []domain.RebuildCandidate{a}); v.Mode != domain.RebuildModeOff || v.Worth() {
		t.Fatalf("unknown mode: verdict = %+v, want mode off", v)
	}
	// Nothing to evaluate is not worth a rebuild in any mode.
	p.Mode = domain.RebuildModeAuto
	if v := domain.EvaluateRebuild(p, nil); v.Mode != domain.RebuildModeAuto || v.Worth() {
		t.Fatalf("no candidates: verdict = %+v, want mode auto and not worth", v)
	}
	// An unreadable floor counts nothing by severity; known exploited still counts.
	p.SeverityFloor = "severe"
	if v := domain.EvaluateRebuild(p, []domain.RebuildCandidate{a}); len(v.Targeted) != 0 {
		t.Fatalf("unreadable floor: counted %+v, want nothing", v.Targeted)
	}
}
