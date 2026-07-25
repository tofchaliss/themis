package engine_test

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/intelligence/adapters/engine"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/intelligence/domain"
)

func TestRuleEngineKind(t *testing.T) {
	if got := engine.NewRuleEngine().Kind(); got != domain.EngineRule {
		t.Fatalf("Kind() = %q, want %q", got, domain.EngineRule)
	}
}

func TestRuleEngineDecides(t *testing.T) {
	e := engine.NewRuleEngine(domain.VersionRangeRule{})
	in := app.ExecInput{Context: domain.AssembledContext{
		Finding:   domain.FindingView{Components: []string{"pkg:pypi/foo@5.0"}, CVE: "CVE-1"},
		Faultline: domain.FaultlineView{AffectedRanges: []string{">= 1.0, < 3.0"}, CVE: "CVE-1"},
	}}
	res, err := e.Execute(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision == nil {
		t.Fatal("expected a decision for a provably out-of-range component")
	}
	if res.Decision.Stance != domain.StanceNotAffected {
		t.Errorf("stance = %q, want not_affected", res.Decision.Stance)
	}
	if res.Raw != "" || res.Provider != "" || res.TokensUsed != 0 {
		t.Errorf("rule engine must carry no provider/model/token provenance, got %+v", res)
	}
}

func TestRuleEngineDefers(t *testing.T) {
	e := engine.NewRuleEngine(domain.VersionRangeRule{})
	in := app.ExecInput{Context: domain.AssembledContext{
		Finding:   domain.FindingView{Components: []string{"pkg:pypi/foo@2.0"}, CVE: "CVE-1"},
		Faultline: domain.FaultlineView{AffectedRanges: []string{">= 1.0, < 3.0"}, CVE: "CVE-1"},
	}}
	res, err := e.Execute(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != nil {
		t.Fatalf("expected defer (in-range component), got decision %+v", res.Decision)
	}
}
