package domain

import "testing"

func TestStanceRecommendable(t *testing.T) {
	for _, s := range []Stance{StanceAffected, StanceNotAffected, StanceMitigated} {
		if !s.Recommendable() {
			t.Errorf("stance %q should be recommendable", s)
		}
	}
	// Human/process stances (and any unknown value) are never recommendable.
	for _, s := range []Stance{"under_investigation", "accepted_risk", "deferred", "bogus"} {
		if Stance(s).Recommendable() {
			t.Errorf("stance %q must not be recommendable", s)
		}
	}
}

func TestCapabilityRef(t *testing.T) {
	c := Capability{ID: "recommend_position", Version: "v1"}
	if got := c.Ref(); got != "recommend_position@v1" {
		t.Errorf("Ref() = %q, want recommend_position@v1", got)
	}
}

func TestRegistryLookup(t *testing.T) {
	r := NewRegistry(
		Capability{ID: "a", Version: "v1"},
		Capability{ID: "b", Version: "v2"},
	)
	if c, ok := r.Lookup("a"); !ok || c.Version != "v1" {
		t.Errorf("Lookup(a) = %+v, %v; want v1, true", c, ok)
	}
	if _, ok := r.Lookup("missing"); ok {
		t.Error("Lookup(missing) should return ok=false")
	}
}

func TestRegistryDuplicateIDOverwrites(t *testing.T) {
	r := NewRegistry(
		Capability{ID: "a", Version: "v1"},
		Capability{ID: "a", Version: "v2"},
	)
	if c, _ := r.Lookup("a"); c.Version != "v2" {
		t.Errorf("duplicate id should keep the last; got version %q", c.Version)
	}
}

func TestRecommendPositionV1(t *testing.T) {
	c := RecommendPositionV1()
	if c.ID != "recommend_position" || c.Version != "v1" {
		t.Fatalf("unexpected id/version: %s@%s", c.ID, c.Version)
	}
	if len(c.Plan) != 1 || c.Plan[0].Engine != EngineLLM || c.Plan[0].Prompt != "recommend_position" {
		t.Errorf("Δ1 plan must be a single LLM step, got %+v", c.Plan)
	}
	if len(c.Needs) != 2 || c.Needs[0] != NeedFinding || c.Needs[1] != NeedFaultline {
		t.Errorf("grounding needs = %v, want [finding faultline]", c.Needs)
	}
	if c.OutputSchema == "" {
		t.Error("capability must carry an output schema")
	}
	for _, s := range c.AllowedStances {
		if !s.Recommendable() {
			t.Errorf("AllowedStances must be recommendable, got %q", s)
		}
	}
	if !c.Routing.LocalOnly || c.Routing.Privacy != PrivacyInternal {
		t.Errorf("Δ1 routing must be local-only/internal, got %+v", c.Routing)
	}
}

func TestDefaultRegistry(t *testing.T) {
	r := DefaultRegistry()
	if _, ok := r.Lookup("recommend_position"); !ok {
		t.Error("DefaultRegistry must contain recommend_position")
	}
}

func TestRegistryAll(t *testing.T) {
	r := NewRegistry(Capability{ID: "a"}, Capability{ID: "b"})
	if len(r.All()) != 2 {
		t.Errorf("All() returned %d capabilities, want 2", len(r.All()))
	}
}
