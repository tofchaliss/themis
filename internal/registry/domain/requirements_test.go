package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/registry/domain"
)

func TestParseRequirement(t *testing.T) {
	for in, want := range map[string]domain.Requirement{"": "X", " h ": "H", "M": "M", "l": "L", "x": "X"} {
		if got, err := domain.ParseRequirement(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	if _, err := domain.ParseRequirement("Z"); !errors.Is(err, domain.ErrInvalidRequirement) {
		t.Errorf("Z: %v", err)
	}
}

func TestNewRequirementRecord(t *testing.T) {
	at := time.Date(2024, 1, 1, 12, 0, 0, 0, time.FixedZone("x", 3600))
	r, err := domain.NewRequirementRecord(domain.TagRelease, "rel-1", "h", "", "L", " public API ", " ops ", "ci", at)
	if err != nil {
		t.Fatal(err)
	}
	if r.Requirements != (domain.Requirements{CR: "H", IR: "X", AR: "L"}) || r.Reason != "public API" || r.Actor != "ops" ||
		r.Via != "ci" || r.At.Location() != time.UTC {
		t.Errorf("record: %+v", r)
	}
	for name, args := range map[string][7]string{
		"level":  {"customer", "id", "H", "H", "H", "why", "who"},
		"value":  {"release", "id", "Q", "H", "H", "why", "who"},
		"id":     {"release", " ", "H", "H", "H", "why", "who"},
		"reason": {"release", "id", "H", "H", "H", " ", "who"},
		"actor":  {"release", "id", "H", "H", "H", "why", ""},
	} {
		if _, err := domain.NewRequirementRecord(domain.RequirementLevel(args[0]), args[1], args[2], args[3], args[4], args[5], args[6], "", at); !errors.Is(err, domain.ErrInvalidRequirement) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestResolveRequirementsPerMetric(t *testing.T) {
	rec := func(level domain.RequirementLevel, cr, ir, ar string) *domain.RequirementRecord {
		r, err := domain.NewRequirementRecord(level, "id", cr, ir, ar, "why", "who", "", time.Unix(0, 0))
		if err != nil {
			t.Fatal(err)
		}
		return &r
	}
	got := domain.ResolveRequirements(rec(domain.TagRelease, "H", "X", "X"), nil, rec(domain.TagProduct, "L", "M", "X"))
	want := domain.ResolvedRequirements{
		CR: domain.ResolvedRequirement{Value: "H", Level: domain.TagRelease},
		IR: domain.ResolvedRequirement{Value: "M", Level: domain.TagProduct},
		AR: domain.ResolvedRequirement{Value: "X", Level: domain.LevelDefault},
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if none := domain.ResolveRequirements(nil, nil, nil); none.CR.Value != "X" || none.CR.Level != domain.LevelDefault {
		t.Errorf("none: %+v", none)
	}
}
