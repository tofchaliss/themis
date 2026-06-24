package correlation

import (
	"context"
	"errors"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

type stubSource struct {
	name    string
	records []domain.VulnerabilityRecord
	err     error
	emitted *bool
}

func (s *stubSource) Name() string { return s.name }

func (s *stubSource) FetchForComponent(context.Context, domain.CanonicalComponent) ([]domain.VulnerabilityRecord, error) {
	return s.records, s.err
}

func (s *stubSource) EmitCorrelationSummary() {
	if s.emitted != nil {
		*s.emitted = true
	}
}

func TestCorrelatorTagsAndSorts(t *testing.T) {
	src := &stubSource{name: domain.FindingSourceOSV, records: []domain.VulnerabilityRecord{
		{CVEID: "CVE-2", Severity: "high"},
		{CVEID: "CVE-1", Severity: "low"},
		{CVEID: ""}, // skipped: no CVE id
	}}
	c := NewCorrelator(nil, src)
	out, err := c.FetchForComponent(context.Background(), domain.CanonicalComponent{Ecosystem: "npm"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 records, got %+v", out)
	}
	if out[0].CVEID != "CVE-1" || out[1].CVEID != "CVE-2" {
		t.Fatalf("not sorted by cve id: %+v", out)
	}
	if out[0].Source != domain.FindingSourceOSV {
		t.Fatalf("source not tagged: %q", out[0].Source)
	}
}

func TestCorrelatorMergesByPrecedence(t *testing.T) {
	nvd := &stubSource{name: domain.FindingSourceNVD, records: []domain.VulnerabilityRecord{
		{CVEID: "CVE-1", Severity: "medium", Source: domain.FindingSourceNVD},
	}}
	osv := &stubSource{name: domain.FindingSourceOSV, records: []domain.VulnerabilityRecord{
		{CVEID: "CVE-1", Severity: "high", Source: domain.FindingSourceOSV},
	}}

	// Order must not matter: OSV outranks NVD for npm either way.
	for _, order := range [][]domain.CorrelationSource{{nvd, osv}, {osv, nvd}} {
		c := NewCorrelator(nil, order...)
		out, err := c.FetchForComponent(context.Background(), domain.CanonicalComponent{Ecosystem: "npm"})
		if err != nil {
			t.Fatal(err)
		}
		if len(out) != 1 || out[0].Source != domain.FindingSourceOSV || out[0].Severity != "high" {
			t.Fatalf("expected osv to win, got %+v", out)
		}
	}
}

func TestCorrelatorEmptyAndErrorAndEmit(t *testing.T) {
	c := NewCorrelator(nil, &stubSource{name: "s"})
	if out, err := c.FetchForComponent(context.Background(), domain.CanonicalComponent{}); err != nil || out != nil {
		t.Fatalf("empty = %+v, %v", out, err)
	}

	failing := &stubSource{name: "bad", err: errors.New("boom")}
	if _, err := NewCorrelator(nil, failing).FetchForComponent(context.Background(), domain.CanonicalComponent{}); err == nil {
		t.Fatal("expected source error to propagate")
	}

	emitted := false
	NewCorrelator(nil, &stubSource{name: "s", emitted: &emitted}).EmitCorrelationSummary()
	if !emitted {
		t.Fatal("EmitCorrelationSummary not propagated to source")
	}
}
