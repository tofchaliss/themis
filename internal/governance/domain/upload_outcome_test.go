package domain_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/themis-project/themis/internal/governance/domain"
)

func set(purls ...string) map[string]bool {
	m := map[string]bool{}
	for _, p := range purls {
		m[p] = true
	}
	return m
}

func TestClassifyUpload_FourBuckets(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	prev := &domain.UploadBaseline{PURLs: set("pkg:a@1", "pkg:b@1", "pkg:d@1", "pkg:r@1"), FiledAt: t0}
	cur := set("pkg:a@1", "pkg:c@1", "pkg:e@1", "pkg:r@1")
	findings := []domain.UploadFinding{
		{ID: "f-a", CVE: "CVE-A", Stage: domain.StageIdentified, CreatedAt: t0.Add(-time.Hour), PURLs: []string{"pkg:a@1"}},         // unchanged
		{ID: "f-b", CVE: "CVE-B", Stage: domain.StagePositionEstablished, CreatedAt: t0.Add(-time.Hour), PURLs: []string{"pkg:b@1"}}, // gone
		{CVE: "CVE-C", Stage: domain.StageIdentified, CreatedAt: t0.Add(time.Hour), PURLs: []string{"pkg:c@1"}},           // new
		{CVE: "CVE-E", Stage: domain.StageIdentified, CreatedAt: t0.Add(-48 * time.Hour), PURLs: []string{"pkg:e@1"}},     // reappeared
		{CVE: "CVE-D", Stage: domain.StageResolved, CreatedAt: t0.Add(-time.Hour), PURLs: []string{"pkg:d@1"}},            // resolved and gone: not judged
		{CVE: "CVE-R", Stage: domain.StageArchived, CreatedAt: t0.Add(-time.Hour), PURLs: []string{"pkg:r@1"}},            // archived and present: not judged
		{CVE: "CVE-S", Stage: domain.StageIdentified, CreatedAt: t0.Add(time.Hour), PURLs: []string{"pkg:scanner-only@1"}}, // in neither SBOM
		{CVE: "CVE-N", Stage: domain.StageIdentified, CreatedAt: t0.Add(time.Hour)},                                        // no components
	}
	got := domain.ClassifyUpload(findings, cur, prev)
	if got.New != 1 || got.Reappeared != 1 || got.NoLongerPresent != 1 || got.Unchanged != 1 || got.NotJudged != 4 || !got.HasBaseline {
		t.Fatalf("buckets = %+v", got)
	}
	if fmt.Sprint(got.PresentIDs, got.GoneIDs) != "[f-a] [f-b]" {
		t.Fatalf("ids = %v %v", got.PresentIDs, got.GoneIDs)
	}
	if fmt.Sprint(got.NewCVEs, got.ReappearedCVEs, got.GoneCVEs) != "[CVE-C] [CVE-E] [CVE-B]" {
		t.Fatalf("lists = %v %v %v", got.NewCVEs, got.ReappearedCVEs, got.GoneCVEs)
	}
}

// A Release's first SBOM has no baseline: everything present is new, nothing can be gone.
func TestClassifyUpload_FirstSBOM(t *testing.T) {
	got := domain.ClassifyUpload([]domain.UploadFinding{
		{CVE: "CVE-1", PURLs: []string{"pkg:a@1"}}, {CVE: "CVE-2", PURLs: []string{"pkg:x@1"}},
	}, set("pkg:a@1"), nil)
	if got.New != 1 || got.NotJudged != 1 || got.HasBaseline || got.NoLongerPresent != 0 {
		t.Fatalf("first = %+v", got)
	}
}

// Counts stay complete; the lists are sorted and capped.
func TestClassifyUpload_ListsCapped(t *testing.T) {
	var fs []domain.UploadFinding
	for i := 0; i < domain.UploadOutcomeCVELimit+5; i++ {
		fs = append(fs, domain.UploadFinding{CVE: fmt.Sprintf("CVE-%03d", 999-i), PURLs: []string{"pkg:a@1"}})
	}
	got := domain.ClassifyUpload(fs, set("pkg:a@1"), nil)
	if got.New != domain.UploadOutcomeCVELimit+5 || len(got.NewCVEs) != domain.UploadOutcomeCVELimit || got.NewCVEs[0] != "CVE-945" {
		t.Fatalf("cap = %d %d %s", got.New, len(got.NewCVEs), got.NewCVEs[0])
	}
}
