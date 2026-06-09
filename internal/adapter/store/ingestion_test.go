package store

import (
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestNewPostgresStoreConstructors(t *testing.T) {
	if repo := NewPostgresIngestionRepository(nil); repo == nil {
		t.Fatal("expected ingestion repository")
	}
	if store := NewPostgresSBOMStore(nil); store == nil {
		t.Fatal("expected sbom store")
	}
	if store := NewPostgresComponentStore(nil); store == nil {
		t.Fatal("expected component store")
	}
	if catalog := NewPostgresVulnerabilityCatalog(nil); catalog == nil {
		t.Fatal("expected vulnerability catalog")
	}
	if repo := NewPostgresCorrelationRepository(nil); repo == nil {
		t.Fatal("expected correlation repository")
	}
	if repo := NewPostgresRiskContextRepository(nil); repo == nil {
		t.Fatal("expected risk context repository")
	}
}

func TestVersionMatches(t *testing.T) {
	if !domain.VersionMatches(nil, "1.0.0") {
		t.Fatal("empty affected versions should match")
	}
	if !domain.VersionMatches([]string{"1.0.0"}, "1.0.0") {
		t.Fatal("expected exact match")
	}
	if domain.VersionMatches([]string{"2.0.0"}, "1.0.0") {
		t.Fatal("expected no match")
	}
}

func TestMapSeverityHelpers(t *testing.T) {
	if mapSeverityToPriority("critical") != "critical" {
		t.Fatal("priority mismatch")
	}
	if mapSeverityToScore("high") != 70 {
		t.Fatal("score mismatch")
	}
	if mapSeverityToPriority("low") != "low" {
		t.Fatal("expected low priority")
	}
	if mapSeverityToScore("critical") != 90 {
		t.Fatal("expected critical score")
	}
	if mapSeverityToScore("medium") != 50 {
		t.Fatal("expected medium score")
	}
	if mapSeverityToScore("low") != 30 {
		t.Fatal("expected low score")
	}
	if mapSeverityToScore("unknown") != 40 {
		t.Fatal("expected default score")
	}
}

func TestMapPipelineStatusesExtended(t *testing.T) {
	if mapPipelineToJobStatus(domain.IngestionStatusRejected) != "cancelled" {
		t.Fatal("expected cancelled")
	}
	if mapJobToPipelineStatus("failed") != domain.IngestionStatusFailed {
		t.Fatal("expected failed")
	}
	if mapJobToPipelineStatus("cancelled") != domain.IngestionStatusRejected {
		t.Fatal("expected rejected")
	}
	if mapJobToPipelineStatus("running") != domain.IngestionStatusReceived {
		t.Fatal("expected received")
	}
	if mapJobToPipelineStatus("completed") != domain.IngestionStatusCompleted {
		t.Fatal("expected completed")
	}
	if mapPipelineToJobStatus(domain.IngestionStatusReceived) != "running" {
		t.Fatal("expected running job status")
	}
}
