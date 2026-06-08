package store

import (
	"context"
	"testing"

	"github.com/themis-project/themis/internal/domain"
)

func TestStaticVulnerabilityFetcher(t *testing.T) {
	fetcher := StaticVulnerabilityFetcher{Records: []domain.VulnerabilityRecord{
		{CVEID: "CVE-1", Ecosystem: "npm", PackageName: "lodash", AffectedVersions: []string{"1.0.0"}},
	}}
	out, err := fetcher.FetchForComponent(context.Background(), domain.CanonicalComponent{
		Ecosystem: "npm", Name: "lodash", Version: "1.0.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].CVEID != "CVE-1" {
		t.Fatalf("records = %+v", out)
	}
}

func TestEncodeDecodeIngestionPayload(t *testing.T) {
	record := domain.IngestionRecord{
		ID:             "id-1",
		JobType:        domain.JobTypeIngestSBOM,
		Status:         domain.IngestionStatusCorrelating,
		IdempotencyKey: "key-1",
		ScanID:         "scan-1",
		StageDetail:    "detail",
	}
	payload, err := encodeIngestionPayload(record)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeIngestionRecord("id-1", string(domain.JobTypeIngestSBOM), "running", payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Status != domain.IngestionStatusCorrelating || decoded.ScanID != "scan-1" {
		t.Fatalf("decoded = %+v", decoded)
	}
}

func TestErrorMessageForStatus(t *testing.T) {
	msg := errorMessageForStatus(domain.IngestionStatusRejected, "bad")
	if msg == nil || *msg != "bad" {
		t.Fatal("expected error message pointer")
	}
	if errorMessageForStatus(domain.IngestionStatusNotified, "ok") != nil {
		t.Fatal("expected nil message")
	}
}
