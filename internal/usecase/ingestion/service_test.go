package ingestion_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/ingestion"
)

func TestPipelineIngestSBOMSuccess(t *testing.T) {
	jobs := &memoryJobs{}
	pipeline := newTestPipeline(jobs)
	input := baseSBOMInput()
	input.IdempotencyKey = "key-1"

	result, err := pipeline.IngestSBOM(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusNotified || result.ScanID == "" {
		t.Fatalf("result = %+v", result)
	}
	if len(jobs.updates) < 5 {
		t.Fatalf("updates = %+v", jobs.updates)
	}
}

func TestPipelineIdempotencyFastPath(t *testing.T) {
	jobs := &memoryJobs{
		byKey: map[string]domain.IngestionRecord{
			"dup-key": {ID: "ing-1", Status: domain.IngestionStatusNotified, ScanID: "scan-1"},
		},
	}
	pipeline := newTestPipeline(jobs)
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	input := baseSBOMInput()
	input.IdempotencyKey = "dup-key"
	result, err = pipeline.IngestSBOM(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Duplicate || result.ScanID != "scan-1" {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineTrustRejection(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Trust = fixedTrust{accepted: false, message: "trust failed"}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusRejected || result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineTrustDuplicate(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Trust = fixedTrust{accepted: true, duplicateID: "existing-scan"}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if result.ScanID != "existing-scan" {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineParserRejection(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Parser = fixedParser{accepted: false, message: "invalid schema", status: domain.ParseStatusRejected}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusRejected {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineParserRetryableFailure(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Parser = fixedParser{accepted: false, message: "timeout", status: domain.ParseStatusFailed}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusFailed || !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineStoreRetryableFailure(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.SBOM = failingSBOMStore{err: fmt.Errorf("%w: db down", domain.ErrRetryable)}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineFetcherEmitsCorrelationSummary(t *testing.T) {
	fetcher := &summaryFetcher{}
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Fetcher = fetcher
	if _, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput()); err != nil {
		t.Fatal(err)
	}
	if !fetcher.emitted {
		t.Fatal("expected EmitCorrelationSummary to be called")
	}
}

func TestPipelineCorrelationNoMatches(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Catalog = memoryCatalog{matches: nil}
	pipeline.Fetcher = staticFetcher{}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusNotified {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineCorrelationWithMatches(t *testing.T) {
	jobs := &memoryJobs{}
	pipeline := newTestPipeline(jobs)
	pipeline.Catalog = memoryCatalog{matches: []domain.VulnerabilityRecord{
		{ID: "vuln-1", CVEID: "CVE-1", Severity: "high", AffectedVersions: []string{"1.0.0"}},
	}}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusNotified {
		t.Fatalf("result = %+v", result)
	}
	if len(jobs.correlateFindings) == 0 {
		t.Fatal("expected findings")
	}
}

func TestPipelineCatalogFindError(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Catalog = memoryCatalog{err: errors.New("catalog down")}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineFetcherError(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Fetcher = failingFetcher{err: errors.New("nvd down")}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineComponentsError(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Components = failingComponents{err: errors.New("components failed")}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineEnrichError(t *testing.T) {
	enrichmentSvc := &memoryEnrichment{applyErr: errors.New("enrich failed")}
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Enrichment = enrichmentSvc
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineIdempotencyLookupError(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{findKeyErr: errors.New("lookup failed")})
	input := baseSBOMInput()
	input.IdempotencyKey = "bad"
	_, err := pipeline.IngestSBOM(context.Background(), input)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPipelineCorrelateUpsertError(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Catalog = upsertFailCatalog{}
	pipeline.Fetcher = staticFetcher{}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineCorrelateCreateFindingError(t *testing.T) {
	jobs := &memoryJobs{createFindingErr: errors.New("create finding failed")}
	pipeline := newTestPipeline(jobs)
	pipeline.Catalog = memoryCatalog{matches: []domain.VulnerabilityRecord{{ID: "vuln-1", CVEID: "CVE-1", Severity: "high", AffectedVersions: []string{"1.0.0"}}}}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineEnrichCreateRiskError(t *testing.T) {
	enrichmentSvc := &memoryEnrichment{applyErr: errors.New("risk failed")}
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Enrichment = enrichmentSvc
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineFetcherUpsertError(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Catalog = upsertFailCatalog{}
	pipeline.Fetcher = staticFetcher{}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineIngestVEXTrustReject(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Trust = fixedTrust{accepted: false, message: "vex trust failed"}
	input := baseSBOMInput()
	input.Kind = domain.ArtifactKindVEX
	input.Format = "openvex"
	result, err := pipeline.IngestVEX(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusRejected {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineIngestVEXTrustDuplicate(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Trust = fixedTrust{accepted: true, duplicateID: "existing-vex"}
	input := baseSBOMInput()
	input.Kind = domain.ArtifactKindVEX
	input.Format = "openvex"
	result, err := pipeline.IngestVEX(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.ScanID != "existing-vex" {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineIngestVEXSaveError(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.SBOM = failingSBOMStore{err: fmt.Errorf("%w: save vex", domain.ErrRetryable)}
	input := baseSBOMInput()
	input.Kind = domain.ArtifactKindVEX
	input.Format = "openvex"
	input.SBOMChecksum = "sha256:sbom"
	result, err := pipeline.IngestVEX(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineSBOMSaveDuplicate(t *testing.T) {
	// SaveSBOM reports an idempotent re-submission (D12): the scan already exists, so
	// the pipeline returns it without re-correlating or appending a phantom scan.
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.SBOM = duplicateSBOMStore{scanID: "dup-scan"}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusNotified || result.ScanID != "dup-scan" {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineIngestVEXEnrichmentUnavailable(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Enrichment = nil
	input := baseSBOMInput()
	input.Kind = domain.ArtifactKindVEX
	input.Format = "openvex"
	input.SBOMChecksum = "sha256:sbom"
	result, err := pipeline.IngestVEX(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusRejected || result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineSkipUnknownComponentPURL(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Components = memoryComponents{versions: map[string]string{}}
	pipeline.Catalog = memoryCatalog{matches: []domain.VulnerabilityRecord{{ID: "vuln-1", CVEID: "CVE-1"}}}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusNotified {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineTransitionErrors(t *testing.T) {
	t.Run("completed transition", func(t *testing.T) {
		pipeline := newTestPipeline(&memoryJobs{updateErr: errors.New("update failed"), updateFailOn: 4})
		_, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
		if err == nil || !domain.IsRetryable(err) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("notified transition", func(t *testing.T) {
		pipeline := newTestPipeline(&memoryJobs{updateErr: errors.New("update failed"), updateFailOn: 5})
		_, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
		if err == nil || !domain.IsRetryable(err) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("correlating transition", func(t *testing.T) {
		pipeline := newTestPipeline(&memoryJobs{updateErr: errors.New("update failed"), updateFailOn: 2})
		result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
		if err != nil {
			t.Fatal(err)
		}
		if !result.Retryable {
			t.Fatalf("result = %+v", result)
		}
	})
	t.Run("enriching sbom transition", func(t *testing.T) {
		pipeline := newTestPipeline(&memoryJobs{updateErr: errors.New("update failed"), updateFailOn: 3})
		result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
		if err != nil {
			t.Fatal(err)
		}
		if !result.Retryable {
			t.Fatalf("result = %+v", result)
		}
	})
	t.Run("vex validating transition", func(t *testing.T) {
		pipeline := newTestPipeline(&memoryJobs{updateErr: errors.New("update failed"), updateFailOn: 1})
		input := baseSBOMInput()
		input.Kind = domain.ArtifactKindVEX
		input.Format = "openvex"
		input.SBOMChecksum = "sha256:sbom"
		result, err := pipeline.IngestVEX(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Retryable {
			t.Fatalf("result = %+v", result)
		}
	})
	t.Run("vex enriching transition", func(t *testing.T) {
		pipeline := newTestPipeline(&memoryJobs{updateErr: errors.New("update failed"), updateFailOn: 2})
		input := baseSBOMInput()
		input.Kind = domain.ArtifactKindVEX
		input.Format = "openvex"
		input.SBOMChecksum = "sha256:sbom"
		result, err := pipeline.IngestVEX(context.Background(), input)
		if err != nil {
			t.Fatal(err)
		}
		if !result.Retryable {
			t.Fatalf("result = %+v", result)
		}
	})
}

func TestPipelineCorrelateMatchWithoutID(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	// FixVersions present exercises the CR-3 source_fixed_version provenance branch.
	pipeline.Catalog = memoryCatalog{matches: []domain.VulnerabilityRecord{{CVEID: "CVE-1", Severity: "high", AffectedVersions: []string{"1.0.0"}, FixVersions: []string{"2.0.0"}}}}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusNotified {
		t.Fatalf("result = %+v", result)
	}
}

func TestNewIngestionIDFallback(t *testing.T) {
	original := ingestion.RandReadHook
	ingestion.RandReadHook = func([]byte) (int, error) { return 0, errors.New("rand failed") }
	t.Cleanup(func() { ingestion.RandReadHook = original })

	jobs := &memoryJobs{}
	pipeline := newTestPipeline(jobs)
	input := baseSBOMInput()
	input.IngestionID = ""
	result, err := pipeline.IngestSBOM(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.IngestionID != "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("IngestionID = %q", result.IngestionID)
	}
}

func TestPipelineIngestVEXEnrichError(t *testing.T) {
	enrichmentSvc := &memoryEnrichment{reenrichErr: errors.New("reenrich failed")}
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Enrichment = enrichmentSvc
	input := baseSBOMInput()
	input.Kind = domain.ArtifactKindVEX
	input.Format = "openvex"
	input.SBOMChecksum = "sha256:sbom"
	result, err := pipeline.IngestVEX(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineCorrelateUpsertInLoopError(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Catalog = upsertFailCatalogWithMatch{}
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

type upsertFailCatalogWithMatch struct{}

func (upsertFailCatalogWithMatch) FindMatches(context.Context, string, string, string) ([]domain.VulnerabilityRecord, error) {
	return []domain.VulnerabilityRecord{{CVEID: "CVE-1", Severity: "high", AffectedVersions: []string{"1.0.0"}}}, nil
}

func (upsertFailCatalogWithMatch) Upsert(context.Context, domain.VulnerabilityRecord) (string, error) {
	return "", errors.New("upsert failed")
}

func TestPipelineNotifyRetryableFailure(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Notify = failingNotifier{err: errors.New("smtp down")}
	_, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err == nil || !domain.IsRetryable(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestPipelineIngestVEXSuccess(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	input := baseSBOMInput()
	input.Kind = domain.ArtifactKindVEX
	input.Format = "openvex"
	input.SBOMChecksum = "sha256:sbom"
	result, err := pipeline.IngestVEX(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusNotified {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineIngestVEXMissingSBOM(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.SBOM = failingSBOMStore{findErr: errors.New("missing sbom")}
	input := baseSBOMInput()
	input.Kind = domain.ArtifactKindVEX
	input.SBOMChecksum = "missing"
	result, err := pipeline.IngestVEX(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusRejected {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineJobsCreateError(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{createErr: errors.New("create failed")})
	_, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPipelineJobsUpdateErrorOnTransition(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{updateErr: errors.New("update failed")})
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != domain.IngestionStatusFailed || !result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineAlreadyProcessed(t *testing.T) {
	jobs := &memoryJobs{
		records: map[string]domain.IngestionRecord{
			"ing-done": {ID: "ing-done", Status: domain.IngestionStatusCompleted, ScanID: "scan-1"},
		},
	}
	pipeline := newTestPipeline(jobs)
	input := baseSBOMInput()
	input.IngestionID = "ing-done"
	result, err := pipeline.IngestSBOM(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Duplicate || result.IngestionID != "ing-done" || result.ScanID != "scan-1" {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineBackfillIdempotencyKey(t *testing.T) {
	jobs := &memoryJobs{
		records: map[string]domain.IngestionRecord{
			"ing-1": {ID: "ing-1", Status: domain.IngestionStatusReceived},
		},
	}
	pipeline := newTestPipeline(jobs)
	input := baseSBOMInput()
	input.IngestionID = "ing-1"
	input.IdempotencyKey = "new-key"
	result, err := pipeline.IngestSBOM(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusNotified {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineAlreadyProcessedRejected(t *testing.T) {
	jobs := &memoryJobs{
		records: map[string]domain.IngestionRecord{
			"ing-rejected": {ID: "ing-rejected", Status: domain.IngestionStatusRejected, ScanID: "scan-1"},
		},
	}
	pipeline := newTestPipeline(jobs)
	input := baseSBOMInput()
	input.IngestionID = "ing-rejected"
	result, err := pipeline.IngestSBOM(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Duplicate || result.Status != domain.IngestionStatusRejected {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineAlreadyProcessedNotified(t *testing.T) {
	jobs := &memoryJobs{
		records: map[string]domain.IngestionRecord{
			"ing-notified": {ID: "ing-notified", Status: domain.IngestionStatusNotified, ScanID: "scan-1"},
		},
	}
	pipeline := newTestPipeline(jobs)
	input := baseSBOMInput()
	input.IngestionID = "ing-notified"
	result, err := pipeline.IngestSBOM(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Duplicate || result.Status != domain.IngestionStatusNotified {
		t.Fatalf("result = %+v", result)
	}
}

func TestPipelineBackfillIdempotencyKeyUpdateError(t *testing.T) {
	jobs := &memoryJobs{
		records: map[string]domain.IngestionRecord{
			"ing-1": {ID: "ing-1", Status: domain.IngestionStatusReceived},
		},
		updateErr:    errors.New("update failed"),
		updateFailOn: 1,
	}
	pipeline := newTestPipeline(jobs)
	input := baseSBOMInput()
	input.IngestionID = "ing-1"
	input.IdempotencyKey = "new-key"
	_, err := pipeline.IngestSBOM(context.Background(), input)
	if err == nil {
		t.Fatal("expected update error")
	}
}

func TestPipelineNilEnrichment(t *testing.T) {
	pipeline := newTestPipeline(&memoryJobs{})
	pipeline.Enrichment = nil
	result, err := pipeline.IngestSBOM(context.Background(), baseSBOMInput())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.IngestionStatusRejected || result.Retryable {
		t.Fatalf("result = %+v", result)
	}
}

func newTestPipeline(jobs *memoryJobs) *ingestion.Pipeline {
	enrichmentSvc := &memoryEnrichment{}
	return ingestion.NewPipeline(ingestion.Pipeline{
		Jobs:       jobs,
		Trust:      fixedTrust{accepted: true},
		Parser:     fixedParser{accepted: true},
		SBOM:       memorySBOMStore{id: "scan-1"},
		Components: memoryComponents{versions: map[string]string{"pkg:npm/lodash@1.0.0": "cv-1"}},
		Catalog:    memoryCatalog{},
		Fetcher:    staticFetcher{},
		Correlate:  jobs,
		Enrichment: enrichmentSvc,
		Notify:     memoryNotifier{},
	})
}

type memoryEnrichment struct {
	applyErr    error
	reenrichErr error
}

func (m *memoryEnrichment) ApplyVEX(context.Context, string) error { return m.applyErr }
func (m *memoryEnrichment) ReenrichVEX(context.Context, string) error {
	return m.reenrichErr
}

func baseSBOMInput() domain.IngestionInput {
	return domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind:        domain.ArtifactKindSBOM,
			Format:      domain.SBOMFormatCycloneDX,
			SpecVersion: "1.4",
			RawDocument: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","components":[{"name":"lodash","version":"1.0.0","purl":"pkg:npm/lodash@1.0.0"}]}`),
			ImageDigest: "sha256:abc",
		},
		TrustPolicy: domain.TrustPolicyStandard,
		ArtifactID:  "image-1",
	}
}

type memoryJobs struct {
	byKey             map[string]domain.IngestionRecord
	records           map[string]domain.IngestionRecord
	updates           []domain.IngestionStatus
	findings          []domain.ComponentFinding
	correlateFindings []domain.ComponentFinding
	createErr         error
	updateErr         error
	updateFailOn      int
	updateCalls       int
	findKeyErr        error
	listErr           error
	createFindingErr  error
	createRiskErr     error
}

func (m *memoryJobs) FindByIdempotencyKey(_ context.Context, key string) (domain.IngestionRecord, bool, error) {
	if m.findKeyErr != nil {
		return domain.IngestionRecord{}, false, m.findKeyErr
	}
	if m.byKey == nil {
		return domain.IngestionRecord{}, false, nil
	}
	record, ok := m.byKey[key]
	return record, ok, nil
}

func (m *memoryJobs) Create(_ context.Context, record domain.IngestionRecord) error {
	if m.createErr != nil {
		return m.createErr
	}
	if m.records == nil {
		m.records = map[string]domain.IngestionRecord{}
	}
	m.records[record.ID] = record
	return nil
}

func (m *memoryJobs) UpdateStatus(_ context.Context, id string, status domain.IngestionStatus, detail, scanID string) error {
	m.updateCalls++
	if m.updateErr != nil && (m.updateFailOn == 0 || m.updateCalls == m.updateFailOn) {
		return m.updateErr
	}
	m.updates = append(m.updates, status)
	if m.records == nil {
		m.records = map[string]domain.IngestionRecord{}
	}
	record := m.records[id]
	record.Status = status
	record.StageDetail = detail
	if scanID != "" {
		record.ScanID = scanID
	}
	m.records[id] = record
	if status == domain.IngestionStatusEnriching && scanID != "" {
		m.correlateFindings = []domain.ComponentFinding{{ID: "finding-1", Severity: "high"}}
	}
	return nil
}

func (m *memoryJobs) Get(_ context.Context, id string) (domain.IngestionRecord, error) {
	record, ok := m.records[id]
	if !ok {
		return domain.IngestionRecord{}, fmt.Errorf("missing %s", id)
	}
	return record, nil
}

func (m *memoryJobs) CreateFinding(_ context.Context, _ domain.CreateFindingInput) (string, error) {
	if m.createFindingErr != nil {
		return "", m.createFindingErr
	}
	m.findings = append(m.findings, domain.ComponentFinding{ID: "finding-1", Severity: "high"})
	return "finding-1", nil
}

func (m *memoryJobs) ListFindings(_ context.Context, _ string) ([]domain.ComponentFinding, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	if len(m.correlateFindings) == 0 {
		return m.findings, nil
	}
	return m.correlateFindings, nil
}

type fixedTrust struct {
	accepted    bool
	message     string
	duplicateID string
}

func (f fixedTrust) Evaluate(_ context.Context, _ domain.RawArtifact, _ domain.TrustPolicy) domain.GateOutcome {
	if !f.accepted {
		return domain.GateOutcome{Accepted: false, Message: f.message}
	}
	return domain.GateOutcome{Accepted: true, DuplicateID: f.duplicateID, Result: domain.TrustResult{Status: domain.TrustStatusVerified, ChecksumSHA256: "sha256:doc"}}
}

type fixedParser struct {
	accepted bool
	message  string
	status   domain.ParseStatus
}

func (f fixedParser) Parse(_ context.Context, _, _ string, _ []byte) domain.ParseOutcome {
	if !f.accepted {
		return domain.ParseOutcome{Accepted: false, Message: f.message, Status: f.status}
	}
	return domain.ParseOutcome{
		Accepted: true,
		Status:   domain.ParseStatusAccepted,
		SBOM: domain.CanonicalSBOM{
			Components: []domain.CanonicalComponent{{PURL: "pkg:npm/lodash@1.0.0", Name: "lodash", Version: "1.0.0", Ecosystem: "npm"}},
		},
	}
}

type memorySBOMStore struct {
	id string
}

func (s memorySBOMStore) SaveSBOM(_ context.Context, _ domain.SaveSBOMInput) (domain.SaveSBOMResult, error) {
	return domain.SaveSBOMResult{SBOMID: s.id, ScanReportID: s.id}, nil
}

func (s memorySBOMStore) SaveVEX(_ context.Context, _ domain.SaveVEXInput) (string, error) {
	return "vex-1", nil
}

func (s memorySBOMStore) FindArtifactBySBOMChecksum(_ context.Context, _ string) (string, error) {
	return s.id, nil
}

type duplicateSBOMStore struct {
	scanID string
}

func (s duplicateSBOMStore) SaveSBOM(_ context.Context, _ domain.SaveSBOMInput) (domain.SaveSBOMResult, error) {
	return domain.SaveSBOMResult{SBOMID: s.scanID, ScanReportID: s.scanID, Duplicate: true}, nil
}

func (s duplicateSBOMStore) SaveVEX(_ context.Context, _ domain.SaveVEXInput) (string, error) {
	return "vex-1", nil
}

func (s duplicateSBOMStore) FindArtifactBySBOMChecksum(_ context.Context, _ string) (string, error) {
	return s.scanID, nil
}

type failingSBOMStore struct {
	err     error
	findErr error
}

func (s failingSBOMStore) SaveSBOM(_ context.Context, _ domain.SaveSBOMInput) (domain.SaveSBOMResult, error) {
	return domain.SaveSBOMResult{}, s.err
}

func (s failingSBOMStore) SaveVEX(_ context.Context, _ domain.SaveVEXInput) (string, error) {
	return "", s.err
}

func (s failingSBOMStore) FindArtifactBySBOMChecksum(_ context.Context, _ string) (string, error) {
	return "", s.findErr
}

type memoryComponents struct {
	versions map[string]string
}

func (m memoryComponents) UpsertFromCanonical(_ context.Context, _ string, sbom domain.CanonicalSBOM) (map[string]string, error) {
	if m.versions != nil {
		return m.versions, nil
	}
	out := map[string]string{}
	for _, component := range sbom.Components {
		out[component.PURL] = "cv-" + component.Name
	}
	return out, nil
}

type upsertFailCatalog struct{}

func (upsertFailCatalog) FindMatches(context.Context, string, string, string) ([]domain.VulnerabilityRecord, error) {
	return nil, nil
}

func (upsertFailCatalog) Upsert(context.Context, domain.VulnerabilityRecord) (string, error) {
	return "", errors.New("upsert failed")
}

type memoryCatalog struct {
	matches []domain.VulnerabilityRecord
	err     error
}

func (c memoryCatalog) FindMatches(_ context.Context, _, _, _ string) ([]domain.VulnerabilityRecord, error) {
	return c.matches, c.err
}

func (c memoryCatalog) Upsert(_ context.Context, record domain.VulnerabilityRecord) (string, error) {
	if record.ID != "" {
		return record.ID, nil
	}
	return "vuln-new", nil
}

type staticFetcher struct{}

type summaryFetcher struct {
	staticFetcher
	emitted bool
}

func (s *summaryFetcher) EmitCorrelationSummary() {
	s.emitted = true
}

func (staticFetcher) FetchForComponent(_ context.Context, component domain.CanonicalComponent) ([]domain.VulnerabilityRecord, error) {
	return []domain.VulnerabilityRecord{
		{CVEID: "CVE-STATIC", Severity: "medium", Ecosystem: component.Ecosystem, PackageName: component.Name, AffectedVersions: []string{component.Version}},
	}, nil
}

type memoryNotifier struct{}

func (memoryNotifier) NotifyComplete(_ context.Context, _ domain.IngestionResult) error {
	return nil
}

type failingNotifier struct {
	err error
}

func (f failingNotifier) NotifyComplete(_ context.Context, _ domain.IngestionResult) error {
	return f.err
}

type failingFetcher struct {
	err error
}

func (f failingFetcher) FetchForComponent(context.Context, domain.CanonicalComponent) ([]domain.VulnerabilityRecord, error) {
	return nil, f.err
}

type failingComponents struct {
	err error
}

func (f failingComponents) UpsertFromCanonical(context.Context, string, domain.CanonicalSBOM) (map[string]string, error) {
	return nil, f.err
}
