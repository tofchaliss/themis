package ingestion

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/enrichment"
)

// Service orchestrates SBOM and VEX ingestion pipelines.
type Service interface {
	IngestSBOM(ctx context.Context, input domain.IngestionInput) (domain.IngestionResult, error)
	IngestVEX(ctx context.Context, input domain.IngestionInput) (domain.IngestionResult, error)
}

// Pipeline coordinates ingestion stage dependencies.
type Pipeline struct {
	Jobs       domain.IngestionRepository
	Trust      domain.TrustGateEvaluator
	Parser     domain.SBOMParserPort
	SBOM       domain.SBOMStore
	Components domain.ComponentStore
	Catalog    domain.VulnerabilityCatalog
	Fetcher    domain.VulnerabilityFetcher
	Correlate  domain.CorrelationRepository
	Enrichment enrichment.Service
	Notify     domain.IngestionNotifier
}

// NewPipeline creates a pipeline with required dependencies.
func NewPipeline(deps Pipeline) *Pipeline {
	return &deps
}

var _ Service = (*Pipeline)(nil)

// IngestSBOM runs the full SBOM ingestion pipeline.
func (p *Pipeline) IngestSBOM(ctx context.Context, input domain.IngestionInput) (domain.IngestionResult, error) {
	return p.run(ctx, input, domain.JobTypeIngestSBOM, p.ingestSBOMStages)
}

// IngestVEX runs the VEX ingestion pipeline.
func (p *Pipeline) IngestVEX(ctx context.Context, input domain.IngestionInput) (domain.IngestionResult, error) {
	input.Kind = domain.ArtifactKindVEX
	return p.run(ctx, input, domain.JobTypeIngestVEX, p.ingestVEXStages)
}

type stageFunc func(context.Context, *domain.IngestionInput, *domain.IngestionRecord) (string, error)

func (p *Pipeline) run(
	ctx context.Context,
	input domain.IngestionInput,
	jobType domain.JobType,
	stages stageFunc,
) (domain.IngestionResult, error) {
	if input.IdempotencyKey != "" {
		if existing, found, err := p.Jobs.FindByIdempotencyKey(ctx, input.IdempotencyKey); err != nil {
			return domain.IngestionResult{}, err
		} else if found {
			return domain.IngestionResult{
				IngestionID: existing.ID,
				ScanID:      existing.ScanID,
				Status:      existing.Status,
				Duplicate:   true,
				Message:     "idempotent replay",
			}, nil
		}
	}

	record := domain.IngestionRecord{
		ID:             input.IngestionID,
		JobType:        jobType,
		Status:         domain.IngestionStatusReceived,
		IdempotencyKey: input.IdempotencyKey,
	}
	if record.ID == "" {
		record.ID = newIngestionID()
	}

	if existing, err := p.Jobs.Get(ctx, record.ID); err == nil {
		if existing.IdempotencyKey == "" && input.IdempotencyKey != "" {
			existing.IdempotencyKey = input.IdempotencyKey
			if err := p.Jobs.UpdateStatus(ctx, existing.ID, existing.Status, existing.StageDetail, existing.ScanID); err != nil {
				return domain.IngestionResult{}, err
			}
		}
		record = existing
		if existing.Status == domain.IngestionStatusNotified ||
			existing.Status == domain.IngestionStatusCompleted ||
			existing.Status == domain.IngestionStatusRejected {
			return domain.IngestionResult{
				IngestionID: existing.ID,
				ScanID:      existing.ScanID,
				Status:      existing.Status,
				Duplicate:   true,
				Message:     "already processed",
			}, nil
		}
	} else if err := p.Jobs.Create(ctx, record); err != nil {
		return domain.IngestionResult{}, err
	}

	scanID, err := stages(ctx, &input, &record)
	if err != nil {
		status := domain.IngestionStatusRejected
		if domain.IsRetryable(err) {
			status = domain.IngestionStatusFailed
		}
		_ = p.Jobs.UpdateStatus(ctx, record.ID, status, err.Error(), scanID)
		return domain.IngestionResult{
			IngestionID: record.ID,
			ScanID:      scanID,
			Status:      status,
			Message:     err.Error(),
			Retryable:   domain.IsRetryable(err),
		}, nil
	}

	if err := p.transition(ctx, record.ID, domain.IngestionStatusCompleted, "completed", scanID); err != nil {
		return domain.IngestionResult{}, err
	}
	if err := p.transition(ctx, record.ID, domain.IngestionStatusNotified, "notified", scanID); err != nil {
		return domain.IngestionResult{}, err
	}
	result := domain.IngestionResult{
		IngestionID: record.ID,
		ScanID:      scanID,
		Status:      domain.IngestionStatusNotified,
		Message:     "completed",
	}
	ctx, endNotify := domain.StartStage(ctx, domain.StageNotify)
	defer endNotify()
	if err := p.Notify.NotifyComplete(ctx, result); err != nil {
		return domain.IngestionResult{}, fmt.Errorf("%w: notify: %v", domain.ErrRetryable, err)
	}
	return result, nil
}

func (p *Pipeline) ingestSBOMStages(ctx context.Context, input *domain.IngestionInput, record *domain.IngestionRecord) (string, error) {
	if err := p.transition(ctx, record.ID, domain.IngestionStatusValidating, "trust gate", ""); err != nil {
		return "", err
	}
	ctx, endTrust := domain.StartStage(ctx, domain.StageTrustGate)
	outcome := p.Trust.Evaluate(ctx, input.RawArtifact, input.TrustPolicy)
	endTrust()
	if !outcome.Accepted {
		return "", stageError(domain.IngestionStatusValidating, fmt.Errorf("%s", outcome.Message), false)
	}
	if outcome.DuplicateID != "" {
		_ = p.Jobs.UpdateStatus(ctx, record.ID, domain.IngestionStatusCompleted, "duplicate artifact", outcome.DuplicateID)
		return outcome.DuplicateID, nil
	}

	if err := p.transition(ctx, record.ID, domain.IngestionStatusCorrelating, "parse and correlate", ""); err != nil {
		return "", err
	}
	ctx, endParse := domain.StartStage(ctx, domain.StageParse)
	parseOutcome := p.Parser.Parse(ctx, input.Format, input.SpecVersion, input.RawDocument)
	endParse()
	if !parseOutcome.Accepted {
		return "", stageError(domain.IngestionStatusCorrelating, fmt.Errorf("%s", parseOutcome.Message), parseOutcome.Status != domain.ParseStatusRejected)
	}

	ctx, endCorrelate := domain.StartStage(ctx, domain.StageCorrelate)
	defer endCorrelate()
	saved, err := p.SBOM.SaveSBOM(ctx, domain.SaveSBOMInput{
		ArtifactID:       input.ArtifactID,
		ImageDigest:      input.ImageDigest,
		SBOMChecksum:     outcome.Result.ChecksumSHA256,
		Format:           input.Format,
		SpecVersion:      input.SpecVersion,
		Scanner:          parseOutcome.SBOM.Format,
		TrustResult:      outcome.Result,
		RawDocument:      input.RawDocument,
		Canonical:        parseOutcome.SBOM,
		CIJobID:          input.CIJobID,
		CIPipelineURL:    input.CIPipelineURL,
		SupplierIdentity: input.SupplierIdentity,
	})
	if err != nil {
		return "", stageError(domain.IngestionStatusCorrelating, err, true)
	}
	scanReportID := saved.ScanReportID
	if saved.Duplicate {
		// Idempotent re-submission (D12): the scan already exists with its findings;
		// do not re-correlate or append a phantom scan.
		return scanReportID, nil
	}

	componentVersions, err := p.Components.UpsertFromCanonical(ctx, saved.SBOMID, parseOutcome.SBOM)
	if err != nil {
		return "", stageError(domain.IngestionStatusCorrelating, err, true)
	}
	if err := p.correlateComponents(ctx, parseOutcome.SBOM, componentVersions, scanReportID); err != nil {
		return "", err
	}

	if err := p.transition(ctx, record.ID, domain.IngestionStatusEnriching, "risk context", scanReportID); err != nil {
		return "", err
	}
	ctx, endEnrich := domain.StartStage(ctx, domain.StageEnrich)
	if p.Enrichment == nil {
		endEnrich()
		return "", stageError(domain.IngestionStatusEnriching, fmt.Errorf("enrichment service unavailable"), false)
	}
	if err := p.Enrichment.ApplyVEX(ctx, input.ArtifactID); err != nil {
		endEnrich()
		return "", stageError(domain.IngestionStatusEnriching, err, true)
	}
	endEnrich()
	return scanReportID, nil
}

func (p *Pipeline) ingestVEXStages(ctx context.Context, input *domain.IngestionInput, record *domain.IngestionRecord) (string, error) {
	if err := p.transition(ctx, record.ID, domain.IngestionStatusValidating, "trust gate", ""); err != nil {
		return "", err
	}
	ctx, endTrust := domain.StartStage(ctx, domain.StageTrustGate)
	outcome := p.Trust.Evaluate(ctx, input.RawArtifact, input.TrustPolicy)
	endTrust()
	if !outcome.Accepted {
		return "", stageError(domain.IngestionStatusValidating, fmt.Errorf("%s", outcome.Message), false)
	}
	if outcome.DuplicateID != "" {
		_ = p.Jobs.UpdateStatus(ctx, record.ID, domain.IngestionStatusCompleted, "duplicate artifact", outcome.DuplicateID)
		return outcome.DuplicateID, nil
	}

	artifactID, err := p.SBOM.FindArtifactBySBOMChecksum(ctx, input.SBOMChecksum)
	if err != nil {
		return "", stageError(domain.IngestionStatusCorrelating, err, false)
	}

	documentID, err := p.SBOM.SaveVEX(ctx, domain.SaveVEXInput{
		ArtifactID:       artifactID,
		SBOMChecksum:     input.SBOMChecksum,
		ChecksumSHA256:   outcome.Result.ChecksumSHA256,
		Format:           input.Format,
		SpecVersion:      input.SpecVersion,
		TrustResult:      outcome.Result,
		RawDocument:      input.RawDocument,
		SupplierIdentity: input.SupplierIdentity,
	})
	if err != nil {
		return "", stageError(domain.IngestionStatusCorrelating, err, true)
	}

	if err := p.transition(ctx, record.ID, domain.IngestionStatusEnriching, "vex re-enrichment", documentID); err != nil {
		return "", err
	}
	ctx, endEnrich := domain.StartStage(ctx, domain.StageEnrich)
	if p.Enrichment == nil {
		endEnrich()
		return "", stageError(domain.IngestionStatusEnriching, fmt.Errorf("enrichment service unavailable"), false)
	}
	if err := p.Enrichment.ReenrichVEX(ctx, documentID); err != nil {
		endEnrich()
		return "", stageError(domain.IngestionStatusEnriching, err, true)
	}
	endEnrich()
	return documentID, nil
}

func (p *Pipeline) correlateComponents(
	ctx context.Context,
	sbom domain.CanonicalSBOM,
	componentVersions map[string]string,
	scanReportID string,
) error {
	for _, component := range sbom.Components {
		componentVersionID, ok := componentVersions[component.PURL]
		if !ok {
			continue
		}
		matches, err := p.localMatches(ctx, component)
		if err != nil {
			return stageError(domain.IngestionStatusCorrelating, err, true)
		}
		versionedPURL := domain.VersionedPURL(component.PURL, component.Version)
		for _, vuln := range matches {
			vulnID := vuln.ID
			if vulnID == "" {
				var upsertErr error
				vulnID, upsertErr = p.Catalog.Upsert(ctx, vuln)
				if upsertErr != nil {
					return stageError(domain.IngestionStatusCorrelating, upsertErr, true)
				}
			}
			fixedVersion := ""
			if len(vuln.FixVersions) > 0 {
				fixedVersion = vuln.FixVersions[0]
			}
			if _, err := p.Correlate.CreateFinding(ctx, domain.CreateFindingInput{
				ComponentVersionID: componentVersionID,
				VulnerabilityID:    vulnID,
				ScanReportID:       scanReportID,
				ComponentPURL:      versionedPURL,
				CVEID:              vuln.CVEID,
				Source:             domain.DefaultFindingSource(vuln.Source),
				SourceSeverity:     vuln.Severity,
				SourceCVSSScore:    vuln.CVSSScore,
				SourceCVSSVector:   vuln.CVSSVector,
				SourceFixedVersion: fixedVersion,
			}); err != nil {
				return stageError(domain.IngestionStatusCorrelating, err, true)
			}
		}
	}
	if reporter, ok := p.Fetcher.(domain.CorrelationSummaryEmitter); ok {
		reporter.EmitCorrelationSummary()
	}
	return nil
}

func (p *Pipeline) localMatches(ctx context.Context, component domain.CanonicalComponent) ([]domain.VulnerabilityRecord, error) {
	matches, err := p.Catalog.FindMatches(ctx, component.Ecosystem, component.Name, component.Version)
	if err != nil {
		return nil, err
	}
	if len(matches) > 0 || p.Fetcher == nil {
		return matches, nil
	}
	fetched, err := p.Fetcher.FetchForComponent(ctx, component)
	if err != nil {
		return nil, err
	}
	for i, record := range fetched {
		id, upsertErr := p.Catalog.Upsert(ctx, record)
		if upsertErr != nil {
			return nil, upsertErr
		}
		fetched[i].ID = id
	}
	return fetched, nil
}

func (p *Pipeline) transition(ctx context.Context, id string, status domain.IngestionStatus, detail, scanID string) error {
	if err := p.Jobs.UpdateStatus(ctx, id, status, detail, scanID); err != nil {
		return fmt.Errorf("%w: update status: %v", domain.ErrRetryable, err)
	}
	return nil
}

func stageError(stage domain.IngestionStatus, err error, retryable bool) error {
	if retryable {
		return fmt.Errorf("%w: %s stage: %v", domain.ErrRetryable, stage, err)
	}
	return fmt.Errorf("%s stage: %w", stage, err)
}

var newIngestionID = func() string {
	buf := make([]byte, 16)
	if _, err := RandReadHook(buf); err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

var randRead = rand.Read

// RandReadHook allows tests to override ingestion ID randomness.
var RandReadHook = randRead
