package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/themis-project/themis/internal/adapter/api/gen"
	"github.com/themis-project/themis/internal/domain"
)

func (h *Handler) UploadSBOM(w http.ResponseWriter, r *http.Request, params gen.UploadSBOMParams) {
	ctx := r.Context()
	principal, ok := AuthFromContext(ctx)
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	_ = principal

	var req gen.SBOMUploadRequest
	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "multipart/form-data") {
		if err := r.ParseMultipartForm(h.deps.MaxUpload); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				WriteProblem(w, r, http.StatusRequestEntityTooLarge, "Payload Too Large", "upload exceeds configured limit")
				return
			}
			WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "invalid multipart upload")
			return
		}
		file, _, err := r.FormFile("document")
		if err != nil {
			WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "document file is required")
			return
		}
		defer func() { _ = file.Close() }()
		raw, err := io.ReadAll(file)
		if err != nil {
			WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "unable to read document")
			return
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "document must be valid JSON")
			return
		}
		req.Document = doc
		req.Format = gen.SBOMUploadRequestFormat(r.FormValue("format"))
		if v := r.FormValue("spec_version"); v != "" {
			req.SpecVersion = &v
		}
		if v := r.FormValue("image_digest"); v != "" {
			req.ImageDigest = &v
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				WriteProblem(w, r, http.StatusRequestEntityTooLarge, "Payload Too Large", "upload exceeds configured limit")
				return
			}
			WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "invalid JSON body")
			return
		}
	}

	raw, err := rawDocumentFromMap(req.Document)
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "document is required")
		return
	}

	input, err := h.buildSBOMInput(req, raw, params.IdempotencyKey)
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return
	}

	if resp, status, ok := h.acceptIngestion(ctx, w, r, input, params.IdempotencyKey); ok {
		WriteJSON(w, status, resp)
		return
	}
}

func (h *Handler) UploadVEX(w http.ResponseWriter, r *http.Request, params gen.UploadVEXParams) {
	ctx := r.Context()
	if _, ok := AuthFromContext(ctx); !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	var req gen.VEXUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "invalid JSON body")
		return
	}
	raw, err := rawDocumentFromMap(req.Document)
	if err != nil || req.SbomChecksum == "" {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "document and sbom_checksum are required")
		return
	}
	specVersion := ""
	if req.SpecVersion != nil {
		specVersion = *req.SpecVersion
	}
	supplier := ""
	if req.SupplierIdentity != nil {
		supplier = *req.SupplierIdentity
	}
	input := domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind:             domain.ArtifactKindVEX,
			Format:           string(req.Format),
			SpecVersion:      specVersion,
			RawDocument:      raw,
			SBOMChecksum:     req.SbomChecksum,
			SupplierIdentity: supplier,
			Actor:            "api",
		},
		TrustPolicy: h.trustPolicy(),
	}
	if params.IdempotencyKey != nil {
		input.IdempotencyKey = string(*params.IdempotencyKey)
	}
	if resp, status, ok := h.acceptIngestion(ctx, w, r, input, params.IdempotencyKey); ok {
		WriteJSON(w, status, resp)
	}
}

func (h *Handler) WebhookScan(w http.ResponseWriter, r *http.Request) {
	ctx, endWebhook := domain.StartStage(r.Context(), domain.StageWebhookReceipt)
	defer endWebhook()
	var req gen.WebhookScanRequest
	body, err := io.ReadAll(r.Body)
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "invalid body")
		return
	}
	if err := json.Unmarshal(body, &req); err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "invalid JSON body")
		return
	}
	raw, err := rawDocumentFromMap(req.Document)
	if err != nil || req.ImageDigest == "" {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "document and image_digest are required")
		return
	}
	specVersion := ""
	if req.SpecVersion != nil {
		specVersion = *req.SpecVersion
	}
	input := domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind:        domain.ArtifactKindSBOM,
			Format:      string(req.Format),
			SpecVersion: specVersion,
			RawDocument: raw,
			ImageDigest: req.ImageDigest,
			Actor:       "webhook",
		},
		TrustPolicy: h.trustPolicy(),
	}
	if req.ArtifactId != nil {
		input.ArtifactID = req.ArtifactId.String()
	}
	if req.ProjectId != nil {
		input.ProjectID = req.ProjectId.String()
	}
	if req.CiJobId != nil {
		input.CIJobID = *req.CiJobId
	}
	if req.CiPipelineUrl != nil {
		input.CIPipelineURL = *req.CiPipelineUrl
	}
	if resp, status, ok := h.acceptIngestion(ctx, w, r, input, nil); ok {
		WriteJSON(w, status, resp)
	}
}

func (h *Handler) GetIngestion(w http.ResponseWriter, r *http.Request, id gen.IngestionID) {
	ctx := r.Context()
	if _, ok := AuthFromContext(ctx); !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "missing authentication")
		return
	}
	record, err := h.deps.Jobs.Get(ctx, id.String())
	if err != nil {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "ingestion not found")
		return
	}
	status := gen.IngestionStatus{
		IngestionId: parseUUID(record.ID),
		Status:      string(record.Status),
		StageDetail: ptrString(record.StageDetail),
		StartedAt:   ptrTime(record.CreatedAt),
		UpdatedAt:   ptrTime(record.CreatedAt),
	}
	if record.ScanID != "" {
		scanID := parseUUID(record.ScanID)
		status.ScanId = &scanID
	}
	WriteJSON(w, http.StatusOK, status)
}

func (h *Handler) buildSBOMInput(req gen.SBOMUploadRequest, raw []byte, idempotency *gen.IdempotencyKey) (domain.IngestionInput, error) {
	if req.Format == "" {
		return domain.IngestionInput{}, errors.New("format is required")
	}
	specVersion := ""
	if req.SpecVersion != nil {
		specVersion = *req.SpecVersion
	}
	input := domain.IngestionInput{
		RawArtifact: domain.RawArtifact{
			Kind:        domain.ArtifactKindSBOM,
			Format:      string(req.Format),
			SpecVersion: specVersion,
			RawDocument: raw,
			Actor:       "api",
		},
		TrustPolicy: h.trustPolicy(),
	}
	if idempotency != nil {
		input.IdempotencyKey = string(*idempotency)
	}
	if req.ArtifactId != nil {
		input.ArtifactID = req.ArtifactId.String()
	}
	if req.ProjectId != nil {
		input.ProjectID = req.ProjectId.String()
	}
	if req.ImageDigest != nil {
		input.ImageDigest = *req.ImageDigest
	}
	if req.CiJobId != nil {
		input.CIJobID = *req.CiJobId
	}
	if req.CiPipelineUrl != nil {
		input.CIPipelineURL = *req.CiPipelineUrl
	}
	if req.SupplierIdentity != nil {
		input.SupplierIdentity = *req.SupplierIdentity
	}
	return input, nil
}

func (h *Handler) acceptIngestion(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	input domain.IngestionInput,
	idempotency *gen.IdempotencyKey,
) (gen.IngestionAccepted, int, bool) {
	if input.IdempotencyKey != "" {
		if existing, found, err := h.deps.Jobs.FindByIdempotencyKey(ctx, input.IdempotencyKey); err == nil && found {
			return gen.IngestionAccepted{
				IngestionId: parseUUID(existing.ID),
				Status:      string(existing.Status),
				Duplicate:   ptrBool(true),
			}, http.StatusOK, true
		}
	}
	jobType := domain.JobTypeIngestSBOM
	if input.Kind == domain.ArtifactKindVEX {
		jobType = domain.JobTypeIngestVEX
	}
	if h.deps.Dispatcher == nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", "ingestion dispatcher unavailable")
		return gen.IngestionAccepted{}, 0, false
	}
	id, err := h.deps.Dispatcher.EnqueueIngestion(ctx, input, jobType)
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Unprocessable Entity", err.Error())
		return gen.IngestionAccepted{}, 0, false
	}
	return gen.IngestionAccepted{
		IngestionId: parseUUID(id),
		Status:      string(domain.IngestionStatusReceived),
	}, http.StatusAccepted, true
}

func ptrBool(v bool) *bool { return &v }
