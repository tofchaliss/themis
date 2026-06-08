package api

import (
	"encoding/json"
	"io"
	"time"

	"github.com/themis-project/themis/internal/domain"
	"github.com/themis-project/themis/internal/usecase/ingestion"
	"github.com/themis-project/themis/internal/usecase/triage"
)

// Dependencies wires handler ports.
type Dependencies struct {
	Ingestion   ingestion.Service
	Jobs        domain.IngestionRepository
	Dispatcher  domain.IngestionAsyncDispatcher
	Catalog     domain.ProductCatalogRepository
	Scans       domain.ScanQueryRepository
	Components  domain.ComponentCatalogRepository
	Watch       domain.CVEWatchFindingRepository
	Notifications domain.NotificationConfigRepository
	Scanners    domain.ScannerConfigRepository
	Triage      triage.Service
	TriageRepo  domain.TriageRepository
	MaxUpload   int64
	TrustPolicy domain.TrustPolicy
}

// Handler implements the generated OpenAPI interface.
type Handler struct {
	deps Dependencies
	now  func() time.Time
}

// NewHandler creates an API handler.
func NewHandler(deps Dependencies) *Handler {
	return &Handler{deps: deps, now: time.Now}
}

func (h *Handler) trustPolicy() domain.TrustPolicy {
	if h.deps.TrustPolicy != "" {
		return h.deps.TrustPolicy
	}
	return domain.TrustPolicyStandard
}

func rawDocumentFromMap(document map[string]any) ([]byte, error) {
	if document == nil {
		return nil, io.EOF
	}
	return json.Marshal(document)
}

func ptrString(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func ptrTime(v time.Time) *time.Time {
	if v.IsZero() {
		return nil
	}
	t := v
	return &t
}
