package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/themis-project/themis/internal/adapter/assetgraph"
	"github.com/themis-project/themis/internal/domain"
)

// ErrorCode is a stable API error identifier.
type ErrorCode string

const (
	CodeSBOMNotFound           ErrorCode = "SBOM_NOT_FOUND"
	CodeProductNotFound        ErrorCode = "PRODUCT_NOT_FOUND"
	CodeImageNotFound          ErrorCode = "IMAGE_NOT_FOUND"
	CodeCustomerNotFound       ErrorCode = "CUSTOMER_NOT_FOUND"
	CodeCannotDeleteLatestSBOM ErrorCode = "CANNOT_DELETE_LATEST_SBOM"
	CodeDuplicateMicroservice  ErrorCode = "DUPLICATE_MICROSERVICE"
	CodeDuplicateCustomer      ErrorCode = "DUPLICATE_CUSTOMER"
	CodeInvalidSBOMFormat      ErrorCode = "INVALID_SBOM_FORMAT"
	CodeInvalidRequest         ErrorCode = "INVALID_REQUEST"
	CodeMissingAPIKey          ErrorCode = "MISSING_API_KEY"
	CodeInvalidAPIKey          ErrorCode = "INVALID_API_KEY"
	CodeInternalError          ErrorCode = "INTERNAL_ERROR"
)

type catalogEntry struct {
	Message string
	Hint    string
}

var errorCatalogue = map[ErrorCode]catalogEntry{
	CodeSBOMNotFound: {
		Message: "That SBOM could not be found. It may have been removed already.",
		Hint:    "Use GET /api/v1/sboms to list SBOMs that are still available.",
	},
	CodeProductNotFound: {
		Message: "We couldn't find a product with that ID.",
		Hint:    "Use GET /api/v1/products to list registered products.",
	},
	CodeImageNotFound: {
		Message: "That image hasn't been registered yet.",
		Hint:    "Register the image first, then upload the SBOM for it.",
	},
	CodeCustomerNotFound: {
		Message: "We couldn't find a customer with that ID.",
		Hint:    "Use GET /api/v1/customers or create the customer before linking a deployment.",
	},
	CodeCannotDeleteLatestSBOM: {
		Message: "This is the latest SBOM for its image, so it can't be deleted without confirmation.",
		Hint:    "Upload a newer SBOM first, or retry with ?force=true if you really want to remove it.",
	},
	CodeDuplicateMicroservice: {
		Message: "A microservice with that name already exists for this product.",
		Hint:    "Choose a different name or update the existing microservice.",
	},
	CodeDuplicateCustomer: {
		Message: "A customer with that email already exists.",
		Hint:    "Use the existing customer record or provide a different contact email.",
	},
	CodeInvalidSBOMFormat: {
		Message: "The SBOM couldn't be read because the format is invalid or incomplete.",
		Hint:    "Check the file is CycloneDX JSON, SPDX, or Trivy JSON and includes required fields.",
	},
	CodeInvalidRequest: {
		Message: "The request was missing a required field or had an invalid value.",
		Hint:    "Review the API documentation and fix the highlighted parameters.",
	},
	CodeMissingAPIKey: {
		Message: "An API key is required to access this endpoint.",
		Hint:    "Add your API key in the X-API-Key request header.",
	},
	CodeInvalidAPIKey: {
		Message: "The API key you provided is not valid or has been revoked.",
		Hint:    "Check the key value or create a new key with the themis CLI.",
	},
	CodeInternalError: {
		Message: "Something went wrong on our end. The problem has been logged.",
		Hint:    "If this keeps happening, check the Themis server logs for details.",
	},
}

// APIErrorEnvelope is the standard error response body.
type APIErrorEnvelope struct {
	Error APIErrorBody `json:"error"`
}

// APIErrorBody holds the three user-facing error fields.
type APIErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint"`
}

// WriteCatalogError writes a catalogue-backed error envelope.
func WriteCatalogError(w http.ResponseWriter, status int, code ErrorCode) {
	entry, ok := errorCatalogue[code]
	if !ok {
		code = CodeInternalError
		entry = errorCatalogue[code]
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(APIErrorEnvelope{
		Error: APIErrorBody{
			Code:    string(code),
			Message: entry.Message,
			Hint:    entry.Hint,
		},
	})
}

// MapError maps a domain or infrastructure error to a catalogue code and HTTP status.
func MapError(err error) (ErrorCode, int) {
	if err == nil {
		return CodeInternalError, http.StatusInternalServerError
	}
	switch {
	case errors.Is(err, domain.ErrSBOMNotFound):
		return CodeSBOMNotFound, http.StatusNotFound
	case errors.Is(err, domain.ErrProductNotFound), errors.Is(err, domain.ErrProductVersionNotFound):
		return CodeProductNotFound, http.StatusNotFound
	case errors.Is(err, assetgraph.ErrProductNotFound):
		return CodeProductNotFound, http.StatusNotFound
	case errors.Is(err, assetgraph.ErrCustomerNotFound):
		return CodeCustomerNotFound, http.StatusNotFound
	case errors.Is(err, assetgraph.ErrMicroserviceNotFound):
		return CodeProductNotFound, http.StatusNotFound
	case errors.Is(err, domain.ErrCannotDeleteLatestSBOM):
		return CodeCannotDeleteLatestSBOM, http.StatusConflict
	case errors.Is(err, assetgraph.ErrDuplicateMicroservice):
		return CodeDuplicateMicroservice, http.StatusConflict
	case errors.Is(err, assetgraph.ErrDuplicateCustomer):
		return CodeDuplicateCustomer, http.StatusConflict
	case isImageNotFound(err):
		return CodeImageNotFound, http.StatusNotFound
	case isInvalidSBOM(err):
		return CodeInvalidSBOMFormat, http.StatusUnprocessableEntity
	case isInvalidRequest(err):
		return CodeInvalidRequest, http.StatusBadRequest
	case isDatabaseError(err):
		return CodeInternalError, http.StatusInternalServerError
	default:
		return CodeInternalError, http.StatusInternalServerError
	}
}

// RespondError writes the mapped catalogue error for err.
func RespondError(w http.ResponseWriter, _ *http.Request, err error) {
	code, status := MapError(err)
	WriteCatalogError(w, status, code)
}

func isImageNotFound(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "image not found")
}

func isInvalidSBOM(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "sbom") && (strings.Contains(msg, "invalid") || strings.Contains(msg, "parse") || strings.Contains(msg, "format"))
}

func isInvalidRequest(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "invalid cursor") || strings.Contains(msg, "required")
}

func isDatabaseError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr)
}
