package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

// WriteProblem writes a layman-friendly error envelope.
// Legacy title/detail arguments are mapped to catalogue codes when possible.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	code := legacyErrorCode(status, title, detail)
	WriteCatalogError(w, status, code)
}

func legacyErrorCode(status int, title, detail string) ErrorCode {
	detail = strings.TrimSpace(detail)
	upper := strings.ToUpper(detail)
	switch {
	case strings.Contains(upper, string(CodeSBOMNotFound)):
		return CodeSBOMNotFound
	case strings.Contains(upper, string(CodeProductNotFound)):
		return CodeProductNotFound
	case strings.Contains(upper, string(CodeImageNotFound)):
		return CodeImageNotFound
	case strings.Contains(upper, string(CodeCustomerNotFound)):
		return CodeCustomerNotFound
	case strings.Contains(upper, string(CodeCannotDeleteLatestSBOM)):
		return CodeCannotDeleteLatestSBOM
	case strings.Contains(upper, string(CodeDuplicateMicroservice)):
		return CodeDuplicateMicroservice
	case strings.Contains(upper, string(CodeDuplicateCustomer)):
		return CodeDuplicateCustomer
	case strings.Contains(upper, string(CodeInvalidSBOMFormat)):
		return CodeInvalidSBOMFormat
	case strings.Contains(upper, string(CodeInvalidRequest)):
		return CodeInvalidRequest
	case strings.Contains(upper, string(CodeMissingAPIKey)):
		return CodeMissingAPIKey
	case strings.Contains(upper, string(CodeInvalidAPIKey)):
		return CodeInvalidAPIKey
	}
	switch status {
	case http.StatusUnauthorized:
		if strings.Contains(strings.ToLower(detail), "missing") {
			return CodeMissingAPIKey
		}
		return CodeInvalidAPIKey
	case http.StatusBadRequest:
		return CodeInvalidRequest
	case http.StatusNotFound:
		if strings.Contains(strings.ToLower(detail), "product") {
			return CodeProductNotFound
		}
		if strings.Contains(strings.ToLower(detail), "sbom") || strings.Contains(strings.ToLower(detail), "scan") {
			return CodeSBOMNotFound
		}
		return CodeProductNotFound
	case http.StatusConflict:
		return CodeCannotDeleteLatestSBOM
	case http.StatusUnprocessableEntity:
		if strings.Contains(strings.ToLower(detail), "sbom") || strings.Contains(strings.ToLower(title), "unprocessable") {
			return CodeInvalidSBOMFormat
		}
		return CodeInvalidRequest
	default:
		return CodeInternalError
	}
}

// WriteJSON writes a JSON response.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
