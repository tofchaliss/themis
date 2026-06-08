package api

import (
	"encoding/json"
	"net/http"
)

const problemContentType = "application/problem+json"

// ProblemDetail is an RFC 7807 error response.
type ProblemDetail struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// WriteProblem writes an RFC 7807 response.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	w.Header().Set("Content-Type", problemContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(ProblemDetail{
		Type:     problemType(status),
		Title:    title,
		Status:   status,
		Detail:   detail,
		Instance: r.URL.Path,
	})
}

func problemType(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "https://themis.dev/problems/unauthorized"
	case http.StatusForbidden:
		return "https://themis.dev/problems/forbidden"
	case http.StatusNotFound:
		return "https://themis.dev/problems/not-found"
	case http.StatusRequestEntityTooLarge:
		return "https://themis.dev/problems/payload-too-large"
	case http.StatusUnprocessableEntity:
		return "https://themis.dev/problems/unprocessable-entity"
	case http.StatusMethodNotAllowed:
		return "https://themis.dev/problems/method-not-allowed"
	default:
		return "https://themis.dev/problems/error"
	}
}

// WriteJSON writes a JSON response.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
