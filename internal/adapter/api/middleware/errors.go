package middleware

import (
	"encoding/json"
	"net/http"
)

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Hint    string `json:"hint"`
	} `json:"error"`
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	_ = r
	var body errorBody
	switch status {
	case http.StatusUnauthorized:
		if detail == "missing X-API-Key header" {
			body.Error.Code = "MISSING_API_KEY"
			body.Error.Message = "An API key is required to access this endpoint."
			body.Error.Hint = "Add your API key in the X-API-Key request header."
		} else {
			body.Error.Code = "INVALID_API_KEY"
			body.Error.Message = "The API key you provided is not valid or has been revoked."
			body.Error.Hint = "Check the key value or create a new key with the themis CLI."
		}
	default:
		body.Error.Code = "INTERNAL_ERROR"
		body.Error.Message = "Something went wrong on our end. The problem has been logged."
		body.Error.Hint = "If this keeps happening, check the Themis server logs for details."
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
