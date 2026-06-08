package metrics

import "net/http"

// StageSpanMiddleware injects OTel stage span helpers into request context.
func StageSpanMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := InjectStageSpan(r.Context())
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
