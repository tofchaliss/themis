package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler serves the Prometheus scrape endpoint.
func Handler() http.Handler {
	Register()
	return promhttp.Handler()
}
