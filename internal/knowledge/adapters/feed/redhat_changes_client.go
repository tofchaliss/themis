package feed

import (
	"context"
	"encoding/csv"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/kernel/value"
)

// defaultRedHatChangesURL is Red Hat's per-CVE VEX change log: one CSV row per VEX document,
// `"<year>/cve-<id>.json","RFC3339 timestamp"`. Verified live 2026-08-27 (~3.6 MB) — the rows
// are keyed by exactly the CVE ids the enrichment sweep iterates, which is what makes it usable
// as the D10 change signal (the advisory-level changes.csv is not: its rows are advisory files).
const defaultRedHatChangesURL = "https://security.access.redhat.com/data/csaf/v2/vex/changes.csv"

// RedHatChangesClient fetches the VEX changes.csv and reduces it to "which CVEs changed since
// t" — the app.RedHatChangeSignal for the D10 sweep gate. Every failure mode answers ok=false,
// which the sweep treats as "no signal, run full": a broken CSV can only cost requests, never
// freshness.
type RedHatChangesClient struct {
	url  string
	http *http.Client
}

// NewRedHatChangesClient builds the client over the given CSV URL ("" → Red Hat's public VEX
// changes.csv) and HTTP client (nil → http.DefaultClient).
func NewRedHatChangesClient(url string, httpClient *http.Client) *RedHatChangesClient {
	if strings.TrimSpace(url) == "" {
		url = defaultRedHatChangesURL
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &RedHatChangesClient{url: url, http: httpClient}
}

// ChangedSince returns the canonical CVE ids modified after since. ok=false on any fetch or
// whole-file parse failure — including a body that yields not a single valid row, which is a
// malformed file wearing a 200, not an empty change window.
func (c *RedHatChangesClient) ChangedSince(ctx context.Context, since time.Time) (map[string]struct{}, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, false
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	reader := csv.NewReader(resp.Body)
	reader.FieldsPerRecord = -1 // tolerate ragged rows; each row is validated below
	changed := map[string]struct{}{}
	validRows := 0
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, false // a CSV-level error means the file shape changed under us
		}
		if len(row) < 2 {
			continue
		}
		ts, err := time.Parse(time.RFC3339, strings.TrimSpace(row[1]))
		if err != nil {
			continue
		}
		validRows++
		if !ts.After(since) {
			continue
		}
		// "2026/cve-2026-21441.json" → "cve-2026-21441" → canonical "CVE-2026-21441".
		name := strings.TrimSuffix(path.Base(strings.TrimSpace(row[0])), ".json")
		cve, err := value.NewCVEID(name)
		if err != nil {
			continue
		}
		changed[cve.String()] = struct{}{}
	}
	if validRows == 0 {
		return nil, false
	}
	return changed, true
}
