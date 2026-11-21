package knowledge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/themis-project/themis/internal/governance/app"
	"github.com/themis-project/themis/internal/governance/domain"
)

// ratingsResponse mirrors Knowledge's SourceRatings wire shape (GET /faultlines/{id}/ratings).
type ratingsResponse struct {
	Observations []struct {
		ID          string `json:"id"`
		DocumentRef string `json:"document_ref"`
		Revision    string `json:"revision"`
		Fingerprint string `json:"fingerprint"`
		UpdatedAt   *struct {
			Instant        *time.Time `json:"instant"`
			Interpretation string     `json:"interpretation"`
		} `json:"updated_at"`
	} `json:"observations"`
	Ratings []struct {
		ID               string `json:"id"`
		ObservationID    string `json:"observation_id"`
		Source           string `json:"source"`
		Feed             string `json:"feed"`
		Assessor         string `json:"assessor"`
		AssessorKey      string `json:"assessor_key"`
		Publisher        string `json:"publisher"`
		NVDType          string `json:"nvd_type"`
		Version          string `json:"cvss_version"`
		Vector           string `json:"vector"`
		AssertedContext  string `json:"asserted_context"`
		InheritedContext string `json:"inherited_context"`
		Status           string `json:"status"`
		Validation       *struct {
			Result string `json:"result"`
			Reason string `json:"reason"`
		} `json:"validation"`
		Identity *struct {
			Key string `json:"key"`
		} `json:"identity"`
	} `json:"ratings"`
}

var _ app.SourceRatingsReader = (*Client)(nil)

// SourceRatings reads a Faultline's source ratings and maps each publication to a selection
// candidate. The observation supplies the canonical publication key's revision (or its content
// fingerprint) and the source time, which counts as missing when it could not be parsed.
func (c *Client) SourceRatings(ctx context.Context, faultlineID string) ([]domain.ScoreCandidate, error) {
	u := c.baseURL + "/api/v1/faultlines/" + url.PathEscape(faultlineID) + "/ratings"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("knowledge: ratings %s: status %d", faultlineID, resp.StatusCode)
	}
	var body ratingsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	type obsInfo struct {
		documentRef, revision string
		at                    time.Time
	}
	obs := map[string]obsInfo{}
	for _, o := range body.Observations {
		info := obsInfo{documentRef: o.DocumentRef, revision: o.Revision}
		if info.revision == "" {
			info.revision = o.Fingerprint
		}
		if o.UpdatedAt != nil && o.UpdatedAt.Instant != nil && o.UpdatedAt.Interpretation != "unparseable" {
			info.at = o.UpdatedAt.Instant.UTC()
		}
		obs[o.ID] = info
	}
	out := make([]domain.ScoreCandidate, 0, len(body.Ratings))
	for _, r := range body.Ratings {
		o := obs[r.ObservationID]
		cand := domain.ScoreCandidate{
			RatingID: r.ID, Source: r.Source, DocumentRef: o.documentRef, Revision: o.revision,
			Feed: r.Feed, Publisher: r.Publisher, Assessor: r.AssessorKey, NVDType: r.NVDType,
			Version: r.Version, Vector: r.Vector, AssertedContext: r.AssertedContext, InheritedContext: r.InheritedContext,
			Active: r.Status == "active", SourceUpdatedAt: o.at,
		}
		if cand.Assessor == "" {
			cand.Assessor = strings.ToLower(strings.TrimSpace(r.Assessor))
		}
		if r.Validation != nil {
			cand.Validation, cand.ValidationReason = r.Validation.Result, r.Validation.Reason
		}
		if r.Identity != nil {
			cand.IdentityKey = r.Identity.Key
		}
		out = append(out, cand)
	}
	return out, nil
}
