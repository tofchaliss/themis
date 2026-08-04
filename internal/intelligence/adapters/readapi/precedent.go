package readapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// PrecedentClient reads our own past Enterprise Positions on the same CVE from OTHER
// releases (Δ2 richer grounding, C6). It composes Governance's EXISTING read endpoints —
// blast-radius (releases for a Faultline) then find-by-key (whose FindingView carries the
// current position) — so it needs no new Governance surface. It implements
// app.PrecedentReader. A per-release read that 404s is simply skipped.
type PrecedentClient struct {
	baseURL string
	http    *http.Client
}

// NewPrecedentClient builds a client against the Governance base URL.
func NewPrecedentClient(baseURL string, hc *http.Client) *PrecedentClient {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &PrecedentClient{baseURL: baseURL, http: hc}
}

type wireCurrentPosition struct {
	Stance    string `json:"stance"`
	Rationale string `json:"rationale"`
}

type wireFindingWithPosition struct {
	CurrentPosition *wireCurrentPosition `json:"current_position"`
}

// GetPrecedents returns the current Enterprise Position for the Faultline in every
// affected release except excludeReleaseID (the subject's own release).
func (c *PrecedentClient) GetPrecedents(ctx context.Context, faultlineID, excludeReleaseID string) ([]domain.PrecedentPosition, error) {
	releases, err := c.blastRadius(ctx, faultlineID)
	if err != nil {
		return nil, err
	}
	var out []domain.PrecedentPosition
	for _, rel := range releases {
		if rel == "" || rel == excludeReleaseID {
			continue
		}
		pos, ok, err := c.currentPosition(ctx, rel, faultlineID)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, domain.PrecedentPosition{ReleaseID: rel, Stance: pos.Stance, Rationale: pos.Rationale})
		}
	}
	return out, nil
}

// CurrentPosition returns the current Enterprise Position (stance + rationale) for a
// (release, faultline) — used by Δ3a index population to label a precedent embedding. It reuses
// the same find-by-key endpoint as GetPrecedents. found=false when that release has no Position
// yet (or the finding is absent).
func (c *PrecedentClient) CurrentPosition(ctx context.Context, release, faultline string) (stance, rationale string, found bool, err error) {
	pos, ok, err := c.currentPosition(ctx, release, faultline)
	if err != nil || !ok {
		return "", "", false, err
	}
	return pos.Stance, pos.Rationale, true, nil
}

func (c *PrecedentClient) blastRadius(ctx context.Context, faultlineID string) ([]string, error) {
	u := fmt.Sprintf("%s/api/v1/faultlines/%s/blast-radius", c.baseURL, url.PathEscape(faultlineID))
	var releases []string
	if err := c.getJSON(ctx, u, &releases); err != nil {
		return nil, err
	}
	return releases, nil
}

func (c *PrecedentClient) currentPosition(ctx context.Context, release, faultline string) (wireCurrentPosition, bool, error) {
	u := fmt.Sprintf("%s/api/v1/findings?release=%s&faultline=%s",
		c.baseURL, url.QueryEscape(release), url.QueryEscape(faultline))
	var wf wireFindingWithPosition
	err := c.getJSON(ctx, u, &wf)
	if err == errNotFound {
		return wireCurrentPosition{}, false, nil
	}
	if err != nil {
		return wireCurrentPosition{}, false, err
	}
	if wf.CurrentPosition == nil {
		return wireCurrentPosition{}, false, nil
	}
	return *wf.CurrentPosition, true, nil
}

var errNotFound = fmt.Errorf("readapi: not found")

func (c *PrecedentClient) getJSON(ctx context.Context, u string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("governance read API: status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}
