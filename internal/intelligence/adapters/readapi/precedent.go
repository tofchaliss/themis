package readapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/themis-project/themis/internal/intelligence/domain"
)

// PrecedentClient reads our own past Enterprise Positions on the same CVE from OTHER
// releases (Δ2 richer grounding, C6). It composes Governance's EXISTING read endpoints —
// blast-radius (releases for a Faultline) then find-by-key (whose FindingView carries the
// current position) — so it needs no new Governance surface. It implements
// app.PrecedentReader. A per-release read that 404s is simply skipped.
type PrecedentClient struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

// NewPrecedentClient builds a client against the Governance base URL.
func NewPrecedentClient(baseURL string, hc *http.Client) *PrecedentClient {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &PrecedentClient{baseURL: baseURL, http: hc}
}

// WithAPIKey makes every precedent read carry `X-API-Key` (EDR-SECURITY-01 F1). An empty key
// leaves the reads unauthenticated — the auth-off development case. A READ-ONLY key is enough.
//
// Without it, every precedent read on an auth-enabled Governance node answers 401 and the
// exact-CVE fallback degrades to "no precedent" — which is indistinguishable from an estate
// that has genuinely never decided this CVE, and that is the one thing a grounding seam must
// never confuse.
func (c *PrecedentClient) WithAPIKey(apiKey string) *PrecedentClient {
	c.apiKey = strings.TrimSpace(apiKey)
	return c
}

type wireCurrentPosition struct {
	Stance             string `json:"stance"`
	Rationale          string `json:"rationale"`
	ActorKind          string `json:"actor_kind"` // human | ai | policy — PositionView already carries it
	AcceptedProposalID string `json:"accepted_proposal_id"`
}

type wireProposal struct {
	ID           string `json:"id"`
	ProposerKind string `json:"proposer_kind"`
}

// systemProposerKind is Governance's own automation raising a proposal (the version-range
// verdict, a vendor not_affected statement). Mirrors governance domain.ActorSystem.
const systemProposerKind = "system"

// RulePositionActorKind is the verdict kind of a Position that rests on a system proposal
// (the version-range verdict, an upstream withdrawal) — whether a policy accepted it or a
// human confirmed it unchanged (AI-RF-4b, 2026-10-14: 311 provable range verdicts accepted by
// hand through `range-accept-provable.sh` survived the first prune because the decider was a
// person, and still surfaced as "similar past decisions"). Such a Position is arithmetic about
// ONE CVE's range and carries no judgement to transfer, so it is never precedent (AI-RF-4,
// 2026-10-14: five of them at 0.99 nudged a human toward not_affected on an affected stdlib
// Finding). The kind this client reports is therefore the VERDICT's, not the clicker's.
const RulePositionActorKind = "policy"

type wireFindingWithPosition struct {
	CurrentPosition *wireCurrentPosition `json:"current_position"`
	Proposals       []wireProposal       `json:"proposals"`
}

// verdictKind is who the Position's judgement belongs to: the decider, except that a decision
// accepting a system proposal is the rule's whoever accepted it.
func verdictKind(pos wireCurrentPosition, proposals []wireProposal) string {
	if pos.ActorKind == RulePositionActorKind {
		return RulePositionActorKind
	}
	for _, p := range proposals {
		if p.ID == pos.AcceptedProposalID && p.ProposerKind == systemProposerKind {
			return RulePositionActorKind
		}
	}
	return pos.ActorKind
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
		if ok && pos.ActorKind != RulePositionActorKind {
			out = append(out, domain.PrecedentPosition{ReleaseID: rel, Stance: pos.Stance, Rationale: pos.Rationale, ExactCVE: true})
		}
	}
	return out, nil
}

// CurrentPosition returns the current Enterprise Position (stance + rationale) for a
// (release, faultline) — used by Δ3a index population to label a precedent embedding. It reuses
// the same find-by-key endpoint as GetPrecedents. found=false when that release has no Position
// yet (or the finding is absent).
func (c *PrecedentClient) CurrentPosition(ctx context.Context, release, faultline string) (stance, rationale, actorKind string, found bool, err error) {
	pos, ok, err := c.currentPosition(ctx, release, faultline)
	if err != nil || !ok {
		return "", "", "", false, err
	}
	return pos.Stance, pos.Rationale, pos.ActorKind, true, nil
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
	pos := *wf.CurrentPosition
	pos.ActorKind = verdictKind(pos, wf.Proposals)
	return pos, true, nil
}

var errNotFound = fmt.Errorf("readapi: not found")

func (c *PrecedentClient) getJSON(ctx context.Context, u string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
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
		return fmt.Errorf("governance read API: status %d%s",
			resp.StatusCode, credentialHint(c.apiKey, resp.StatusCode, "Governance"))
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}
