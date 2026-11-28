package serializer

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/themis-project/themis/internal/communication/app"
)

// The rebuild request (EDR-REBUILD-01 D6): one JSON document in CloudEvents shape, built ONCE
// when the intent is created and stored as bytes (D36). Every delivery try sends those bytes,
// and the signature is over them. The facts are the frozen decision of Governance and the
// cycle's own numbers; nothing is read again later, and no credential is in it.

const (
	// RebuildRequestedType is the CloudEvents type of the request.
	RebuildRequestedType = "themis.rebuild.requested.v1"
	// RebuildRequestedSource is the CloudEvents source.
	RebuildRequestedSource = "themis/communication"
)

// RebuildRequestedEvent is the body a build connector receives.
type RebuildRequestedEvent struct {
	SpecVersion string               `json:"specversion"`
	Type        string               `json:"type"`
	ID          string               `json:"id"`
	Time        string               `json:"time"`
	Source      string               `json:"source"`
	Data        RebuildRequestedData `json:"data"`
}

// RebuildRequestedData is the `data` of the request. Targeted and Build are passed on as
// Governance recorded them; Themis does not read inside the build profile (D10).
type RebuildRequestedData struct {
	ProductID            string          `json:"product_id"`
	ProductName          string          `json:"product_name,omitempty"`
	ProjectID            string          `json:"project_id"`
	ProjectName          string          `json:"project_name,omitempty"`
	ReleaseID            string          `json:"release_id"`
	ReleaseVersion       string          `json:"release_version,omitempty"`
	PriorSBOMID          string          `json:"prior_sbom_id,omitempty"`
	DecisionID           string          `json:"decision_id"`
	CycleID              string          `json:"cycle_id"`
	Attempt              int             `json:"attempt"`
	Try                  int             `json:"try"`
	MaxAttempts          int             `json:"max_attempts"`
	Reason               string          `json:"reason"`
	PolicyVersion        int             `json:"policy_version"`
	PolicyScope          string          `json:"policy_scope"`
	BuildProfileRevision int             `json:"build_profile_revision,omitempty"`
	BuildProfileScope    string          `json:"build_profile_scope,omitempty"`
	BuildProfileSHA256   string          `json:"build_profile_sha256,omitempty"`
	Targeted             json.RawMessage `json:"targeted"`
	Build                json.RawMessage `json:"build,omitempty"`
}

// rebuildDecisionDTO reads the fields of governance.rebuild_requested.v1 the request passes on.
type rebuildDecisionDTO struct {
	DecisionID  string `json:"decision_id"`
	TriggerType string `json:"trigger_type"`
	Policy      struct {
		ScopeKind string `json:"scope_kind"`
		Version   int    `json:"version"`
	} `json:"policy"`
	BuildProfile *struct {
		Scope    string `json:"scope"`
		Revision int    `json:"revision"`
		SHA256   string `json:"sha256"`
	} `json:"build_profile"`
	Targeted json.RawMessage `json:"targeted"`
	Build    json.RawMessage `json:"build"`
}

// RenderRebuildRequested renders the summary line and the request body for one intent. A
// snapshot with no decision, or one that is not JSON, is an error: an intent whose content
// cannot be determined is not created.
func (r OutwardRenderer) RenderRebuildRequested(ctx context.Context, in app.Intent) (string, []byte, error) {
	s := in.Snapshot
	var d rebuildDecisionDTO
	if err := json.Unmarshal([]byte(s[app.SnapshotRebuildDecision]), &d); err != nil {
		return "", nil, fmt.Errorf("communication: rebuild request has no readable decision: %w", err)
	}
	if strings.TrimSpace(d.DecisionID) == "" || len(d.Targeted) == 0 {
		return "", nil, fmt.Errorf("communication: rebuild request decision names no decision id or no targeted components")
	}
	data := RebuildRequestedData{
		ProductID: in.ProductID, ProjectID: in.ProjectID, ReleaseID: in.ReleaseID,
		PriorSBOMID: s[app.SnapshotPriorSBOMID], DecisionID: d.DecisionID, CycleID: s[app.SnapshotRebuildCycleID],
		Attempt: atoiOr(s[app.SnapshotAttempt], 1), Try: atoiOr(s[app.SnapshotRebuildTry], 1),
		MaxAttempts: atoiOr(s[app.SnapshotRebuildMaxAttempts], 0), Reason: d.TriggerType,
		PolicyVersion: d.Policy.Version, PolicyScope: d.Policy.ScopeKind,
		Targeted: d.Targeted, Build: d.Build,
	}
	if d.BuildProfile != nil {
		data.BuildProfileRevision, data.BuildProfileScope, data.BuildProfileSHA256 = d.BuildProfile.Revision, d.BuildProfile.Scope, d.BuildProfile.SHA256
	}
	label, _ := r.releaseLabel(ctx, in)
	if r.identity != nil {
		if ref, err := r.identity.ReleaseIdentity(ctx, in.ReleaseID); err == nil {
			data.ProductName, data.ProjectName, data.ReleaseVersion = ref.Product, ref.Project, ref.Version
		}
	}
	body, err := json.Marshal(RebuildRequestedEvent{
		SpecVersion: "1.0", Type: RebuildRequestedType, ID: in.ID, Time: in.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Source: RebuildRequestedSource, Data: data,
	})
	if err != nil {
		return "", nil, err
	}
	summary := fmt.Sprintf("Themis asks for a rebuild of %s: attempt %d, try %d", label, data.Attempt, data.Try)
	return summary, body, nil
}

// RenderRebuildNoticeEmail renders the mail that tells a person about one rebuild request: the
// connector refused it, the refusals stopped the cycle, or nobody can tell whether a build was
// submitted. It states what Themis knows and what a person can do; it changes nothing.
func (r OutwardRenderer) RenderRebuildNoticeEmail(ctx context.Context, in app.Intent) (string, []byte) {
	label, who := r.releaseLabel(ctx, in)
	s := in.Snapshot
	var subject, lead string
	switch s[app.SnapshotRebuildNotice] {
	case app.NoticeCycleRefused:
		subject = "Themis rebuild stopped after refusals - " + label
		lead = "The build side refused the rebuild request " + strconv.Itoa(app.MaxRefusalsPerCycle) + " times. The cycle is stopped as refused.\n" +
			"Themis asks for nothing more in this cycle. The next trigger of the release is judged afresh.\n"
	case app.NoticeRefused:
		subject = "Themis rebuild request refused - " + label
		lead = "The build side refused the rebuild request. A refusal is not an attempt.\n" +
			"The request is made again at the next trigger of the release, or when a person asks for it.\n"
	default:
		subject = "Themis rebuild request uncertain - " + label
		lead = "Nobody can tell whether a build was submitted for this rebuild request.\n" +
			"A person settles it with one of two answers: submitted, or not_submitted.\n"
	}
	var b strings.Builder
	b.WriteString(lead)
	b.WriteString("No Finding was changed. Only the evaluation of a new SBOM can close one.\n\n")
	writeFacts(&b, append(who, []fact{
		{"Request", s[app.SnapshotRebuildIntentID]},
		{"Cycle", s[app.SnapshotRebuildCycleID]},
		{"Attempt", s[app.SnapshotRebuildAttempt]},
		{"Try", s[app.SnapshotRebuildTry]},
		{"Sent by", s[app.SnapshotRebuildChannel]},
		{"Reason given", s[app.SnapshotRebuildNoticeText]},
		{"Build", s[app.SnapshotRebuildBuildRef]},
		{"Decision", s[app.SnapshotRebuildDecisionID]},
	}...))
	return subject, []byte(b.String())
}

// recommendReasonText says in words why a decision is a recommendation and not a request.
func recommendReasonText(reason string) string {
	switch reason {
	case "no_build_profile":
		return "No build profile applies to this release, so no build can be asked for"
	case "mode_ask":
		return "The rebuild mode of this release is ask, so a person decides"
	default:
		return "A person decides"
	}
}

func atoiOr(s string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return fallback
	}
	return n
}
