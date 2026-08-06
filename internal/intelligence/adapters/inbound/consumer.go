// Package inbound is the Intelligence Gateway's population consumer: it drains Governance's
// Position events off the bus and maintains the Operational Semantic Index (KS2, Δ3a). On each
// PositionEstablished/Revised it reads the subject Finding (components) + Faultline (severity) +
// current Position (stance/rationale) via read APIs, embeds the subject text, and upserts one
// vector keyed by Finding id. It NEVER imports Governance/Knowledge — the event JSON + read-API
// JSON are the only contracts (D5) — and it writes only a derived, rebuildable index, never
// truth (D12), so the orchestration lives in the adapter ring (there is no domain invariant to
// guard). Intelligence becomes a bus consumer here for the first time (R6).
package inbound

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/themis-project/themis/internal/intelligence/adapters/embed"
	"github.com/themis-project/themis/internal/intelligence/adapters/store"
	"github.com/themis-project/themis/internal/intelligence/app"
	"github.com/themis-project/themis/internal/kernel/event"
	"github.com/themis-project/themis/internal/platform/eventbus"
)

// Governance integration-event types Intelligence consumes for population (the wire contract,
// not a shared package) — the same stream + Position facts Communication consumes.
const (
	eventPositionEstablished = "governance.position_established"
	eventPositionRevised     = "governance.position_revised"
)

// Subscription declares Intelligence's bus binding (Δ3a R6): it consumes the Governance stream
// and dispatches on the two Position facts. The interest filter drops the lifecycle/proposal
// events Governance also emits.
var Subscription = eventbus.Subscription{
	Consumer: "intelligence",
	Stream:   "governance",
	Interest: []string{eventPositionEstablished, eventPositionRevised},
}

// PositionReader reads the current Enterprise Position (stance + rationale) for a
// (release, faultline) — the precedent labels. The readapi PrecedentClient satisfies it.
type PositionReader interface {
	CurrentPosition(ctx context.Context, release, faultline string) (stance, rationale string, found bool, err error)
}

// EmbeddingWriter persists an embedding (the store) — the durable write, which joins the inbox
// transaction.
type EmbeddingWriter interface {
	Upsert(ctx context.Context, rec store.EmbeddingRecord) error
}

// IndexWriter refreshes the live in-memory index — a post-commit, self-healing update (a rare
// aborted transaction is corrected by the boot-time reload from the store).
type IndexWriter interface {
	Upsert(rec store.EmbeddingRecord)
}

// Consumer maintains the Operational Semantic Index from Governance Position events.
type Consumer struct {
	projection app.ProjectionReader
	positions  PositionReader
	embedder   app.Embedder
	store      EmbeddingWriter
	index      IndexWriter
	model      string
}

// NewConsumer wires the population consumer. The embedder's model is stamped on every row so a
// model swap is detectable and the index rebuildable (R6).
func NewConsumer(projection app.ProjectionReader, positions PositionReader,
	embedder app.Embedder, st EmbeddingWriter, idx IndexWriter) *Consumer {
	return &Consumer{
		projection: projection, positions: positions,
		embedder: embedder, store: st, index: idx, model: embedder.Model(),
	}
}

// Prepare runs the read + embed phase OUTSIDE the inbox transaction (D7) and returns the
// write-only apply. A recognized payload that cannot be built into an embeddable record (no
// components and no severity) yields a no-op apply that still claims the envelope, so a
// permanently un-embeddable Finding is not retried forever. A read/embed error returns no apply
// so the event is retried — a transient read-API or embedder outage recovers without data loss
// (the index lags and the recommendation degrades to no-precedent meanwhile).
func (c *Consumer) Prepare(ctx context.Context, env event.Envelope) (func(context.Context) error, error) {
	dto, ok, err := decodePosition(env)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil // not a population event (defensive — the interest filter drops these)
	}
	rec, err := c.buildRecord(ctx, dto)
	if err != nil {
		return nil, err // transient → retry
	}
	if rec == nil {
		return func(context.Context) error { return nil }, nil // nothing to embed → claim + skip
	}
	return func(txCtx context.Context) error {
		if err := c.store.Upsert(txCtx, *rec); err != nil {
			return err
		}
		c.index.Upsert(*rec) // memory refresh; self-heals from the store on next boot if the tx aborts
		return nil
	}, nil
}

// Handle is the non-Preparer fallback (EB-06): the same read + write, inside the inbox
// transaction. In production Prepare is always used; Handle keeps the Handler contract total.
func (c *Consumer) Handle(ctx context.Context, env event.Envelope) error {
	dto, ok, err := decodePosition(env)
	if err != nil || !ok {
		return err
	}
	rec, err := c.buildRecord(ctx, dto)
	if err != nil {
		return err
	}
	if rec == nil {
		return nil
	}
	if err := c.store.Upsert(ctx, *rec); err != nil {
		return err
	}
	c.index.Upsert(*rec)
	return nil
}

// buildRecord assembles one embedding from the event + read APIs. It returns (nil, nil) when
// there is nothing to embed (no components and no severity), and an error only for a transient
// read/embed failure (which the caller retries).
func (c *Consumer) buildRecord(ctx context.Context, dto positionEventDTO) (*store.EmbeddingRecord, error) {
	// One projection read, not two gathering reads (T10) — the population path is a consumer
	// of the same business view the reasoning path uses.
	proj, err := c.projection.GetAssessment(ctx, dto.FindingID)
	if err != nil {
		return nil, err
	}
	text := embed.SubjectText(proj.Knowledge.Severity, proj.Finding.Components)
	if text == "" {
		return nil, nil
	}
	vec, err := c.embedder.Embed(ctx, text)
	if err != nil {
		return nil, err
	}
	_, rationale, _, err := c.positions.CurrentPosition(ctx, dto.ReleaseID, dto.FaultlineID)
	if err != nil {
		return nil, err
	}
	return &store.EmbeddingRecord{
		FindingID:   dto.FindingID,
		FaultlineID: dto.FaultlineID,
		ReleaseID:   dto.ReleaseID,
		CVE:         dto.CVE,
		Component:   representativeComponent(proj.Finding.Components),
		Stance:      dto.Stance,
		Rationale:   rationale,
		Model:       c.model,
		Vector:      vec,
		TextHash:    textHash(text),
	}, nil
}

func decodePosition(env event.Envelope) (positionEventDTO, bool, error) {
	switch env.Type {
	case eventPositionEstablished, eventPositionRevised:
		var dto positionEventDTO
		if err := json.Unmarshal(env.Payload, &dto); err != nil {
			return positionEventDTO{}, false, err
		}
		return dto, true, nil
	default:
		return positionEventDTO{}, false, nil
	}
}

func representativeComponent(purls []string) string {
	if len(purls) == 0 {
		return ""
	}
	return purls[0]
}

func textHash(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

// positionEventDTO mirrors Governance's PositionEstablished / PositionRevised JSON (its domain
// event structs marshal without tags, so keys are the exported field names).
type positionEventDTO struct {
	FindingID   string `json:"FindingID"`
	ReleaseID   string `json:"ReleaseID"`
	FaultlineID string `json:"FaultlineID"`
	CVE         string `json:"CVE"`
	Version     int    `json:"Version"`
	Stance      string `json:"Stance"`
}
