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

// eventFaultlineEnriched is Knowledge's enrichment fact. Severity feeds embed.SubjectText, so a
// severity change makes every indexed Finding on that card stale.
const eventFaultlineEnriched = "knowledge.faultline_enriched"

// Subscription declares Intelligence's bus binding (Δ3a R6): it consumes the Governance stream
// and dispatches on the two Position facts. The interest filter drops the lifecycle/proposal
// events Governance also emits.
var Subscription = eventbus.Subscription{
	Consumer: "intelligence",
	Stream:   "governance",
	Interest: []string{eventPositionEstablished, eventPositionRevised},
}

// FaultlineSubscription is the SECOND binding (Δ3a freshness): the Knowledge stream, filtered to
// the enrichment fact.
//
// Without it the index went stale in one direction only — a Faultline's severity is half of the
// embedded subject text, but the index was refreshed exclusively on Position events, so a CVE
// escalating from high to critical did not move its vectors until each affected Finding happened
// to be re-decided. Never wrong (the vector still matched on components), just increasingly out
// of date, which is the failure mode nobody notices.
//
// A DISTINCT consumer name because the bus cursor is per (consumer, stream): sharing the name
// would make the two streams fight over one cursor position.
var FaultlineSubscription = eventbus.Subscription{
	Consumer: "intelligence-knowledge",
	Stream:   "knowledge",
	Interest: []string{eventFaultlineEnriched},
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
	// CachedEmbedding returns the stored embed-text hash and vector for a Finding, so an
	// unchanged subject can be re-labelled without paying for another embed call.
	CachedEmbedding(ctx context.Context, findingID string) (hash string, vector []float32, found bool, err error)
	// IndexedForFaultline lists the Findings already indexed for a Faultline — the exact set a
	// severity change makes stale.
	IndexedForFaultline(ctx context.Context, faultlineID string) ([]store.IndexedFinding, error)
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
	if env.Type == eventFaultlineEnriched {
		return c.prepareReEmbed(ctx, env)
	}
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
	if env.Type == eventFaultlineEnriched {
		apply, err := c.prepareReEmbed(ctx, env)
		if err != nil || apply == nil {
			return err
		}
		return apply(ctx)
	}
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

// prepareReEmbed refreshes every indexed Finding on an enriched Faultline.
//
// It reuses buildRecord unchanged, which means it also inherits the embed cache: a Faultline
// event that did NOT move the severity produces the same subject text, the hash matches, and no
// model call is made. So subscribing to every enrichment is cheap — the cost is one index read
// per event, not one embed per Finding.
//
// An unknown Faultline (nothing indexed for it yet) claims the envelope and does nothing: there
// is no vector to refresh, and the Position event that eventually creates one will embed then.
func (c *Consumer) prepareReEmbed(ctx context.Context, env event.Envelope) (func(context.Context) error, error) {
	var dto faultlineEventDTO
	if err := json.Unmarshal(env.Payload, &dto); err != nil {
		return nil, err
	}
	if dto.FaultlineID == "" {
		return func(context.Context) error { return nil }, nil
	}
	indexed, err := c.store.IndexedForFaultline(ctx, dto.FaultlineID)
	if err != nil {
		return nil, err // transient → retry
	}
	recs := make([]store.EmbeddingRecord, 0, len(indexed))
	for _, f := range indexed {
		rec, err := c.buildRecord(ctx, positionEventDTO{
			FindingID: f.FindingID, ReleaseID: f.ReleaseID, FaultlineID: f.FaultlineID,
			CVE: f.CVE, Stance: f.Stance,
		})
		if err != nil {
			return nil, err // transient → retry the whole event; re-embedding is idempotent
		}
		if rec != nil {
			recs = append(recs, *rec)
		}
	}
	return func(txCtx context.Context) error {
		for _, rec := range recs {
			if err := c.store.Upsert(txCtx, rec); err != nil {
				return err
			}
			c.index.Upsert(rec)
		}
		return nil
	}, nil
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
	hash := textHash(text)
	// Skip the embed when the SUBJECT text is unchanged. A Position revise usually moves only
	// the stance or the rationale — neither of which is embedded (SubjectText keys on component
	// + severity) — so re-embedding would spend an Ollama round-trip to produce a vector
	// identical to the stored one. The row is still rewritten below with the new labels; only
	// the model call is avoided.
	vec, err := c.cachedOrEmbed(ctx, dto.FindingID, hash, text)
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
		TextHash:    hash,
	}, nil
}

// cachedOrEmbed returns the stored vector when the subject text has not changed, otherwise a
// freshly embedded one.
//
// A lookup failure is deliberately NOT fatal: the cache is an optimization, and refusing to
// make progress because it could not be consulted would let a storage hiccup stall index
// population. It falls through to the embed, which is always correct — just slower.
func (c *Consumer) cachedOrEmbed(ctx context.Context, findingID, hash, text string) ([]float32, error) {
	if storedHash, vec, found, err := c.store.CachedEmbedding(ctx, findingID); err == nil && found &&
		storedHash == hash && len(vec) > 0 {
		return vec, nil
	}
	return c.embedder.Embed(ctx, text)
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

// SubjectTextHashFor exposes the embed-cache key for tests, so a test seeds the cache the way
// the consumer computes it rather than hard-coding a hex string that silently stops matching
// when SubjectText changes.
func SubjectTextHashFor(severity string, components []string) string {
	return textHash(embed.SubjectText(severity, components))
}

// faultlineEventDTO mirrors the one field of Knowledge's FaultlineEnriched this consumer needs.
type faultlineEventDTO struct {
	FaultlineID string `json:"FaultlineID"`
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
