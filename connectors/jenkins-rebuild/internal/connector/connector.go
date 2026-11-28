package connector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// claimMargin is added to the end of a claim before another worker may ask the build system
// about it (D39 item 4): the old worker's call is over by then.
const claimMargin = 10 * time.Second

// questionTries is how often the question "is there a build with this intent id" may fail to
// be asked before the request is reported as uncertain.
const questionTries = 3

// maxEventBytes bounds one request body.
const maxEventBytes = 4 << 20

// Connector is one running instance.
type Connector struct {
	cfg      Config
	secret   string
	store    Store
	builder  Builder
	reporter Reporter
	now      func() time.Time
	owner    string
	log      *slog.Logger
	kick     chan struct{}
	// broad is true when the instance runs under the exception of D33 item 4.
	broad bool
}

// New wires an instance. owner names it in a claim; two instances must not share a name.
func New(cfg Config, secret string, store Store, builder Builder, reporter Reporter, owner string, log *slog.Logger) *Connector {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Connector{cfg: cfg, secret: secret, store: store, builder: builder, reporter: reporter,
		now: time.Now, owner: owner, log: log, kick: make(chan struct{}, 1)}
}

// WithClock replaces the clock (tests).
func (c *Connector) WithClock(now func() time.Time) *Connector {
	c.now = now
	return c
}

// CheckCredential runs the startup check of D33. It fails closed: the caller must not serve
// when it returns an error. Only a credential that is too broad can be accepted, and only by
// the explicit setting; a check that could not be run is never accepted.
func (c *Connector) CheckCredential(ctx context.Context) error {
	err := c.builder.CheckCredential(ctx, c.cfg.AllowedJobs())
	if errors.Is(err, ErrBroadCredential) && c.cfg.Jenkins.AcceptBroadCredential {
		c.broad = true
		c.log.Warn("the build-system credential is broader than the allow-list and was accepted by configuration; the allow-list of this connector is the only limit",
			"detail", err.Error())
		return nil
	}
	return err
}

// Receive handles one delivery of an event: signature, record, answer. It returns the HTTP
// status. A success answer is a promise that the request ends in submitted, refused or
// uncertain and that Themis is told (D37 item 1).
func (c *Connector) Receive(signature string, body []byte) (status int, message string) {
	if !VerifySignature(signature, body, c.secret) {
		return http.StatusUnauthorized, "the signature does not match"
	}
	ev, err := ParseEvent(body)
	if err != nil {
		return http.StatusBadRequest, err.Error()
	}
	now := c.now().UTC()
	rec := Record{IntentID: ev.ID, State: StateReceived, ReceivedAt: now, UpdatedAt: now}
	job, params, err := c.cfg.authorize(ev, now)
	if err != nil {
		// A refusal is recorded and reported; it is not an attempt (D20).
		rec.State, rec.Reason = StateRefused, err.Error()
	} else {
		rec.Job, rec.Params = job, params
	}
	stored, created, err := c.store.Put(rec)
	if err != nil {
		c.log.Error("the request could not be stored", "intent_id", ev.ID, "error", err.Error())
		return http.StatusServiceUnavailable, "the request could not be stored"
	}
	if !created {
		// The same event id again: acknowledged, and nothing new is submitted (D12 item 2).
		return http.StatusAccepted, "already recorded as " + stored.State
	}
	c.log.Info("request recorded", "intent_id", ev.ID, "state", rec.State, "job", rec.Job, "reason", rec.Reason)
	select {
	case c.kick <- struct{}{}:
	default:
	}
	return http.StatusAccepted, "recorded as " + rec.State
}

// Recover is one pass of the recovery worker (D37 item 2): it carries every record forward by
// the table of D37 and repeats the reports Themis has not confirmed.
func (c *Connector) Recover(ctx context.Context) {
	recs, err := c.store.List()
	if err != nil {
		c.log.Error("the store could not be read", "error", err.Error())
		return
	}
	for _, rec := range recs {
		if ctx.Err() != nil {
			return
		}
		switch rec.State {
		case StateReceived:
			c.submit(ctx, rec.IntentID)
		case StateSubmitting:
			c.question(ctx, rec)
		}
		c.report(ctx, rec.IntentID)
	}
	if n, err := c.store.Prune(c.now().UTC().Add(-time.Duration(c.cfg.Retention))); err != nil {
		c.log.Error("old records could not be removed", "error", err.Error())
	} else if n > 0 {
		c.log.Info("old reported records removed", "count", n)
	}
}

// submit claims a received record and makes the one call to the build system.
func (c *Connector) submit(ctx context.Context, intentID string) {
	now := c.now().UTC()
	rec, ok, err := c.store.Claim(intentID, c.owner, now, time.Duration(c.cfg.ClaimTTL))
	if err != nil || !ok {
		return // another worker holds it, or it has moved on
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.CallTimeout))
	defer cancel()
	ref, err := c.builder.Submit(callCtx, rec.Job, rec.Params)
	var refused *RefusedError
	switch {
	case err == nil:
		c.outcome(rec, StateSubmitted, ref, "")
	case errors.As(err, &refused):
		c.outcome(rec, StateRefused, "", refused.Reason)
	default:
		// The result is not known. The record stays in submitting; after the claim ends the
		// build system is asked, and never called again blindly (D12 item 3).
		c.log.Warn("the call to the build system ended without an answer; the build system will be asked", "intent_id", intentID, "error", err.Error())
	}
}

// question handles a record found in submitting: once its claim is over, ask the build system
// for a build that carries the intent id (D37 item 3).
func (c *Connector) question(ctx context.Context, rec Record) {
	now := c.now().UTC()
	taken, ok, err := c.store.TakeOver(rec.IntentID, c.owner, now, now.Add(-claimMargin), time.Duration(c.cfg.ClaimTTL))
	if err != nil || !ok {
		return // the claim is still running, or another worker took it
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.CallTimeout))
	defer cancel()
	ref, found, complete, err := c.builder.Find(callCtx, taken.Job, taken.IntentID, taken.ReceivedAt)
	switch {
	case err != nil && taken.ClaimCounter <= questionTries:
		c.log.Warn("the build system could not be asked; it is asked again after this claim", "intent_id", taken.IntentID, "error", err.Error())
	case err != nil:
		c.outcome(taken, StateUncertain, "", "the build system could not be asked whether it has a build for this request")
	case found:
		c.outcome(taken, StateSubmitted, ref, "")
	case complete:
		// The build system has none, and that answer may be believed: back to received, and
		// the build is submitted (D37 item 3, D39 item 5).
		if ok, err := c.store.Release(taken.IntentID, taken.ClaimCounter, now); err == nil && ok {
			c.submit(ctx, taken.IntentID)
		}
	default:
		c.outcome(taken, StateUncertain, "", "no build with this request id was found, and the search cannot rule one out")
	}
}

// outcome writes the outcome record under the claim counter (D39 item 3).
func (c *Connector) outcome(rec Record, state, ref, reason string) {
	ok, err := c.store.Outcome(rec.IntentID, rec.ClaimCounter, state, ref, reason, c.now().UTC())
	switch {
	case err != nil:
		c.log.Error("the outcome could not be stored", "intent_id", rec.IntentID, "state", state, "error", err.Error())
	case !ok:
		c.log.Warn("the outcome was not written: this worker no longer holds the claim", "intent_id", rec.IntentID, "state", state)
	default:
		c.log.Info("request ended", "intent_id", rec.IntentID, "state", state, "build_ref", ref, "reason", reason)
	}
}

// report tells Themis the end state of one record, until Themis confirms it (D37 item 4).
func (c *Connector) report(ctx context.Context, intentID string) {
	rec, found, err := c.store.Get(intentID)
	if err != nil || !found || !rec.ended() || rec.Reported {
		return
	}
	callCtx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.CallTimeout))
	defer cancel()
	if err := c.reporter.Report(callCtx, rec); err != nil {
		c.log.Warn("the status call was not confirmed; it is sent again", "intent_id", intentID, "state", rec.State, "error", err.Error())
		return
	}
	if err := c.store.MarkReported(intentID, rec.State, c.now().UTC()); err != nil {
		c.log.Error("the confirmed report could not be noted", "intent_id", intentID, "error", err.Error())
	}
}

// Run is the recovery worker: one pass at start, then on every new request and on a timer,
// until ctx ends.
func (c *Connector) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(c.cfg.RecoveryInterval))
	defer ticker.Stop()
	for {
		c.Recover(ctx)
		select {
		case <-ctx.Done():
			return
		case <-c.kick:
		case <-ticker.C:
		}
	}
}

// Status is what GET /status serves: counts only, no request content.
type Status struct {
	States     map[string]int `json:"states"`
	Unreported int            `json:"unreported"`
	// BroadCredentialAccepted is the exception of D33 item 4, shown as long as it is in force.
	BroadCredentialAccepted bool `json:"broad_credential_accepted"`
}

// Handler serves the three addresses of the connector.
func (c *Connector) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /events", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEventBytes))
		if err != nil {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"message": "the request is too large"})
			return
		}
		status, msg := c.Receive(r.Header.Get(SignatureHeader), body)
		writeJSON(w, status, map[string]string{"message": msg})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		recs, err := c.store.List()
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"message": "the store could not be read"})
			return
		}
		st := Status{States: map[string]int{}, BroadCredentialAccepted: c.broad}
		for _, rec := range recs {
			st.States[rec.State]++
			if rec.ended() && !rec.Reported {
				st.Unreported++
			}
		}
		writeJSON(w, http.StatusOK, st)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
