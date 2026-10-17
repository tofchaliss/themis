-- EDR-DELIVERY-01 N-M2h / M2-7: a build system's callback is governed-external EVIDENCE ON THE
-- INTENT that asked for the build — never a Finding, a Position or a posture. It is keyed by the
-- intent, so "what did the rebuild produce" is answered from the intent's own record, and it is
-- idempotent per (intent, sbom): a job that retries its callback adds nothing.
CREATE TABLE IF NOT EXISTS delivery_callbacks (
    intent_id    UUID NOT NULL REFERENCES delivery_intents(id) ON DELETE CASCADE,
    sbom_id      TEXT NOT NULL,                 -- the NEW SBOM's Evidence id (REQUIRED, RC-3)
    image_digest TEXT NOT NULL,                 -- the built image (REQUIRED, RC-3)
    build_id     TEXT NOT NULL DEFAULT '',      -- the job's own build identifier, as given
    git_ref      TEXT NOT NULL DEFAULT '',      -- the revision built, as given
    reported_by  TEXT NOT NULL DEFAULT '',      -- the delivery:callback key id that reported it
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (intent_id, sbom_id)
);
