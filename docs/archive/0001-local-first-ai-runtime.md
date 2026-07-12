# 1. Local-first AI runtime, config-selectable, router deferred

Date: 2026-06-30
Status: Accepted
Phase: 2b (v0.4.0 — AI Intelligence)

## Context

Phase 2b introduces Layer-2 AI enrichment. A worker (the harness) calls a language model
through the `domain.AIWorkerRuntime` port. We had to decide *which* model backend(s) v0.4.0
supports and how that choice is wired.

Two distinct concerns were initially conflated:

- **Runtime selection** — which implementation backs `AIWorkerRuntime`, chosen at startup.
- **Model router** — per-finding *dynamic* dispatch across several backends (local vs
  external) with fallback chains and cost/availability-based routing.

Two project invariants constrain the choice:

- **Reproducibility is mandatory from day one** (D-LLMOPS-1): every `ai_analyses` row records
  `model` + `model_version`. A local model can be pinned to an exact digest; an external
  hosted endpoint silently updates the model under a stable name, weakening `model_version`.
- **No data egress without an explicit operator decision.** Sending finding context (CVE,
  component, service descriptions) to a third party is a governance decision many operators
  of a security-intelligence platform will forbid.

## Decision

1. **Config-selectable single runtime.** Config key `ai_runtime` (enum). The only valid value
   in v0.4.0 is `ollama`. The `AIWorkerRuntime` port plus a DI-root factory *is* the extension
   seam — no router needed to add a backend later.

2. **Local-first.** v0.4.0 runs Ollama locally. The reproducibility invariant holds because a
   local model is pinned to an exact digest recorded in every analysis.

3. **Ollama as the v0.4.0 runtime.** Lowest ops (single binary, CPU-capable 7B, simple model
   pull), native structured output (`format: json`) that reduces self-correction retries, and
   it exposes an OpenAI-compatible `/v1/chat/completions` endpoint — the wire contract a future
   router can standardize on.

4. **Router and external/internet-hosted backends are deferred.** They carry zero value while
   only one backend exists. When added, they are opt-in / off by default, require an explicit
   data-egress acknowledgement, and pin `model_version` on a best-effort basis. The future
   router standardizes on the OpenAI-compatible contract — "same contract, different base URL +
   auth + model name." Per-analysis LLM identification is already provided by the
   reproducibility record (`model` + `model_version`).

5. **Runtime ≠ model.** The model (CyberPal-2.0 / Qwen2.5-7B) is an independent config knob
   (`ai_model`), decided separately.

## Consequences

- The local `adapter/ollama/` adapter is not rewritten when external backends arrive; only a
  new adapter implementing the same port is added behind the config seam.
- Operators cannot use a hosted frontier model in v0.4.0. This is intentional: it keeps the
  reproducibility invariant strong and avoids data-egress decisions during the thin first slice.
- CyberPal-2.0 registry availability remains a deployment risk (OQ-3); mitigated because the
  model is a config knob with a guaranteed-available alternative.
- The future router design is constrained to the OpenAI-compatible chat-completions contract.
