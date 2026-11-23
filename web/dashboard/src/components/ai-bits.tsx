// The AI pieces every screen shares (AI-204-1, GUI-9, TRUST-8): call a capability, show an
// answer with its provenance, and name a no-answer by its reason. The reason and its detail
// are TWO headers and are never joined: a consumer switches on the reason and shows the detail.
import { Badge } from "@/components/ui/badge";
import { apiRaw } from "@/lib/api";

type Tone = "crit" | "warn" | "info" | "accent";

/** Every reason the Gateway and Governance can state. Keep in step with
 * internal/intelligence/app/gateway.go and internal/governance/app's ReasonAI* constants. */
export const AI_REASONS: Record<string, [string, Tone, string]> = {
  insufficient: ["declined honestly", "accent", "Not enough grounded evidence to answer: the safety check working, not a failure."],
  no_subject: ["not asked: no carrier", "accent", "No installed component is evidenced to carry this flaw, so there was nothing to take a position on."],
  business_invalid: ["failed grounding", "crit", "The model answered but its citations failed the grounding check, so the answer was refused."],
  provider_error: ["provider error", "warn", "The model provider failed mid-call. A caller timeout shorter than the model's latency also lands here."],
  budget_exhausted: ["budget exhausted", "warn", "This capability's token budget for the current window is spent; it resets when the window rolls."],
  no_grounding: ["no grounding assembled", "warn", "The Gateway found nothing to reason from for this subject: a data gap, not a model verdict."],
  schema_invalid: ["malformed answer", "crit", "The model's answer did not match the capability's schema and was discarded."],
  prompt_error: ["prompt error", "crit", "The prompt could not be built for this capability: a problem on this node, not an AI outcome."],
  unauthorized: ["not permitted", "crit", "The caller was refused before any model ran: a credentials or policy problem."],
  selection_mismatch: ["wrong subject", "crit", "This capability does not accept the subject it was given: a caller bug."],
  unknown_capability: ["capability not registered", "crit", "This node's Gateway does not know that capability: an older or differently configured node."],
  ok: ["empty answer", "warn", "The Gateway reported success and returned nothing."],
  disabled: ["AI disabled", "info", "The AI plane is switched off on this node."],
  unreachable: ["Intelligence unreachable", "warn", "The Intelligence node did not answer: an operations problem, not an AI verdict."],
  declined: ["no reason stated", "info", "The Gateway produced nothing and sent no reason (an Intelligence node older than AI-204-1)."],
  business_verification_failed: ["failed our own check", "crit", "The answer cited evidence Governance could not vouch for, so nothing was recorded."],
};

export function AiOutcome({ reason, detail }: { reason?: string | null; detail?: string | null }) {
  let key = (reason ?? "").trim();
  let extra = (detail ?? "").trim();
  // A node that still flattens the two headers into one: split it back, so the lookup works.
  const cut = key.indexOf(": ");
  if (cut > 0 && !AI_REASONS[key]) {
    if (!extra) extra = key.slice(cut + 2);
    key = key.slice(0, cut);
  }
  // An unknown reason is NAMED, never denied.
  const [label, tone, why] =
    AI_REASONS[key] ??
    (key ? [key, "warn" as Tone, "The Gateway stated a reason this page does not know; it is shown as sent."] : ["no answer", "info" as Tone, "The Gateway returned nothing and stated no reason."]);
  return (
    <div role="status" className="flex flex-wrap items-start gap-2 rounded-lg border border-line bg-page p-3">
      <Badge tone={tone}>{label}</Badge>
      <span className="min-w-0 flex-1">
        {why}
        {extra && <span className="mt-1 block font-mono text-xs text-ink-2">{extra}</span>}
      </span>
    </div>
  );
}

export type AiAnswer = { information?: string; decided_by?: string; precedents_used?: number };
export type AiResult = { kind: "answer"; data: AiAnswer } | { kind: "none"; reason: string | null; detail: string | null } | { kind: "missing" };

/** Invoke one capability. 204 is a no-answer with its reason; 404 means this node predates it.
 * Any other refusal is an error with the node's detail. */
export async function invokeCapability(name: string, subject: { type: string; ids: string[] }): Promise<AiResult> {
  const r = await apiRaw("intelligence", `/capabilities/${name}/invoke`, { method: "POST", body: JSON.stringify({ subject }) });
  if (r.status === 200) return { kind: "answer", data: (await r.json()) as AiAnswer };
  if (r.status === 204) return { kind: "none", reason: r.headers.get("X-Themis-AI-Reason"), detail: r.headers.get("X-Themis-AI-Detail") };
  if (r.status === 404) return { kind: "missing" };
  const j = (await r.json().catch(() => ({}))) as { detail?: string; title?: string };
  throw new Error(`${name} returned ${r.status}: ${j.detail || j.title || "no detail"}`);
}

/** TRUST-8: an identifier the model was not grounded on is marked, so it cannot be skimmed past. */
function Prose({ text }: { text: string }) {
  const parts = text.split(/(\[UNVERIFIED MENTIONS[^\]]*\])/g);
  return (
    <div className="leading-relaxed whitespace-pre-wrap">
      {parts.map((p, i) =>
        p.startsWith("[UNVERIFIED MENTIONS") ? (
          <mark key={i} className="rounded bg-warn/30 px-0.5 text-ink" title="this identifier was NOT in the model's grounding: verify before acting on it">
            {p}
          </mark>
        ) : (
          p
        ),
      )}
    </div>
  );
}

export function AiAnswerView({ a }: { a: AiAnswer }) {
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap gap-1.5">
        <Badge tone="ai" title="the AI path is local-only: prompts go to the on-prem model and nothing leaves the building">
          AI · local-only
        </Badge>
        {a.decided_by && <Badge title="which plan step produced this: a rule or the model">{a.decided_by}</Badge>}
        {Number.isInteger(a.precedents_used) && (
          <Badge title="past decisions that grounded this">
            {a.precedents_used} precedent{a.precedents_used === 1 ? "" : "s"} used
          </Badge>
        )}
      </div>
      <Prose text={a.information ?? ""} />
    </div>
  );
}

export function AiResultView({ r, missing }: { r: AiResult; missing: string }) {
  if (r.kind === "answer") return <AiAnswerView a={r.data} />;
  if (r.kind === "none") return <AiOutcome reason={r.reason} detail={r.detail} />;
  return (
    <div role="status" className="rounded-lg border border-line bg-page p-3 text-ink-2">
      {missing}
    </div>
  );
}
