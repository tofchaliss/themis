// The one intake door (EDR-INTAKE-01): an SBOM or a scanner report is sent as the file itself,
// the door identifies it, and the answer is a receipt. A VEX still takes POST /evidence.
// Everything here goes through the dashboard's proxy, so the browser never holds a node key.
import { ApiError, NodeDownError, apiGet, apiRaw } from "./api";
import type { components as Evidence } from "@/types/api/evidence";

export type IntakeReceipt = Evidence["schemas"]["IntakeReceipt"] & { observed_at?: string };

/* The intake refusal reasons, one plain line each. The reason itself is always shown
   verbatim; this only says what it MEANS. Keep it in step with AllRejectReasons in
   internal/evidence/domain/intake.go and RejectReason in api/evidence.openapi.yaml. The
   type below makes a missing entry a compile error. */
export const INTAKE_REASONS: Record<Evidence["schemas"]["RejectReason"], string> = {
  unknown_release: "the release id, or the product/project/version triple, does not resolve",
  no_inventory_for_release: "no SBOM is filed for this release: upload the SBOM first",
  unrecognised_format: "the document's format could not be identified; nothing was filed",
  declared_format_mismatch: "the declared kind or format contradicts the body",
  malformed_body: "not well-formed JSON, unparseable CSV, or invalid UTF-8",
  source_invalid: "the format was recognised but the input failed its rules; the detail names the element or row",
  schema_invalid: "the converted document failed its contract, so it was refused instead of filed unreadable",
  empty_report: "zero findings, an empty array, or an SBOM with no components",
  observed_at_underivable: "no scan time could be derived and none was given; intake never stamps “now”",
  observed_at_invalid: "the scan time given is unparseable or implausible",
  conversion_failed: "the format was valid but no finding survived translation",
  checksum_mismatch: "the expected checksum does not match the bytes sent",
  duplicate_other_release: "these exact bytes are already filed against another release; a new build is a new release",
  payload_too_large: "the file is over this node's intake size limit",
  too_many_records: "more findings or CSV rows than this node's record limit",
  unauthorized: "the API key is missing, invalid, or not allowed to write here",
  create_release_conflict: "release_id and create_release were both given; they exclude each other",
  incomplete_release_triple: "create_release needs the whole product/project/version triple",
  ambiguous_name: "the name matches more than one registered item",
  build_id_invalid: "build_id is invalid UTF-8, or over 256 characters",
};

export function reasonMeaning(reason: string): string {
  return (INTAKE_REASONS as Record<string, string>)[reason] ?? "a reason this page does not know; it is shown as sent";
}

/** What the file is sent as. The door identifies the content; this only picks the header. */
export function intakeContentType(name: string): string {
  if (/\.csv$/i.test(name)) return "text/csv";
  if (/\.(nessus|xml)$/i.test(name)) return "application/xml";
  return "application/json";
}

/** A CSV export does not carry its scan time, so only a CSV asks for one. */
export const needsScanDate = (name: string) => /\.csv$/i.test(name);

export type Outcome = { tone: "ok" | "note" | "err"; title: string; reason?: string; detail: string };

const PENDING = new Set(["accepted", "validating", "converting", "registering"]);
export const isPending = (r: IntakeReceipt) => PENDING.has(r.status);

/** The receipt in words. The counts are always a PAIR: "427 of 427" and "427 of 500" must not
 * look alike. */
export function receiptOutcome(r: IntakeReceipt): Outcome {
  if (r.status === "rejected" || r.status === "failed") return refusal(r.reason, r.detail || `intake ${r.status}`);
  if (isPending(r))
    return {
      tone: "note",
      title: "Accepted, still working",
      detail: `The file is larger than the inline budget, so intake is finishing on the server. Receipt ${r.intake_id}; following it…`,
    };
  const counts =
    r.detected_kind === "sbom"
      ? `${r.components ?? "?"} components${r.components_unmanaged ? ` (${r.components_unmanaged} hand-installed)` : ""}${
          r.components_skipped ? `, ${r.components_skipped} packages skipped (no identity)` : ""
        }`
      : `${r.findings_total ?? "?"} findings considered, ${r.findings_skipped ?? 0} skipped`;
  const parts = [
    `${r.detected_kind || "?"} / ${r.detected_format || "?"}`,
    counts,
    r.converted_by ? `converted by ${r.converted_by}` : "",
    r.observed_at ? `observed ${r.observed_at}` : "",
    r.evidence_id ? `evidence ${r.evidence_id.slice(0, 16)}` : "",
  ].filter(Boolean);
  return {
    tone: "ok",
    title: r.created === false ? "Already filed: same bytes, same evidence id" : "Filed. Correlation runs in the background; check the release shortly.",
    detail: parts.join(" · "),
  };
}

/** A refusal is TWO fields: the closed reason a consumer switches on, and the detail it shows.
 * They are never joined into one string. No reason means the failure is Themis's, not the file's. */
export function refusal(reason: string | undefined, detail: string): Outcome {
  return { tone: "err", title: reason ? "Intake refused" : "Intake could not be carried out", reason, detail };
}

/** Send one SBOM or scanner report through the intake door. `scanDate` is YYYY-MM-DD, sent as
 * midnight UTC; nothing picked sends nothing. */
export async function sendIntake(file: File, releaseId: string, scanDate: string): Promise<IntakeReceipt | Outcome> {
  let q = `release_id=${encodeURIComponent(releaseId)}`;
  if (scanDate) q += `&observed_at=${encodeURIComponent(`${scanDate}T00:00:00Z`)}`;
  const r = await apiRaw("evidence", `/intake?${q}`, { method: "POST", headers: { "Content-Type": intakeContentType(file.name) }, body: file });
  // 503 carries no receipt: the backlog is full, nothing was filed, retrying is safe.
  if (r.status === 503) return { tone: "err", title: "Intake is busy", detail: "Nothing was filed and no receipt was made. Retry this upload in a moment." };
  const body = (await r.json().catch(() => ({}))) as Partial<IntakeReceipt> & { title?: string };
  if (r.ok) return body as IntakeReceipt;
  return refusal(body.reason, body.detail || body.title || `status ${r.status}`);
}

/** Follow a receipt to its end. `wait` is replaceable in tests. Returns null when the node went
 * away or the receipt never finished; the receipt stays readable later. */
export async function followReceipt(
  rec: IntakeReceipt,
  wait: (ms: number) => Promise<void> = (ms) => new Promise((done) => setTimeout(done, ms)),
  tries = 60,
): Promise<IntakeReceipt | null> {
  const ms = Math.max(1, rec.retry_after_seconds || 2) * 1000;
  for (let i = 0; i < tries; i++) {
    await wait(ms);
    let next: IntakeReceipt | null;
    try {
      next = await apiGet<IntakeReceipt>("evidence", `/intake/${encodeURIComponent(rec.intake_id)}`);
    } catch {
      return null;
    }
    if (!next) return null;
    if (!isPending(next)) return next;
  }
  return null;
}

/** A VEX goes through POST /evidence: the intake door identifies SBOMs and reports only, and a
 * door that cannot identify a document must refuse it rather than guess. */
export async function sendVex(file: File, releaseId: string): Promise<Outcome> {
  const document = await file.text();
  const r = await apiRaw("evidence", "/evidence", { method: "POST", body: JSON.stringify({ kind: "vex", subject_release_id: releaseId, document }) });
  const j = (await r.json().catch(() => ({}))) as { id?: string; created?: boolean; detail?: string; title?: string };
  if (r.status === 201)
    return { tone: "ok", title: "VEX filed", detail: `Evidence ${j.id ?? ""}. Knowledge overlays it on the cards it covers; it never deletes a finding.` };
  if (r.status === 200 && j.created === false) return { tone: "ok", title: "Already filed against this release", detail: "Byte-identical content keeps the same evidence id." };
  return { tone: "err", title: `Refused (${r.status})`, detail: j.detail || j.title || "no detail given" };
}

/** Register one Registry item and return its id; a refusal is shown as the node said it. */
export async function register(path: string, body: unknown, what: string): Promise<string> {
  const r = await apiRaw("registry", path, { method: "POST", body: JSON.stringify(body) });
  const j = (await r.json().catch(() => ({}))) as { id?: string; detail?: string; title?: string };
  if (r.status !== 201 && r.status !== 200) throw new ApiError(r.status, `Cannot register the ${what}: ${j.detail || j.title || r.status}`);
  if (!j.id) throw new ApiError(r.status, `Cannot register the ${what}: the Registry returned no id`);
  return j.id;
}

export function errorText(e: unknown): string {
  if (e instanceof NodeDownError) return `The ${e.node} node did not answer.`;
  return e instanceof Error ? e.message : "The request failed.";
}
