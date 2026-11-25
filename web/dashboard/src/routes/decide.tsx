// The decision page (EDR-GUI-02 D14): deciding a Finding happens here, on a full page, never in
// the drawer. "Record decision" is the same two Governance steps as the old GUI (raise a human
// proposal, then accept it as the signed-in person): two audit entries, never one. A rationale
// is required. Leaving with unsaved changes asks first.
//
// The AI box (owner, 2026-11-25): the AI is asked only on the "Ask the AI" button, never on
// opening the page, so a low or plainly affected finding costs no model call. The form stays
// usable while the AI works. Its answer (recommend_position, recorded as an advisory proposal)
// goes into the form only when the person says so, and replacing values they already typed
// asks first. A read-only key may ask and read the answer, never record. Recording an unchanged AI fill accepts the AI's proposal; a changed form is the
// person's own proposal. The AI never decides.
//
// Copying (EDR-SYNC-01 revision 2, owner 2026-11-25): the person may tick other releases of the
// same product that carry the same CVE; the decision is then copied to each, once, in their
// name. A ticked release that already has a decision is replaced, and the page asks first.
// The pick list took the place of the "Applies to" scope picker.
//
// Severity (EDR-SCORING-01 section 7.1, owner 2026-11-25): the "Severity" card shows the original
// score and lets an admin set the severity that counts for the product, with the reason.
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Sparkles } from "lucide-react";
import { AiOutcome } from "@/components/ai-bits";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { PackageCell, StanceBadge, isCleared } from "@/components/finding-bits";
import { ErrorPanel } from "@/components/states";
import { CopyPicker, copySummary, type CopyTarget } from "@/components/copy-picker";
import { SeverityCard } from "@/components/severity-card";
import { apiPost, apiRaw } from "@/lib/api";
import { useAssessment, useCveReleases, useWhoAmI } from "@/lib/queries";
import { releaseHash } from "@/lib/router";
import { cn } from "@/lib/utils";
import type { components as Governance } from "@/types/api/governance";

type Treatment = "" | "accept" | "transfer" | "avoid" | "mitigate_later";
type Proposal = Governance["schemas"]["ProposalView"];
/** A proposal nobody has decided yet. Governance's word is "proposed" (domain.StatusProposed). */
const isWaiting = (p: Proposal) => p.status === "proposed";
type Asked = { kind: "recorded" } | { kind: "none"; reason: string | null; detail: string | null };

/** Ask Governance for an AI recommendation. 201 recorded an advisory proposal; 204 is a
 * no-answer with its reason (two headers, never joined). */
async function recommend(findingId: string): Promise<Asked> {
  const r = await apiRaw("governance", `/findings/${encodeURIComponent(findingId)}/recommend`, { method: "POST" });
  if (r.status === 201) return { kind: "recorded" };
  if (r.status === 204) return { kind: "none", reason: r.headers.get("X-Themis-AI-Reason"), detail: r.headers.get("X-Themis-AI-Detail") };
  const j = (await r.json().catch(() => ({}))) as { detail?: string; title?: string };
  throw new Error(`The AI recommendation returned ${r.status}: ${j.detail || j.title || "no detail"}`);
}

const STANCES: { id: string; label: string; note: string }[] = [
  { id: "affected", label: "Affected", note: "it applies here and needs fixing" },
  { id: "not_affected", label: "Not affected", note: "suppresses it, with the premise recorded" },
  { id: "mitigated", label: "Mitigated", note: "a compensating control is in place" },
  { id: "accepted_risk", label: "Accepted risk", note: "suppresses it until the review date" },
  { id: "under_investigation", label: "Under investigation", note: "still being looked at" },
  { id: "deferred", label: "Deferred", note: "fix in a later release" },
];
const suppressing = (st: string) => st === "not_affected" || st === "accepted_risk" || st === "deferred";
/** EDR-REMEDIATION-01 D2: an acceptance names its owner, treatment and proof. */
const acceptance = (st: string) => st === "accepted_risk" || st === "deferred";

const field = "w-full rounded-lg border border-line bg-card px-2.5 py-1.5 text-ink focus-visible:outline-2 focus-visible:outline-accent";

function Label({ children, htmlFor, note }: { children: ReactNode; htmlFor: string; note?: string }) {
  return (
    <label htmlFor={htmlFor} className="mb-1 block font-medium">
      {children}
      {note && <span className="ml-1.5 font-normal text-ink-2">{note}</span>}
    </label>
  );
}

/** Seconds since the ask began, so a slow model never looks frozen. */
function Elapsed() {
  const [s, setS] = useState(0);
  useEffect(() => {
    const t = window.setInterval(() => setS((n) => n + 1), 1000);
    return () => window.clearInterval(t);
  }, []);
  return <span className="font-mono">{s} s</span>;
}

function AiBox({
  proposal,
  asking,
  asked,
  error,
  filled,
  canUse,
  onAsk,
  onUse,
}: {
  proposal?: Proposal;
  asking: boolean;
  asked?: Asked;
  error?: Error | null;
  filled: boolean;
  canUse: boolean;
  onAsk: () => void;
  onUse: () => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          <Sparkles className="size-4 text-ai-ink" aria-hidden />
          AI recommendation
          <Badge tone="ai" title="The AI proposes; a person decides. Its proposal rests on inferred evidence and no rule can accept it.">
            advisory
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        {asking ? (
          <div role="status" aria-label="Asking the AI" className="flex flex-col gap-2">
            <Skeleton className="h-4 w-3/4" />
            <p className="text-xs text-ink-2">Asking the AI for its reading of this CVE. A local model may take a few minutes (<Elapsed /> so far). You can keep working on the form.</p>
          </div>
        ) : proposal ? (
          <>
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-ink-2">The AI proposes</span>
              <StanceBadge stance={proposal.stance} decided />
              {proposal.evidence_trust && <Badge tone={proposal.evidence_trust === "inferred" ? "warn" : "neutral"}>{proposal.evidence_trust}</Badge>}
            </div>
            {proposal.rationale && <p className="leading-relaxed whitespace-pre-wrap">{proposal.rationale}</p>}
            {filled ? (
              <p className="text-xs text-ink-2">In the form below. Record it as is, or change anything first.</p>
            ) : (
              canUse && (
                <div>
                  <Button size="sm" variant="outline" onClick={onUse}>
                    Use this in the form
                  </Button>
                </div>
              )
            )}
          </>
        ) : (
          <>
            {error ? (
              <p role="alert" className="text-crit">
                {error.message}
              </p>
            ) : asked?.kind === "none" ? (
              <AiOutcome reason={asked.reason} detail={asked.detail} />
            ) : asked?.kind === "recorded" ? (
              <p role="alert" className="text-crit">
                The AI answered and Governance recorded its proposal, but this page could not read it back. Reload the page to see it.
              </p>
            ) : (
              <p className="text-ink-2">Not asked for this finding. Ask when a second reading helps; each ask is one model call.</p>
            )}
            <div>
              <Button size="sm" variant="outline" onClick={onAsk}>
                {error || asked ? "Ask the AI again" : "Ask the AI"}
              </Button>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

export function Decide({ findingId, releaseId, version }: { findingId: string; releaseId: string; version: string }) {
  const a = useAssessment(findingId);
  const who = useWhoAmI();
  const qc = useQueryClient();
  const f = a.data?.finding;
  const k = a.data?.knowledge;
  const others = useCveReleases(f?.faultline_id, !!f?.faultline_id);
  const relId = releaseId || f?.release_id || "";
  const back = releaseHash(relId, version);

  const [stance, setStance] = useState("");
  const [rationale, setRationale] = useState("");
  const [copyTo, setCopyTo] = useState<string[]>([]);
  const [copyTargets, setCopyTargets] = useState<CopyTarget[]>([]);
  const [reviewBy, setReviewBy] = useState("");
  const [owner, setOwner] = useState("");
  const [treatment, setTreatment] = useState<Treatment>("");
  const [proof, setProof] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");
  const [filledFrom, setFilledFrom] = useState("");

  const canWrite = who.data?.can_write !== false;
  // Setting a severity is admin only (OS4); with no scopes stated (auth off) whoever may write.
  const isAdmin = who.data ? (who.data.scopes ? who.data.scopes.includes("admin") : who.data.can_write) : false;
  // The newest AI proposal still waiting: the one the box shows and the form fills from.
  const aiProposal = (f?.proposals ?? []).filter((p) => isWaiting(p) && p.proposer_kind === "ai").at(-1);
  // Asked only on the button (ask.refetch), never on opening: the person chooses when a model
  // call is worth it. A read-only key may ask too (owner, 2026-11-25): the ask records an
  // advisory proposal only, and recording a decision stays blocked for that key.
  const ask = useQuery({
    queryKey: ["recommend", findingId],
    enabled: false,
    queryFn: async () => {
      const r = await recommend(findingId);
      // The recorded proposal is read back before the wait ends, so the form fills in one step.
      if (r.kind === "recorded") await qc.invalidateQueries({ queryKey: ["assessment", findingId] });
      return r;
    },
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
  });
  const asking = ask.isFetching;
  const fill = (p: Proposal) => {
    setStance(STANCES.some((s) => s.id === p.stance) ? (p.stance ?? "") : "");
    setRationale(p.rationale ?? "");
    setFilledFrom(p.id ?? "");
  };
  // The AI's answer goes into the form on the person's word; values already there ask first.
  const takeAi = () => {
    if (!aiProposal) return;
    const typed = !!stance || !!rationale.trim();
    if (typed && !window.confirm("Replace the decision and rationale in the form with the AI's answer? Do you want to proceed?")) return;
    fill(aiProposal);
  };
  // "As is": the form still says what the AI proposed, so recording it accepts that proposal.
  const asIs = !!aiProposal && filledFrom === aiProposal.id && stance === aiProposal.stance && rationale === (aiProposal.rationale ?? "");

  const dirty = !done && ((!asIs && (!!stance || !!rationale.trim())) || copyTo.length > 0 || !!reviewBy || !!owner || !!treatment || !!proof);

  // Leaving with unsaved changes asks first: a reload or closed tab, and any in-app link.
  useEffect(() => {
    if (!dirty) return;
    const onUnload = (e: BeforeUnloadEvent) => e.preventDefault();
    const onClick = (e: MouseEvent) => {
      const link = (e.target as Element | null)?.closest?.("a[href]");
      if (link && !window.confirm("Leave this page? The decision is not recorded yet.")) e.preventDefault();
    };
    window.addEventListener("beforeunload", onUnload);
    document.addEventListener("click", onClick, true);
    return () => {
      window.removeEventListener("beforeunload", onUnload);
      document.removeEventListener("click", onClick, true);
    };
  }, [dirty]);

  const user = who.data?.user ?? "";
  const enc = encodeURIComponent;

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["assessment", findingId] });
    void qc.invalidateQueries({ queryKey: ["posture"] });
    void qc.invalidateQueries({ queryKey: ["cve-releases"] });
  };

  // What a copy does, said before and after: how many findings, and how many decisions go.
  const copy = copySummary(copyTargets, copyTo);
  const copied = () => (copyTo.length ? `; copying to ${copyTo.length} more finding${copyTo.length === 1 ? "" : "s"}, they follow within a minute` : "");
  // The person is told before a decision already on a ticked release is replaced (owner, C2).
  const okToReplace = () =>
    copy.replaced === 0 ||
    window.confirm(
      `${copy.replaced} of the ticked releases already ${copy.replaced === 1 ? "has" : "have"} a decision. It will be replaced by this one; the old one stays in the history. Do you want to proceed?`,
    );

  async function accept(proposalId: string, st: string) {
    const body: Governance["schemas"]["DecisionRequest"] = { actor_id: user, actor_kind: "human" };
    if (copyTo.length) body.copy_to = copyTo;
    if (suppressing(st) && reviewBy) body.review_by = new Date(`${reviewBy}T00:00:00Z`).toISOString();
    if (acceptance(st)) {
      if (owner.trim()) body.owner = owner.trim();
      if (treatment) body.treatment = treatment;
      if (proof.trim()) body.proof = proof.trim();
    }
    await apiPost("governance", `/findings/${enc(findingId)}/proposals/${enc(proposalId)}/accept`, body);
  }

  async function submit(e: FormEvent, mode: "record" | "propose") {
    e.preventDefault();
    setError("");
    if (!stance) return setError("Choose a decision.");
    if (!rationale.trim()) return setError("Write the rationale: it is the audit record.");
    if (mode === "record" && stance === "accepted_risk" && !owner.trim()) return setError("Name the accountable owner of this risk.");
    if (mode === "propose" && copyTo.length) return setError("A proposal is not copied. Untick the releases, or record the decision.");
    if (mode === "record" && !okToReplace()) return;
    setBusy(true);
    try {
      if (mode === "record" && asIs && aiProposal?.id) {
        await accept(aiProposal.id, stance);
        setDone(`Recorded: ${stance.replace("_", " ")}, as the AI proposed, decided by ${user}${copied()}.`);
        refresh();
        return;
      }
      const raised = await apiPost<{ proposal_id?: string }>("governance", `/findings/${enc(findingId)}/proposals`, {
        stance,
        rationale: rationale.trim(),
        proposer_kind: "human",
        proposer_id: user,
      });
      if (mode === "record") {
        const pid = raised.data?.proposal_id;
        if (!pid) throw new Error("Governance raised the proposal but returned no id; accept it under Proposals on record.");
        await accept(pid, stance);
        setDone(`Recorded: ${stance.replace("_", " ")}, decided by ${user}${copied()}.`);
      } else {
        setDone("Proposal raised. It waits for someone to decide.");
      }
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "The request failed.");
    } finally {
      setBusy(false);
    }
  }

  async function act(proposalId: string, st: string, verb: "accept" | "reject") {
    setError("");
    if (verb === "accept" && !okToReplace()) return;
    setBusy(true);
    try {
      if (verb === "accept") await accept(proposalId, st);
      else await apiPost("governance", `/findings/${enc(findingId)}/proposals/${enc(proposalId)}/reject`, { actor_id: user, actor_kind: "human" });
      setDone(verb === "accept" ? `Recorded: ${st.replace("_", " ")}, decided by ${user}${copied()}.` : "Proposal rejected. The finding keeps its current state.");
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "The request failed.");
    } finally {
      setBusy(false);
    }
  }

  if (a.isPending)
    return (
      <div className="space-y-3">
        <Skeleton className="h-6 w-64" />
        <Skeleton className="h-64" />
      </div>
    );
  if (a.isError) return <ErrorPanel error={a.error} />;
  if (!f) return <ErrorPanel error={new Error("Governance has no such finding.")} />;

  const pos = f.current_position;
  const comps = f.components ?? [];
  const pending = (f.proposals ?? []).filter(isWaiting);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <a href={back} className="inline-flex items-center gap-1 text-ink-2 hover:text-ink">
          <ArrowLeft className="size-4" aria-hidden />
          Back to the release
        </a>
      </div>
      <h1 className="flex flex-wrap items-center gap-2 text-lg font-semibold">
        Decide <span className="font-mono">{f.cve}</span>
        {pos ? <StanceBadge stance={pos.stance} decided /> : <StanceBadge decided={false} />}
      </h1>

      {done && (
        <div role="status" className="rounded-lg border border-good/40 bg-good/10 p-3">
          {done} <a className="text-accent" href={back}>Back to the release</a>
        </div>
      )}
      {error && (
        <div role="alert" className="rounded-lg border border-crit/40 bg-crit/10 p-3">
          {error}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_380px]">
        <div className="flex flex-col gap-4">
        <AiBox
          proposal={aiProposal}
          asking={asking}
          asked={ask.data}
          error={ask.error}
          filled={asIs}
          canUse={canWrite}
          onAsk={() => void ask.refetch()}
          onUse={takeAi}
        />
        <SeverityCard findingId={findingId} canSet={isAdmin} user={user} />
        <Card>
          <CardHeader>
            <CardTitle>Your decision</CardTitle>
            <CardDescription>
              {pos
                ? `Current decision: ${pos.stance?.replace("_", " ")} (version ${pos.version}). A new decision adds the next version; nothing is overwritten.`
                : "No decision yet."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {!canWrite ? (
              <p className="text-ink-2">Your key is read-only, so you can see this page but not record a decision.</p>
            ) : (
              <form className="flex flex-col gap-4" onSubmit={(e) => void submit(e, "record")}>
                <fieldset>
                  <legend className="mb-1.5 font-medium">Decision</legend>
                  <div className="grid gap-2 sm:grid-cols-2">
                    {STANCES.map((s) => (
                      <label
                        key={s.id}
                        className={cn(
                          "flex cursor-pointer items-start gap-2 rounded-lg border border-line p-2.5 hover:bg-hover",
                          stance === s.id && "border-accent bg-accent-soft",
                        )}
                      >
                        <input type="radio" name="stance" value={s.id} checked={stance === s.id} onChange={() => setStance(s.id)} className="mt-0.5" />
                        <span>
                          <span className="block font-medium">{s.label}</span>
                          <span className="block text-xs text-ink-2">{s.note}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                </fieldset>

                <div>
                  <Label htmlFor="d-rationale" note="required, this is the audit record">
                    Rationale
                  </Label>
                  <textarea
                    id="d-rationale"
                    rows={4}
                    className={field}
                    value={rationale}
                    onChange={(e) => setRationale(e.target.value)}
                    placeholder="Why, in your words. For example: the vulnerable function is not reachable; the loader is SafeLoader throughout."
                  />
                </div>

                <div>
                  <p className="mb-1 font-medium">
                    Copy to
                    <span className="ml-1.5 font-normal text-ink-2">other releases of this product that have this CVE (optional)</span>
                  </p>
                  <CopyPicker findingId={findingId} picked={copyTo} onChange={setCopyTo} onTargets={setCopyTargets} />
                </div>

                {suppressing(stance) && (
                  <div>
                    <Label htmlFor="d-review" note="optional, when this should come back for review">
                      Review by
                    </Label>
                    <Input id="d-review" type="date" value={reviewBy} onChange={(e) => setReviewBy(e.target.value)} className="w-48" />
                  </div>
                )}

                {acceptance(stance) && (
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div>
                      <Label htmlFor="d-owner" note={stance === "accepted_risk" ? "required" : "optional"}>
                        Owner
                      </Label>
                      <Input id="d-owner" className="w-full" value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="who is accountable for this risk" />
                    </div>
                    <div>
                      <Label htmlFor="d-treatment">Disposition</Label>
                      <select id="d-treatment" className={field} value={treatment} onChange={(e) => setTreatment(e.target.value as Treatment)}>
                        <option value="">Not stated</option>
                        <option value="accept">Accept: carry it as is</option>
                        <option value="transfer">Transfer: someone else carries it</option>
                        <option value="avoid">Avoid: remove the exposure</option>
                        <option value="mitigate_later">Mitigate later: fix in a later release</option>
                      </select>
                    </div>
                    <div className="sm:col-span-2">
                      <Label htmlFor="d-proof" note="optional link or document id; stored, never fetched">
                        Proof
                      </Label>
                      <Input id="d-proof" className="w-full" value={proof} onChange={(e) => setProof(e.target.value)} placeholder="https://…" />
                    </div>
                  </div>
                )}

                <div className="flex flex-wrap items-center gap-2">
                  <Button type="submit" disabled={busy}>
                    Record decision
                  </Button>
                  <Button type="button" variant="outline" disabled={busy} onClick={(e) => void submit(e, "propose")}>
                    Only propose
                  </Button>
                  <span className="text-xs text-ink-2">
                    {asIs
                      ? `Recording it as is accepts the AI's proposal in your name (${user}).`
                      : `Recorded in your name (${user}). Propose leaves the decision to someone else.`}
                  </span>
                </div>
              </form>
            )}
          </CardContent>
        </Card>
        </div>

        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>The facts</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-2">
              {k?.summary && <p className="leading-relaxed">{k.summary}</p>}
              <div className="flex flex-wrap items-center gap-1">
                {k?.severity && <Badge>{k.severity}{k.cvss_score ? ` · CVSS ${k.cvss_score}` : ""}</Badge>}
                {k?.kev && <Badge tone="crit">KEV</Badge>}
                {k?.exploit_public && <Badge tone="serious">public exploit</Badge>}
                {typeof k?.epss === "number" && <Badge>EPSS {(k.epss * 100).toFixed(1)}%</Badge>}
              </div>
              <div>
                <div className="text-xs text-ink-2">Packages</div>
                <PackageCell components={comps.filter((c) => !isCleared(c))} />
              </div>
              <div>
                <div className="text-xs text-ink-2">Vendor fix</div>
                {(k?.fixes ?? []).length ? (
                  <span className="font-mono text-xs">{(k?.fixes ?? []).map((x) => `${x.package ? `${x.package} → ` : ""}${x.version}`).join(", ")}</span>
                ) : (
                  <span className="text-muted">none for these components</span>
                )}
              </div>
              {(a.data?.vendor_statements ?? []).map((s, i) => (
                <div key={i} className="flex flex-wrap items-center gap-1 text-xs">
                  <span className="font-mono">{s.package}</span>
                  <Badge>{s.status}</Badge>
                  <Badge tone={s.applicability === "applicable" ? "accent" : "info"}>{s.applicability}</Badge>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Proposals waiting</CardTitle>
              <CardDescription>An AI or vendor proposal is never accepted by a rule; a person decides.</CardDescription>
            </CardHeader>
            <CardContent>
              {pending.length === 0 ? (
                <p className="text-muted">none</p>
              ) : (
                <ul className="flex flex-col gap-2">
                  {pending.map((p) => (
                    <li key={p.id} className="rounded-lg border border-line p-2.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Badge>{p.stance}</Badge>
                        <span className="text-ink-2">by {p.proposer_kind}</span>
                        {p.proposer_kind === "ai" && <Badge tone="ai">AI</Badge>}
                        {p.evidence_trust && <Badge tone={p.evidence_trust === "inferred" ? "warn" : "neutral"}>{p.evidence_trust}</Badge>}
                      </div>
                      {p.rationale && <p className="mt-1 text-xs text-ink-2">{p.rationale}</p>}
                      {canWrite && (
                        <div className="mt-2 flex gap-2">
                          <Button size="sm" disabled={busy} onClick={() => void act(p.id ?? "", p.stance ?? "", "accept")}>
                            Accept
                          </Button>
                          <Button size="sm" variant="outline" disabled={busy} onClick={() => void act(p.id ?? "", p.stance ?? "", "reject")}>
                            Reject
                          </Button>
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Other releases</CardTitle>
            </CardHeader>
            <CardContent>
              {!f.faultline_id ? (
                <p className="text-muted">none</p>
              ) : others.isPending ? (
                <Skeleton className="h-4 w-1/2" />
              ) : others.isError ? (
                <ErrorPanel error={others.error} />
              ) : (
                <ul className="flex flex-col gap-1">
                  {(others.data ?? [])
                    .filter((r) => r.releaseId !== f.release_id)
                    .map((r) => (
                      <li key={r.releaseId} className="flex flex-wrap items-center gap-1.5">
                        <span>
                          {r.project || "release"} v{r.version || r.releaseId.slice(0, 8)}
                        </span>
                        <StanceBadge stance={r.entry.stance} decided={r.entry.has_position} />
                      </li>
                    ))}
                  {(others.data ?? []).filter((r) => r.releaseId !== f.release_id).length === 0 && <li className="text-muted">none</li>}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
