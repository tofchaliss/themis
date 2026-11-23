// The decision page (EDR-GUI-02 D14): deciding a Finding happens here, on a full page, never in
// the drawer. "Record decision" is the same two Governance steps as the old GUI (raise a human
// proposal, then accept it as the signed-in person): two audit entries, never one. A rationale
// is required. Leaving with unsaved changes asks first.
//
// Changing severity is NOT here yet: severity comes from the CVSS vector, and the governed
// vector change (EDR-SCORING-01 S6) is not built, so there is nothing true to warn about.
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { PackageCell, StanceBadge, isCleared } from "@/components/finding-bits";
import { ErrorPanel } from "@/components/states";
import { apiGet, apiPost } from "@/lib/api";
import { useAssessment, useCveReleases, useWhoAmI } from "@/lib/queries";
import { releaseHash } from "@/lib/router";
import { cn } from "@/lib/utils";
import type { components as Governance } from "@/types/api/governance";

type Scope = "release" | "project" | "product";
type Treatment = "" | "accept" | "transfer" | "avoid" | "mitigate_later";
type ScopeTargets = Governance["schemas"]["ScopeTargetsView"];

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

/** EDR-SYNC-01 D7: what a wider scope reaches, BEFORE the click. "Nobody" and "cannot tell"
 * are different answers: an unreachable Registry is an error, never zero. */
function ScopePreview({ findingId, scope }: { findingId: string; scope: Scope }) {
  const [state, setState] = useState<{ scope: Scope; data?: ScopeTargets | null; error?: string } | null>(null);
  useEffect(() => {
    if (scope === "release") return;
    let live = true;
    apiGet<ScopeTargets>("governance", `/findings/${encodeURIComponent(findingId)}/scope-targets?scope=${scope}`)
      .then((data) => live && setState({ scope, data }))
      .catch((e: unknown) => live && setState({ scope, error: e instanceof Error ? e.message : "failed" }));
    return () => {
      live = false;
    };
  }, [findingId, scope]);
  if (scope === "release") return null;
  if (!state || state.scope !== scope) return <p className="text-xs text-ink-2">Checking what the {scope} scope reaches…</p>;
  if (state.error) return <p className="text-xs text-crit">Scope preview failed: {state.error}</p>;
  const targets = state.data?.targets ?? [];
  if (!targets.length)
    return <p className="text-xs text-ink-2">Reaches no other finding right now. A release uploaded later still gets this decision.</p>;
  return (
    <p className="flex flex-wrap items-center gap-1 text-xs text-ink-2">
      Will also apply to{" "}
      <b className="text-ink">
        {state.data?.count} finding{state.data?.count === 1 ? "" : "s"} in {state.data?.projects} project{state.data?.projects === 1 ? "" : "s"}
      </b>
      , in your name:
      {targets.slice(0, 8).map((t) => (
        <Badge key={t.finding_id}>
          {t.project_name || t.project_id} {t.version}
        </Badge>
      ))}
      {targets.length > 8 && <Badge tone="info">+{targets.length - 8} more</Badge>}A finding someone already decided keeps its decision.
    </p>
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
  const [scope, setScope] = useState<Scope>("release");
  const [reviewBy, setReviewBy] = useState("");
  const [owner, setOwner] = useState("");
  const [treatment, setTreatment] = useState<Treatment>("");
  const [proof, setProof] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  const dirty = !done && (!!stance || !!rationale.trim() || scope !== "release" || !!reviewBy || !!owner || !!treatment || !!proof);

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
  const canWrite = who.data?.can_write !== false;
  const enc = encodeURIComponent;

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["assessment", findingId] });
    void qc.invalidateQueries({ queryKey: ["posture"] });
    void qc.invalidateQueries({ queryKey: ["cve-releases"] });
  };

  async function accept(proposalId: string, st: string) {
    const body: Governance["schemas"]["DecisionRequest"] = { actor_id: user, actor_kind: "human" };
    if (scope !== "release") body.scope = scope;
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
    setBusy(true);
    try {
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
        setDone(`Recorded: ${stance.replace("_", " ")}, decided by ${user}${scope !== "release" ? ` for the whole ${scope}` : ""}.`);
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
    setBusy(true);
    try {
      if (verb === "accept") await accept(proposalId, st);
      else await apiPost("governance", `/findings/${enc(findingId)}/proposals/${enc(proposalId)}/reject`, { actor_id: user, actor_kind: "human" });
      setDone(verb === "accept" ? `Recorded: ${st.replace("_", " ")}, decided by ${user}.` : "Proposal rejected. The finding keeps its current state.");
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
  const pending = (f.proposals ?? []).filter((p) => p.status === "pending");

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
                  <Label htmlFor="d-scope" note="who this decision applies to">
                    Applies to
                  </Label>
                  <select id="d-scope" className={field} value={scope} onChange={(e) => setScope(e.target.value as Scope)}>
                    <option value="release">This release only</option>
                    <option value="project">Every release of this project</option>
                    <option value="product">Every project and release of this product</option>
                  </select>
                  <div className="mt-1.5">
                    <ScopePreview findingId={findingId} scope={scope} />
                  </div>
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
                  <span className="text-xs text-ink-2">Recorded in your name ({user}). Propose leaves the decision to someone else.</span>
                </div>
              </form>
            )}
          </CardContent>
        </Card>

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
