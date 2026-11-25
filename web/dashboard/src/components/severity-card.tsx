// Owner-set severity (EDR-SCORING-01 section 7.1). The product owner decides the severity that
// counts for the product. They give a reason and either a level or changed CVSS metric values;
// Themis computes the score either way and shows it before anything is saved. The original
// score stays beside it. The same severity can be set on other releases of the same product
// that have the same CVE, picked from a list; one that already has an owner-set severity is
// replaced, and the page asks first. Admin only: everyone else reads.
import { useEffect, useState, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { SeverityCell } from "@/components/finding-bits";
import { ErrorPanel } from "@/components/states";
import { when } from "@/components/when";
import { apiGet, apiPost, apiPut } from "@/lib/api";
import { BASE_METRICS, changedMetrics, metricOf, withMetric } from "@/lib/cvss";
import type { components as Governance } from "@/types/api/governance";

type Severity = Governance["schemas"]["FindingSeverity"];
type Owner = Governance["schemas"]["OwnerSeverity"];
type Preview = Governance["schemas"]["SeverityPreview"];
type Result = Governance["schemas"]["SetSeverityResult"];
export type SeverityTarget = Governance["schemas"]["SeverityTarget"];
type Targets = Governance["schemas"]["SeverityTargets"];

const LEVELS = ["critical", "high", "medium", "low", "none"] as const;
const field = "w-full rounded-lg border border-line bg-card px-2.5 py-1.5 text-ink focus-visible:outline-2 focus-visible:outline-accent";
const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;
const enc = encodeURIComponent;

function OwnerLine({ o }: { o: Owner }) {
  return (
    <span className="text-xs text-ink-2">
      {o.kind === "vector" ? "from changed CVSS metrics" : "level picked"}, by {o.set_by} on {when(o.set_at)}
    </span>
  );
}

/** The pick list: other releases of the same product that have this CVE. Read only when opened. */
export function SeverityPicker({
  findingId,
  picked,
  onChange,
  onTargets,
}: {
  findingId: string;
  picked: string[];
  onChange: (ids: string[]) => void;
  onTargets?: (targets: SeverityTarget[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const [state, setState] = useState<{ targets?: SeverityTarget[]; error?: string } | null>(null);
  useEffect(() => {
    if (!open) return;
    let live = true;
    apiGet<Targets>("governance", `/findings/${enc(findingId)}/severity/targets`)
      .then((r) => {
        if (!live) return;
        const targets = r?.targets ?? [];
        setState({ targets });
        onTargets?.(targets);
      })
      .catch((e: unknown) => live && setState({ error: e instanceof Error ? e.message : "failed" }));
    return () => {
      live = false;
    };
    // onTargets is the card's setter; the list is read once per open.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, findingId]);

  if (!open)
    return (
      <Button type="button" variant="outline" size="sm" onClick={() => setOpen(true)}>
        Choose other releases
      </Button>
    );
  if (!state) return <p className="text-xs text-ink-2">Reading the releases of this product that have this CVE…</p>;
  if (state.error) return <p className="text-xs text-crit">The list of releases could not be read: {state.error}</p>;
  const targets = state.targets ?? [];
  if (!targets.length) return <p className="text-xs text-ink-2">No other release of this product has this CVE.</p>;

  const all = targets.map((t) => t.finding_id);
  const set = (list: string[], on: boolean) => onChange(on ? [...new Set([...picked, ...list])] : picked.filter((id) => !list.includes(id)));
  const projects = [...new Map(targets.map((t) => [t.project_id ?? "", t.project_name || t.project_id || "unnamed project"])).entries()];
  const chosen = targets.filter((t) => picked.includes(t.finding_id));
  const replaced = chosen.filter((t) => t.owner).length;

  return (
    <div className="space-y-2 rounded-lg border border-line p-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" variant="outline" size="sm" onClick={() => onChange(all)}>
          Select all in product
        </Button>
        <Button type="button" variant="ghost" size="sm" onClick={() => onChange([])} disabled={!picked.length}>
          Clear
        </Button>
        <span className="text-xs text-ink-2">
          {plural(targets.length, "release")} in {plural(projects.length, "project")} {targets.length === 1 ? "has" : "have"} this CVE.
        </span>
      </div>
      <ul className="max-h-72 space-y-2 overflow-y-auto">
        {projects.map(([pid, name]) => {
          const rows = targets.filter((t) => (t.project_id ?? "") === pid);
          const ids = rows.map((t) => t.finding_id);
          return (
            <li key={pid}>
              <label className="flex items-center gap-2 font-medium">
                <input type="checkbox" aria-label={`Project ${name}`} checked={ids.every((id) => picked.includes(id))} onChange={(e) => set(ids, e.target.checked)} />
                {name}
              </label>
              <ul className="ml-6 mt-1 space-y-1">
                {rows.map((t) => {
                  const on = picked.includes(t.finding_id);
                  return (
                    <li key={t.finding_id} className="flex flex-wrap items-center gap-2 text-xs">
                      <label className="flex items-center gap-2">
                        <input type="checkbox" aria-label={`${name} ${t.version ?? ""}`.trim()} checked={on} onChange={(e) => set([t.finding_id], e.target.checked)} />
                        <span className="font-mono">{t.version || t.release_id}</span>
                      </label>
                      {t.owner && (
                        <>
                          <span className="text-ink-2">owner-set</span>
                          <SeverityCell severity={t.owner.level} score={t.owner.score} />
                          {on && <Badge tone="warn">will be replaced</Badge>}
                        </>
                      )}
                    </li>
                  );
                })}
              </ul>
            </li>
          );
        })}
      </ul>
      <p className="text-xs text-ink-2" role="note">
        {chosen.length === 0 ? (
          "Nothing is ticked: the severity is set on this release only."
        ) : (
          <>
            Also sets it on{" "}
            <b className="text-ink">
              {plural(chosen.length, "finding")} in {plural(new Set(chosen.map((t) => t.project_id)).size, "project")}
            </b>
            .
            {replaced > 0 && (
              <>
                {" "}
                <b className="text-ink">
                  {replaced} of them {replaced === 1 ? "has" : "have"} an owner-set severity that will be replaced
                </b>
                ; the old one stays in the history.
              </>
            )}
          </>
        )}
      </p>
    </div>
  );
}

export function SeverityCard({ findingId, canSet, user }: { findingId: string; canSet: boolean; user: string }) {
  const qc = useQueryClient();
  const path = `/findings/${enc(findingId)}/severity`;
  const sev = useQuery({ queryKey: ["severity", findingId], queryFn: () => apiGet<Severity>("governance", path) });
  const [editing, setEditing] = useState(false);
  const [mode, setMode] = useState<"level" | "vector">("level");
  const [level, setLevel] = useState("");
  const [vector, setVector] = useState("");
  const [reason, setReason] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [targets, setTargets] = useState<SeverityTarget[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState("");

  const s = sev.data;
  const original = s?.original_vector ?? "";
  const changed = mode === "vector" && !!vector && vector !== original;
  const ready = mode === "level" ? !!level : changed;
  const input = mode === "level" ? { level } : { vector };
  // What Themis would compute, read from Governance before anything is saved.
  const preview = useQuery({
    queryKey: ["severity-preview", findingId, mode, level, vector],
    enabled: editing && ready,
    queryFn: async () => (await apiPost<Preview>("governance", `${path}/preview`, input)).data,
    retry: false,
  });

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["severity", findingId] });
    void qc.invalidateQueries({ queryKey: ["posture"] });
    void qc.invalidateQueries({ queryKey: ["cve-releases"] });
    void qc.invalidateQueries({ queryKey: ["assessment", findingId] });
  };
  const open = () => {
    setEditing(true);
    setDone("");
    setError("");
    setMode("level");
    setLevel("");
    setVector(original);
    setReason("");
    setPicked([]);
  };

  async function save(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (!ready) return setError(mode === "level" ? "Pick a level." : "Change at least one metric.");
    if (!reason.trim()) return setError("Write the reason: it is the record of why this severity is right for the product.");
    const replaced = targets.filter((t) => picked.includes(t.finding_id) && t.owner).length + (s?.owner ? 1 : 0);
    if (
      replaced > 0 &&
      !window.confirm(`${plural(replaced, "owner-set severity")} will be replaced by this one; the old one stays in the history. Do you want to proceed?`)
    )
      return;
    setBusy(true);
    try {
      const r = await apiPut<Result>("governance", path, { actor_id: user, reason: reason.trim(), ...input, ...(picked.length ? { apply_to: picked } : {}) });
      const o = r.severity.owner;
      setDone(`Saved: ${o?.level} ${o?.score.toFixed(1)}, set on ${plural(r.applied, "finding")}. Priority and deadline use it from now.`);
      setEditing(false);
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "The request failed.");
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setError("");
    if (!window.confirm("Remove the owner-set severity? The original score counts again; the record stays in the history. Do you want to proceed?")) return;
    setBusy(true);
    try {
      await apiPost("governance", `${path}/remove`, { actor_id: user });
      setDone("Removed. The original score counts again.");
      setEditing(false);
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "The request failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Severity</CardTitle>
        <CardDescription>The original score is what the sources say. The product owner may set the severity that counts for this product.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {sev.isPending ? (
          <Skeleton className="h-10" />
        ) : sev.isError ? (
          <ErrorPanel error={sev.error} />
        ) : !s ? (
          <p className="text-muted">Severity is not available for this finding.</p>
        ) : (
          <>
            <dl className="grid gap-x-4 gap-y-2 sm:grid-cols-[9rem_1fr]">
              <dt className="text-ink-2">Original</dt>
              <dd className="flex flex-wrap items-center gap-2">
                <SeverityCell severity={s.original_severity} score={s.original_score} />
                {original && <span className="font-mono text-xs text-ink-2 break-all">{original}</span>}
              </dd>
              <dt className="text-ink-2">Owner-set</dt>
              <dd className="flex flex-col gap-1">
                {s.owner ? (
                  <>
                    <span className="flex flex-wrap items-center gap-2">
                      <SeverityCell severity={s.owner.level} score={s.owner.score} />
                      <Badge tone="accent">counts for priority and deadline</Badge>
                    </span>
                    <OwnerLine o={s.owner} />
                    {s.owner.vector && <span className="font-mono text-xs text-ink-2 break-all">{s.owner.vector}</span>}
                    <span className="text-xs">Reason: {s.owner.reason}</span>
                  </>
                ) : (
                  <span className="text-muted">none, the original counts</span>
                )}
              </dd>
            </dl>

            {done && (
              <p role="status" className="rounded-lg border border-good/40 bg-good/10 p-2 text-xs">
                {done}
              </p>
            )}
            {error && (
              <p role="alert" className="rounded-lg border border-crit/40 bg-crit/10 p-2 text-xs">
                {error}
              </p>
            )}

            {!canSet ? (
              <p className="text-xs text-ink-2">Only an admin can set or remove the severity.</p>
            ) : !editing ? (
              <div className="flex flex-wrap gap-2">
                <Button type="button" size="sm" variant="outline" onClick={open}>
                  {s.owner ? "Change severity" : "Set severity"}
                </Button>
                {s.owner && (
                  <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => void remove()}>
                    Remove owner-set severity
                  </Button>
                )}
              </div>
            ) : (
              <form className="flex flex-col gap-3 rounded-lg border border-line p-3" onSubmit={(e) => void save(e)}>
                <fieldset className="flex flex-wrap gap-4">
                  <legend className="mb-1 font-medium">How</legend>
                  <label className="flex items-center gap-2">
                    <input type="radio" name="sev-mode" checked={mode === "level"} onChange={() => setMode("level")} />
                    Pick a level
                  </label>
                  <label className={original ? "flex items-center gap-2" : "flex items-center gap-2 text-muted"}>
                    <input type="radio" name="sev-mode" checked={mode === "vector"} disabled={!original} onChange={() => setMode("vector")} />
                    Change CVSS metrics
                  </label>
                  {!original && <span className="text-xs text-ink-2">No CVSS 3 vector is stored for this CVE, so only a level can be set.</span>}
                </fieldset>

                {mode === "level" ? (
                  <div>
                    <label htmlFor="sev-level" className="mb-1 block font-medium">
                      Level
                    </label>
                    <select id="sev-level" className={`${field} sm:w-56`} value={level} onChange={(e) => setLevel(e.target.value)}>
                      <option value="">Choose…</option>
                      {LEVELS.map((l) => (
                        <option key={l} value={l}>
                          {l[0]!.toUpperCase() + l.slice(1)}
                        </option>
                      ))}
                    </select>
                    <p className="mt-1 text-xs text-ink-2">Themis moves the original score into the level's range by the shortest way.</p>
                  </div>
                ) : (
                  <div className="flex flex-col gap-2">
                    <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                      {BASE_METRICS.map((m) => (
                        <div key={m.key}>
                          <label htmlFor={`sev-${m.key}`} className="mb-1 block text-xs font-medium">
                            {m.label}
                          </label>
                          <select id={`sev-${m.key}`} className={field} value={metricOf(vector, m.key)} onChange={(e) => setVector(withMetric(vector, m.key, e.target.value))}>
                            {m.values.map(([v, name]) => (
                              <option key={v} value={v}>
                                {name}
                              </option>
                            ))}
                          </select>
                        </div>
                      ))}
                    </div>
                    <p className="font-mono text-xs text-ink-2 break-all">{vector}</p>
                    <p className="text-xs text-ink-2">{changed ? `Changed: ${changedMetrics(original, vector).join(", ")}` : "Nothing is changed yet."}</p>
                  </div>
                )}

                <div role="status" aria-label="Computed severity" className="rounded-lg bg-hover p-2">
                  {!ready ? (
                    <span className="text-xs text-ink-2">The computed score shows here.</span>
                  ) : preview.isError ? (
                    <span className="text-xs text-crit">The score could not be computed: {preview.error.message}</span>
                  ) : !preview.data ? (
                    <span className="text-xs text-ink-2">Computing…</span>
                  ) : (
                    <span className="flex flex-wrap items-center gap-2">
                      <span className="text-ink-2">Themis computes</span>
                      <SeverityCell severity={preview.data.level} score={preview.data.score} />
                      {typeof s.original_score === "number" && <span className="text-xs text-ink-2">(original {s.original_score.toFixed(1)})</span>}
                    </span>
                  )}
                </div>

                <div>
                  <label htmlFor="sev-reason" className="mb-1 block font-medium">
                    Reason <span className="ml-1.5 font-normal text-ink-2">required, this is the record</span>
                  </label>
                  <textarea
                    id="sev-reason"
                    rows={3}
                    className={field}
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    placeholder="Why this severity is right for the product. For example: the service is reachable only after login."
                  />
                </div>

                <div>
                  <p className="mb-1 font-medium">
                    Also set on <span className="ml-1.5 font-normal text-ink-2">other releases of this product that have this CVE (optional)</span>
                  </p>
                  <SeverityPicker findingId={findingId} picked={picked} onChange={setPicked} onTargets={setTargets} />
                  {mode === "level" && picked.length > 0 && <p className="mt-1 text-xs text-ink-2">Each release gets its own score: its original moved into the level's range.</p>}
                </div>

                <div className="flex flex-wrap items-center gap-2">
                  <Button type="submit" size="sm" disabled={busy}>
                    Save severity
                  </Button>
                  <Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => setEditing(false)}>
                    Cancel
                  </Button>
                  <span className="text-xs text-ink-2">Recorded in your name ({user}).</span>
                </div>
              </form>
            )}

            {s.history.length > 0 && (
              <details>
                <summary className="cursor-pointer text-xs text-ink-2">History ({s.history.length})</summary>
                <ul className="mt-2 flex flex-col gap-2">
                  {[...s.history].reverse().map((h, i) => (
                    <li key={i} className="rounded-lg border border-line p-2 text-xs">
                      <span className="flex flex-wrap items-center gap-2">
                        <SeverityCell severity={h.level} score={h.score} />
                        <OwnerLine o={h} />
                        {h.ended_at ? <Badge>{`${h.end_cause} by ${h.ended_by} on ${when(h.ended_at)}`}</Badge> : <Badge tone="accent">in force</Badge>}
                      </span>
                      <span className="mt-1 block">Reason: {h.reason}</span>
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
