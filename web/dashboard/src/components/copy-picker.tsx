// The pick list of a decision copy (EDR-SYNC-01 revision 2, D10). The person ticks the releases
// of the same product that carry the same CVE; the decision is copied to each, once, in their
// name. A release that already has a decision can be ticked and says so: "will be replaced".
// A release that has the CVE on a different component is listed and cannot be ticked. The list
// is read only when the person opens it. Nothing here decides or copies: it only collects ids.
import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { StanceBadge } from "@/components/finding-bits";
import { apiGet } from "@/lib/api";
import type { components as Governance } from "@/types/api/governance";

type Targets = Governance["schemas"]["ScopeTargetsView"];
export type CopyTarget = Governance["schemas"]["ScopeTargetView"];

export const copyable = (t: CopyTarget) => t.level !== "vulnerability";

/** What the page says before recording: how many findings, in how many projects, how many
 * decisions get replaced. */
export function copySummary(targets: CopyTarget[], picked: string[]) {
  const chosen = targets.filter((t) => t.finding_id && picked.includes(t.finding_id));
  return {
    findings: chosen.length,
    projects: new Set(chosen.map((t) => t.project_id)).size,
    replaced: chosen.filter((t) => t.decision).length,
  };
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

export function CopyPicker({
  findingId,
  picked,
  onChange,
  onTargets,
}: {
  findingId: string;
  picked: string[];
  onChange: (ids: string[]) => void;
  /** The loaded list, so the page can count what a copy replaces. */
  onTargets?: (targets: CopyTarget[]) => void;
}) {
  const [open, setOpen] = useState(false);
  const [state, setState] = useState<{ targets?: CopyTarget[]; error?: string } | null>(null);
  useEffect(() => {
    if (!open) return;
    let live = true;
    apiGet<Targets>("governance", `/findings/${encodeURIComponent(findingId)}/scope-targets?scope=product&all=true`)
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
    // onTargets is the page's setter; the list is read once per open.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, findingId]);

  if (!open)
    return (
      <Button type="button" variant="outline" size="sm" onClick={() => setOpen(true)}>
        Choose releases to copy to
      </Button>
    );
  if (!state) return <p className="text-xs text-ink-2">Reading the releases of this product that have this CVE…</p>;
  if (state.error) return <p className="text-xs text-crit">The list of releases could not be read: {state.error}</p>;
  const targets = state.targets ?? [];
  if (!targets.length) return <p className="text-xs text-ink-2">No other release of this product has this CVE. There is nothing to copy to.</p>;

  const canPick = targets.filter(copyable);
  const ids = (ts: CopyTarget[]) => ts.map((t) => t.finding_id ?? "").filter(Boolean);
  const set = (list: string[], on: boolean) => onChange(on ? [...new Set([...picked, ...list])] : picked.filter((id) => !list.includes(id)));
  const projects = [...new Map(targets.map((t) => [t.project_id ?? "", t.project_name || t.project_id || "unnamed project"])).entries()];
  const sum = copySummary(targets, picked);

  return (
    <div className="space-y-2 rounded-lg border border-line p-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" variant="outline" size="sm" onClick={() => onChange(ids(canPick))} disabled={!canPick.length}>
          Select all in product
        </Button>
        <Button type="button" variant="ghost" size="sm" onClick={() => onChange([])} disabled={!picked.length}>
          Clear
        </Button>
        <span className="text-xs text-ink-2">
          {plural(canPick.length, "release")} can take a copy, in {plural(new Set(canPick.map((t) => t.project_id)).size, "project")}.
        </span>
      </div>
      <ul className="max-h-72 space-y-2 overflow-y-auto">
        {projects.map(([pid, name]) => {
          const rows = targets.filter((t) => (t.project_id ?? "") === pid);
          const pickable = ids(rows.filter(copyable));
          const all = pickable.length > 0 && pickable.every((id) => picked.includes(id));
          return (
            <li key={pid}>
              <label className="flex items-center gap-2 font-medium">
                <input
                  type="checkbox"
                  aria-label={`Project ${name}`}
                  checked={all}
                  disabled={!pickable.length}
                  onChange={(e) => set(pickable, e.target.checked)}
                />
                {name}
              </label>
              <ul className="ml-6 mt-1 space-y-1">
                {rows.map((t) => {
                  const id = t.finding_id ?? "";
                  const on = picked.includes(id);
                  const what = `${name} ${t.version ?? ""}`.trim();
                  return (
                    <li key={id} className="flex flex-wrap items-center gap-2 text-xs">
                      <label className={copyable(t) ? "flex items-center gap-2" : "flex items-center gap-2 text-muted"}>
                        <input type="checkbox" aria-label={what} checked={on} disabled={!copyable(t)} onChange={(e) => set([id], e.target.checked)} />
                        <span className="font-mono">{t.version || t.release_id}</span>
                      </label>
                      {!copyable(t) && <span className="text-muted">different component, cannot be copied to</span>}
                      {copyable(t) && t.level === "component" && <Badge tone="info">same package, other version</Badge>}
                      {t.decision && (
                        <>
                          <StanceBadge stance={t.decision.stance} decided />
                          <span className="text-ink-2">by {t.decision.decided_by_id || t.decision.decided_by_kind}</span>
                          {on && <Badge tone="warn">will be replaced by this decision</Badge>}
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
        {sum.findings === 0 ? (
          "Nothing is ticked: the decision stays on this release only."
        ) : (
          <>
            Also copies to{" "}
            <b className="text-ink">
              {plural(sum.findings, "finding")} in {plural(sum.projects, "project")}
            </b>
            , once, in your name.
            {sum.replaced > 0 && (
              <>
                {" "}
                <b className="text-ink">
                  {sum.replaced} of them {sum.replaced === 1 ? "has" : "have"} a decision that will be replaced
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
