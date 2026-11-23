// The small pieces every Finding view shares: severity band, decision, SLA, package and fix.
// Status colours are fixed (EDR-GUI-01) and every badge carries its word beside the colour.
import { Badge } from "@/components/ui/badge";
import type { Component, PostureEntry, SLA } from "@/lib/queries";

type Tone = "crit" | "serious" | "warn" | "elevated" | "info" | "good" | "neutral" | "accent";

const BAND_TONE: Record<string, Tone> = {
  critical: "crit",
  "high+": "serious",
  high: "warn",
  elevated: "elevated",
  informational: "info",
};

/** Knowledge's exploitability band, shown as the row's severity (D13: one name, not two). */
export function BandBadge({ band }: { band?: string }) {
  if (!band) return <Badge tone="neutral">unbanded</Badge>;
  return <Badge tone={BAND_TONE[band] ?? "neutral"}>{band}</Badge>;
}

const STANCE_TONE: Record<string, Tone> = {
  affected: "crit",
  not_affected: "good",
  accepted_risk: "warn",
  mitigated: "elevated",
};

export function StanceBadge({ stance, decided }: { stance?: string; decided?: boolean }) {
  if (!decided) return <Badge tone="neutral">open</Badge>;
  return <Badge tone={STANCE_TONE[stance ?? ""] ?? "neutral"}>{(stance || "decided").replace("_", " ")}</Badge>;
}

const fmtDay = (iso?: string) => (iso ? iso.slice(0, 10) : "");

/** EDR-REMEDIATION-01 D1: the deadline is derived on every read; a breach changes nothing,
 * this only shows it. */
export function SlaCell({ sla }: { sla?: SLA }) {
  if (!sla || sla.state === "not_applicable") return <span className="text-muted">—</span>;
  const age = `${sla.age_days} day${sla.age_days === 1 ? "" : "s"} old${sla.days_under_acceptance ? `, ${sla.days_under_acceptance} under acceptance` : ""}`;
  const left = sla.days_left ?? 0;
  const chip: Record<string, [Tone, string]> = {
    breached: ["crit", `breached ${Math.abs(left)}d ago`],
    due_soon: ["warn", `due in ${left}d`],
    within: ["neutral", `${left}d left`],
    paused: ["info", "paused"],
    met: ["good", "met"],
    missed: ["elevated", "missed"],
  };
  const [tone, text] = chip[sla.state] ?? ["neutral", sla.state];
  return (
    <span className="inline-flex flex-wrap items-center gap-1" title={age}>
      <Badge tone={tone}>{text}</Badge>
      {sla.kev_due_applied && (
        <Badge tone="crit" title="CISA's KEV due date is earlier than the policy's and is the deadline">
          KEV date
        </Badge>
      )}
      {sla.due && sla.state !== "paused" && <span className="font-mono text-xs text-muted">{fmtDay(sla.due)}</span>}
    </span>
  );
}

/** Carriers first (unknown counts as carrier: a gap in attribution must never hide a flaw). */
export function packageSummary(components?: Component[]): { name: string; more: number } {
  const cs = components ?? [];
  const carriers = cs.filter((c) => c.claim_class !== "scope");
  const first = (carriers[0] ?? cs[0])?.name ?? "";
  return { name: first, more: Math.max(0, cs.length - 1) };
}

export function PackageCell({ components }: { components?: Component[] }) {
  const { name, more } = packageSummary(components);
  if (!name) return <span className="text-muted">—</span>;
  return (
    <span className="inline-flex items-center gap-1">
      <span className="font-mono text-xs">{name}</span>
      {more > 0 && <Badge tone="info">+{more}</Badge>}
    </span>
  );
}

export function FixCell({ entry }: { entry: PostureEntry }) {
  const fixes = entry.fixes ?? [];
  if (!fixes.length) return <span className="text-muted">none attributed</span>;
  return (
    <span className="inline-flex items-center gap-1">
      <span className="font-mono text-xs">{fixes[0]?.version}</span>
      {fixes.length > 1 && <Badge tone="info">+{fixes.length - 1}</Badge>}
    </span>
  );
}

/** The two priority numbers stay off the table (D13); they are on hover and in the drawer. */
export function priorityTitle(e: PostureEntry): string {
  const r = e.residual_priority ?? 0;
  const eff = e.effective_priority ?? 0;
  return `priority ${r.toFixed(1)} after decisions (${eff.toFixed(1)} before), base ${e.base_score ?? "—"}`;
}

export const isSuppressed = (e: PostureEntry) => !!e.has_position && ["not_affected", "accepted_risk"].includes(e.stance ?? "");
export const isCleared = (c: Component) => c.verdict_state === "cleared_vendor_fix";
/** The machine's "handled": every carrier copy provably carries its vendor fix. */
export const allCarriersCleared = (e: PostureEntry) => {
  const carriers = (e.components ?? []).filter((c) => c.claim_class !== "scope");
  return carriers.length > 0 && carriers.every(isCleared);
};
