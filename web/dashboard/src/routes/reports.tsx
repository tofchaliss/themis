// Reports (EDR-GUI-02 G5, EDR-REMEDIATION-01 D6): remediation metrics, estate-wide and per product.
// Time to remediation (no longer in an evaluated SBOM, THEN decided by a person) and time to
// resolution are two measures and are never shown as one.
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Count } from "@/components/count";
import { Empty, ErrorPanel } from "@/components/states";
import { apiGet } from "@/lib/api";
import type { components as Governance } from "@/types/api/governance";

type Report = Governance["schemas"]["RemediationReport"];
type Metrics = Governance["schemas"]["RemediationMetrics"];
type Mean = Governance["schemas"]["MeanDays"];

const AGES = ["0-7", "8-30", "31-90", "over-90"];
const SEVS = ["critical", "high", "medium", "low", "unknown"];

function MeanCell({ m }: { m: Mean }) {
  return m.count ? (
    <>
      {m.mean_days.toFixed(1)} d <span className="text-xs text-muted">(n={m.count})</span>
    </>
  ) : (
    <span className="text-xs text-muted">no sample</span>
  );
}

function Share({ m }: { m: Metrics }) {
  return m.sla_applicable ? (
    <>
      {Math.round(m.within_sla_share * 100)}%{" "}
      <span className="text-xs text-muted">
        ({m.within_sla}/{m.sla_applicable})
      </span>
    </>
  ) : (
    <span className="text-xs text-muted">—</span>
  );
}

export function Reports() {
  const [draft, setDraft] = useState("");
  const [tag, setTag] = useState("");
  const q = tag ? `?tag=${encodeURIComponent(tag)}` : "";
  const rep = useQuery({ queryKey: ["remediation-metrics", tag], queryFn: () => apiGet<Report>("governance", `/metrics/remediation${q}`) });

  return (
    <div className="flex flex-col gap-4">
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          setTag(draft.trim().toLowerCase());
        }}
      >
        <Input aria-label="Only releases tagged" placeholder="tag, e.g. env:prod" className="w-56 font-mono" value={draft} onChange={(e) => setDraft(e.target.value)} />
        <Button type="submit" variant="outline">
          Apply
        </Button>
        <span className="text-xs text-ink-2">{tag ? `Every figure below, estate included, covers only releases tagged ${tag}.` : "Tags filter; they never change a priority."}</span>
      </form>
      {rep.isError ? (
        <ErrorPanel error={rep.error} />
      ) : rep.isPending ? (
        <Skeleton className="h-40" />
      ) : !rep.data ? (
        <Empty title="No metrics">This Governance node does not serve them yet.</Empty>
      ) : (
        <ReportView r={rep.data} q={q} />
      )}
    </div>
  );
}

function ReportView({ r, q }: { r: Report; q: string }) {
  const e = r.estate;
  const json = `/api/communication/reports/remediation-metrics?format=json${q ? `&${q.slice(1)}` : ""}`;
  return (
    <>
      <Card className="flex flex-wrap gap-x-8 gap-y-2 px-4 py-3">
        <Count value={e.open} label="Open findings" note="estate-wide" />
        <Count value={e.sla_applicable ? `${Math.round(e.within_sla_share * 100)}%` : "—"} label="Within SLA" note={`${e.within_sla} of ${e.sla_applicable} running clocks`} />
        <Count value={e.breached_now} label="Breached now" note="a breach changes no decision" tone={e.breached_now ? "text-crit" : undefined} />
        <Count value={e.time_to_decision.count ? e.time_to_decision.mean_days.toFixed(1) : "—"} label="Days to decision" note="creation to the first person's decision" />
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>By product</CardTitle>
          <CardDescription>
            Time to remediation counts a finding only when an evaluated SBOM stopped carrying it and a person decided afterwards; time to resolution
            is creation to a person resolving it.{" "}
            {r.products_unavailable && <b>Per-product figures are unavailable: the product list could not be read. </b>}
            {r.unattributed > 0 && `${r.unattributed} finding(s) sit on releases the product list does not include. `}
            <a className="text-accent" href={`/api/communication/reports/remediation-metrics${q}`} target="_blank" rel="noopener">
              Markdown report
            </a>{" "}
            ·{" "}
            <a className="text-accent" href={json} target="_blank" rel="noopener">
              JSON
            </a>
          </CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto px-0">
          <table className="w-full min-w-[760px] text-left">
            <thead className="border-y border-line text-xs text-ink-2">
              <tr>
                <th className="py-2 pr-3 pl-4 font-medium">Scope</th>
                <th className="py-2 pr-3 text-right font-medium">Open</th>
                <th className="py-2 pr-3 font-medium">Within SLA</th>
                <th className="py-2 pr-3 text-right font-medium">Breached</th>
                <th className="py-2 pr-3 font-medium">To decision</th>
                <th className="py-2 pr-3 font-medium">To remediation</th>
                <th className="py-2 pr-3 font-medium">To resolution</th>
              </tr>
            </thead>
            <tbody>
              {[e, ...r.products].map((m, i) => (
                <tr key={`${m.scope}-${i}`} className="border-b border-line">
                  <td className="py-2 pr-3 pl-4 font-medium">{m.scope || "Estate"}</td>
                  <td className="py-2 pr-3 text-right tabular-nums">{m.open}</td>
                  <td className="py-2 pr-3">
                    <Share m={m} />
                  </td>
                  <td className="py-2 pr-3 text-right tabular-nums">{m.breached_now}</td>
                  <td className="py-2 pr-3">
                    <MeanCell m={m.time_to_decision} />
                  </td>
                  <td className="py-2 pr-3">
                    <MeanCell m={m.time_to_remediation} />
                  </td>
                  <td className="py-2 pr-3">
                    <MeanCell m={m.time_to_resolution} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Open findings by age (estate)</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto px-0">
          <table className="w-full text-left">
            <thead className="border-y border-line text-xs text-ink-2">
              <tr>
                <th className="py-2 pr-3 pl-4 font-medium">Days open</th>
                {SEVS.map((s) => (
                  <th key={s} className="py-2 pr-3 text-right font-medium">
                    {s}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {AGES.map((a) => (
                <tr key={a} className="border-b border-line">
                  <td className="py-2 pr-3 pl-4">{a}</td>
                  {SEVS.map((s) => (
                    <td key={s} className="py-2 pr-3 text-right tabular-nums">
                      {e.open_by_age[a]?.[s] ?? 0}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </>
  );
}
