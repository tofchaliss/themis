// One scanner report (EDR-GUI-02 G3): every claim the tool made, beside what the enterprise did
// with it. "Ingested the report" and "ingested most of the report" must never look alike: a
// claim with no Finding was skipped in translation, out of the correlated range, or vendor
// fixed. It is filtered, not lost; the stored report keeps it as the tool said it.
import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { BandBadge, ExpertSeverity, StanceBadge } from "@/components/finding-bits";
import { FindingDrawer } from "@/components/finding-drawer";
import { Empty, ErrorPanel } from "@/components/states";
import { useEvidenceFacts, usePosture, useScanReport, type PostureEntry, type ScanClaim } from "@/lib/queries";
import { releaseHash } from "@/lib/router";

function Count({ value, label, note }: { value: number; label: string; note: string }) {
  return (
    <div title={note} className="min-w-[72px]">
      <div className="text-xl leading-tight font-semibold tabular-nums">{value}</div>
      <div className="text-xs text-ink-2">{label}</div>
    </div>
  );
}

const claimed = (f: ScanClaim) => `${(f.severity ?? "").toLowerCase() || "—"}${f.cvss_score ? ` ${f.cvss_score}` : ""}`;
const comp = (f: ScanClaim) => `${f.component?.name ?? "?"}${f.component?.version ? `@${f.component.version}` : ""}`;

export function Scan({ evidenceId, releaseId, version }: { evidenceId: string; releaseId: string; version: string }) {
  const facts = useEvidenceFacts(evidenceId);
  const report = useScanReport(evidenceId);
  const posture = usePosture(releaseId);
  const [drawer, setDrawer] = useState<PostureEntry | null>(null);

  // One Finding per (release, CVE) however many tools asserted it, so the CVE is the key.
  const rows = useMemo(() => {
    const byCve = new Map((posture.data ?? []).map((p) => [p.cve, p]));
    return (report.data?.findings ?? [])
      .map((f) => ({ f, entry: f?.cve ? byCve.get(f.cve) : undefined }))
      .sort((a, b) => (b.entry?.residual_priority ?? -1) - (a.entry?.residual_priority ?? -1));
  }, [report.data, posture.data]);

  const back = releaseHash(releaseId, version);
  const err = report.error ?? posture.error;
  if (err) return <ErrorPanel error={err} />;
  if (report.isPending || posture.isPending) return <Skeleton className="h-40" />;
  if (!report.data) return <ErrorPanel error={new Error("This evidence document was not found.")} />;
  if (!report.data.findings) return <ErrorPanel error={new Error("This document is not a curated scanner report ({findings:[…]}), so there is nothing to join.")} />;

  const matched = rows.filter((r) => r.entry).length;
  const decided = rows.filter((r) => r.entry?.has_position).length;

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-baseline gap-2">
        <h1 className="text-lg font-semibold">Scan report</h1>
        {facts.data?.provenance_source && <Badge tone="accent">{facts.data.provenance_source}</Badge>}
        {facts.data?.filed_at && <Badge title={facts.data.filed_at}>filed {facts.data.filed_at.slice(0, 10)}</Badge>}
      </div>
      <Card className="flex flex-wrap gap-x-6 gap-y-2 px-4 py-3">
        <Count value={rows.length} label="Asserted" note="claims in this report" />
        <Count value={matched} label="Matched" note="have a Finding on this release" />
        <Count value={decided} label="Decided" note="carry a decision" />
        <Count value={rows.length - matched} label="No Finding" note="filtered at ingestion; the claim stays in this report" />
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Every claim</CardTitle>
          <CardDescription>What the tool said on the left, what Themis did with it on the right. A row with a Finding opens it.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto px-0">
          {!rows.length ? (
            <Empty title="Empty report">This document asserts no findings.</Empty>
          ) : (
            <table className="w-full min-w-[820px] text-left">
              <thead className="border-y border-line text-xs text-ink-2">
                <tr>
                  <th className="py-2 pr-3 pl-4 font-medium">CVE</th>
                  <th className="py-2 pr-3 font-medium">Claimed severity</th>
                  <th className="py-2 pr-3 font-medium">Component as claimed</th>
                  <th className="py-2 pr-3 font-medium">Claimed fix</th>
                  <th className="py-2 pr-3 font-medium">Expert severity</th>
                  <th className="py-2 pr-3 font-medium">Decision</th>
                </tr>
              </thead>
              <tbody>
                {rows.map(({ f, entry }, i) => (
                  <tr
                    key={`${f?.cve ?? "?"}-${i}`}
                    className={entry ? "cursor-pointer border-b border-line hover:bg-hover" : "border-b border-line text-ink-2"}
                    onClick={entry ? () => setDrawer(entry) : undefined}
                    onKeyDown={entry ? (e) => e.key === "Enter" && setDrawer(entry) : undefined}
                    tabIndex={entry ? 0 : undefined}
                    aria-label={`${f?.cve ?? "?"} claim`}
                  >
                    <td className="py-2 pr-3 pl-4 font-mono text-xs font-medium">
                      {f?.cve ?? "?"}
                      {entry && (
                        <span className="ml-1.5 font-sans">
                          <BandBadge band={entry.band} />
                        </span>
                      )}
                    </td>
                    <td className="py-2 pr-3">{claimed(f ?? {})}</td>
                    <td className="py-2 pr-3 font-mono text-xs">{comp(f ?? {})}</td>
                    <td className="py-2 pr-3 font-mono text-xs">{f?.fixed?.[0] ?? "—"}</td>
                    {entry ? (
                      <>
                        <td className="py-2 pr-3">
                          <ExpertSeverity entry={entry} />
                        </td>
                        <td className="py-2 pr-3">
                          <StanceBadge stance={entry.stance} decided={entry.has_position} />
                        </td>
                      </>
                    ) : (
                      <td colSpan={2} className="py-2 pr-3">
                        <Badge tone="info" title="skipped in translation, out of the correlated range, or vendor fixed; the claim is kept as said in this report">
                          no Finding, filtered at ingestion
                        </Badge>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="px-4 pt-3">
            <a className="text-accent" href={back}>
              ← Back to the release
            </a>
          </p>
        </CardContent>
      </Card>
      <FindingDrawer entry={drawer} releaseId={releaseId} version={version} onClose={() => setDrawer(null)} />
    </div>
  );
}
