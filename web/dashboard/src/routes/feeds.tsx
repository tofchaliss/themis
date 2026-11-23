// Feed health (EDR-GUI-02 G5): the inbound enrichment feeds, and the outbound webhook
// destinations beside them (EDR-REMEDIATION-01 D4).
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Empty, ErrorPanel } from "@/components/states";
import { ago, when } from "@/components/when";
import { apiGet } from "@/lib/api";
import { useFeeds } from "@/lib/queries";
import { asArray } from "@/lib/utils";
import type { components as Communication } from "@/types/api/communication";

type Hook = Communication["schemas"]["WebhookHealth"];

const feedTone = (s?: string) => (s === "healthy" ? "good" : s === "stale" ? "crit" : "warn");
const hookTone = (s: string) => (s === "active" ? "good" : s === "inactive_permanent" ? "crit" : "warn");

export function Feeds() {
  const feeds = useFeeds();
  // Delivery off, or an older node: no webhook card at all, never an error.
  const hooks = useQuery({ queryKey: ["webhook-health"], queryFn: async () => asArray<Hook>(await apiGet("communication", "/webhook-health")), retry: false });
  if (feeds.isError) return <ErrorPanel error={feeds.error} />;
  if (feeds.isPending) return <Skeleton className="h-40" />;
  const entries = feeds.data?.feeds ?? [];
  return (
    <div className="flex flex-col gap-4">
      {feeds.data?.signals_stale && (
        <div role="alert" className="rounded-lg border border-crit/40 bg-crit/10 p-3">
          Signals are STALE: a tier-1 feed has gone quiet, so exploitability data may be out of date.
        </div>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Enrichment feeds</CardTitle>
          <CardDescription>A stale tier-1 feed blocks trust in signals; a tier-2 failure degrades quietly. OSV runs on every upload; the rest are opt-in.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto px-0">
          {entries.length ? (
            <table className="w-full text-left">
              <thead className="border-y border-line text-xs text-ink-2">
                <tr>
                  <th className="py-2 pr-3 pl-4 font-medium">Source</th>
                  <th className="py-2 pr-3 text-right font-medium">Tier</th>
                  <th className="py-2 pr-3 font-medium">Status</th>
                  <th className="py-2 pr-3 text-right font-medium">Failures in a row</th>
                  <th className="py-2 pr-3 font-medium">Last success</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((f) => (
                  <tr key={f.source} className="border-b border-line">
                    <td className="py-2 pr-3 pl-4 font-medium">{f.source}</td>
                    <td className="py-2 pr-3 text-right">{f.tier}</td>
                    <td className="py-2 pr-3">
                      <Badge tone={feedTone(f.status)}>{f.status}</Badge>
                    </td>
                    <td className="py-2 pr-3 text-right tabular-nums">{f.consecutive_failures ?? 0}</td>
                    <td className="py-2 pr-3" title={f.last_success_at ?? ""}>
                      {ago(f.last_success_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty title="No feed activity recorded">Feeds record health on every poll; enable one and it appears here.</Empty>
          )}
        </CardContent>
      </Card>
      {hooks.data && (
        <Card>
          <CardHeader>
            <CardTitle>Outbound webhooks</CardTitle>
            <CardDescription>
              One-way posts to Slack, Teams or another receiver, by audience name. A paused destination is tried again after its pause; a disabled one
              waits for <span className="font-mono">deliveryctl webhook-enable</span>.
            </CardDescription>
          </CardHeader>
          <CardContent className="overflow-x-auto px-0">
            {hooks.data.length ? (
              <table className="w-full min-w-[720px] text-left">
                <thead className="border-y border-line text-xs text-ink-2">
                  <tr>
                    <th className="py-2 pr-3 pl-4 font-medium">Destination</th>
                    <th className="py-2 pr-3 font-medium">Status</th>
                    <th className="py-2 pr-3 text-right font-medium">Failures in a row</th>
                    <th className="py-2 pr-3 font-medium">Last success</th>
                    <th className="py-2 pr-3 font-medium">Paused until</th>
                    <th className="py-2 pr-3 font-medium">Last error</th>
                  </tr>
                </thead>
                <tbody>
                  {hooks.data.map((h) => (
                    <tr key={h.destination} className="border-b border-line">
                      <td className="py-2 pr-3 pl-4 font-medium">{h.destination}</td>
                      <td className="py-2 pr-3">
                        <Badge tone={hookTone(h.state)}>{h.state}</Badge>
                      </td>
                      <td className="py-2 pr-3 text-right tabular-nums">{h.consecutive_failures}</td>
                      <td className="py-2 pr-3">{ago(h.last_success_at)}</td>
                      <td className="py-2 pr-3">{when(h.paused_until)}</td>
                      <td className="py-2 pr-3 text-xs text-ink-2">{h.last_error}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Empty title="No webhook sent yet">A destination appears here after its first post.</Empty>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
