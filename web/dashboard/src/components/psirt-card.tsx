// The PSIRT early alert on the Overview (EDR-PSIRT-01 P3): the first bucket BEFORE the Themis
// engine. CVEs the world published recently with a critical or high ORIGINAL (source) score,
// each with the product components it MAY hit by name. No Themis score anywhere (owner B):
// the team assesses after the alert, and the engine decides.
import { useMemo, useState } from "react";
import { AlertTriangle, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select } from "@/components/ui/native-select";
import { Skeleton } from "@/components/ui/skeleton";
import { SeverityCell } from "@/components/finding-bits";
import { Paged } from "@/components/pager";
import { Empty, ErrorPanel } from "@/components/states";
import { ago, when } from "@/components/when";
import { usePSIRTAlerts, type FeedHealth, type PSIRTAlert } from "@/lib/queries";
import { asArray } from "@/lib/utils";

export const PSIRT_WINDOWS = [1, 7, 30] as const;
type Floor = "critical" | "high";
type Tab = "products" | "world";

const cveHash = (cve: string) => `#/cve/${encodeURIComponent(cve)}`;
const nvdURL = (cve: string) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`;

/** The sources that are behind: stale or degraded. Informational feeds (a quiet OSV distro)
 * are never "behind" (EDR-PSIRT-01, discovery health beside the alert). */
export function sourcesBehind(feeds: FeedHealth | null | undefined): string[] {
  return asArray<{ source?: string; status?: string }>(feeds?.feeds)
    .filter((f) => f.status === "stale" || f.status === "degraded")
    .map((f) => f.source ?? "unnamed source")
    .sort();
}

function HealthStrip({ feeds, feedsError }: { feeds: FeedHealth | null | undefined; feedsError: boolean }) {
  if (feedsError) {
    return (
      <div role="status" className="flex items-center gap-2 rounded-lg border border-warn/50 bg-warn/10 px-3 py-1.5 text-xs">
        <AlertTriangle className="size-3.5 text-warn" aria-hidden />
        Source health could not be read, so this list may be missing issues.
      </div>
    );
  }
  if (!feeds) return null;
  const behind = sourcesBehind(feeds);
  if (!behind.length) {
    return (
      <div role="status" className="rounded-lg border border-line px-3 py-1.5 text-xs text-ink-2">
        Sources: all current.
      </div>
    );
  }
  return (
    <div role="status" className="flex items-center gap-2 rounded-lg border border-warn/50 bg-warn/10 px-3 py-1.5 text-xs">
      <AlertTriangle className="size-3.5 text-warn" aria-hidden />
      {behind.length} {behind.length === 1 ? "source is" : "sources are"} behind: {behind.join(", ")}.
    </div>
  );
}

function IssueType({ a }: { a: PSIRTAlert }) {
  const cwes = asArray<string>(a.cwes);
  if (!a.issue_type && !cwes.length) return <span className="text-xs text-muted">not stated</span>;
  return (
    <span className="flex flex-col">
      <span>{a.issue_type}</span>
      {cwes.length > 0 && <span className="font-mono text-[11px] text-muted">{cwes.join(", ")}</span>}
    </span>
  );
}

function Components({ a, product, estateUnavailable }: { a: PSIRTAlert; product: string; estateUnavailable: boolean }) {
  const matches = asArray<PSIRTAlert["matches"][number]>(a.matches).filter((m) => !product || m.product_id === product);
  if (!matches.length) {
    return <span className="text-xs text-muted">{estateUnavailable ? "inventory not read" : "not known"}</span>;
  }
  return (
    <ul className="flex flex-col gap-0.5">
      {matches.map((m) => (
        <li key={`${m.product_id}/${m.component}`} title={`matched on the affected name "${m.matched_on}" (name only, version ignored)`}>
          <span className="font-medium">{m.product_name || m.product_id}</span> · <span className="font-mono text-xs">{m.component}</span>
        </li>
      ))}
    </ul>
  );
}

function Table({ rows, product, estateUnavailable }: { rows: PSIRTAlert[]; product: string; estateUnavailable: boolean }) {
  return (
    <Paged rows={rows}>
      {(page) => (
        <table className="w-full text-left text-[13px]">
          <thead className="text-xs text-ink-2">
            <tr className="border-b border-line">
              <th className="py-2 pr-3 pl-4 font-medium">Original score</th>
              <th className="py-2 pr-3 font-medium">CVE</th>
              <th className="py-2 pr-3 font-medium">Issue type</th>
              <th className="py-2 pr-3 font-medium">Published / updated</th>
              <th className="py-2 pr-3 font-medium">Product · component</th>
              <th className="py-2 pr-3 font-medium">In Themis</th>
            </tr>
          </thead>
          <tbody>
            {page.map((a) => (
              <tr key={a.cve} className="border-b border-line align-top last:border-0">
                <td className="py-2 pr-3 pl-4" title={`from ${a.score_source}`}>
                  <SeverityCell severity={a.original_severity} score={a.original_score} />
                  <span className="block text-[11px] text-muted">{a.score_source}</span>
                </td>
                <td className="py-2 pr-3">
                  <a className="font-mono text-xs font-medium text-accent" href={nvdURL(a.cve)} target="_blank" rel="noreferrer" title={a.summary}>
                    {a.cve}
                  </a>
                </td>
                <td className="py-2 pr-3">
                  <IssueType a={a} />
                </td>
                <td className="py-2 pr-3 whitespace-nowrap">
                  <span className="block" title={when(a.published)}>
                    {ago(a.published)}
                  </span>
                  {a.modified && a.modified !== a.published && (
                    <span className="block text-[11px] text-muted" title={when(a.modified)}>
                      updated {ago(a.modified)}
                    </span>
                  )}
                </td>
                <td className="py-2 pr-3">
                  <Components a={a} product={product} estateUnavailable={estateUnavailable} />
                </td>
                <td className="py-2 pr-3">
                  {a.carded ? (
                    <a href={cveHash(a.cve)} className="text-accent">
                      in Themis
                    </a>
                  ) : (
                    <span className="text-xs text-muted">not yet</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Paged>
  );
}

export function PSIRTCard({ feeds, feedsError }: { feeds: FeedHealth | null | undefined; feedsError: boolean }) {
  const [days, setDays] = useState<number>(7);
  const [floor, setFloor] = useState<Floor>("high");
  const [tab, setTab] = useState<Tab>("products");
  const [product, setProduct] = useState("");
  const q = usePSIRTAlerts(days, floor);
  const alerts = useMemo(() => asArray<PSIRTAlert>(q.data?.alerts), [q.data]);
  const matched = useMemo(() => alerts.filter((a) => asArray(a.matches).length > 0), [alerts]);
  const products = useMemo(() => {
    const m = new Map<string, string>();
    for (const a of matched) for (const x of a.matches) m.set(x.product_id, x.product_name || x.product_id);
    return [...m.entries()].sort((a, b) => a[1].localeCompare(b[1]));
  }, [matched]);
  const pick = products.some(([id]) => id === product) ? product : "";
  const rows = tab === "world" ? alerts : matched.filter((a) => !pick || a.matches.some((m) => m.product_id === pick));
  const estateUnavailable = !!q.data?.estate_unavailable;
  const behind = sourcesBehind(feeds);
  const floorWord = floor === "critical" ? "critical" : "critical or high";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          <ShieldAlert className="size-4 text-crit" aria-hidden />
          PSIRT early alert
          <Badge title="read live from NVD and CVE.org when the page opens; nothing is stored">live, not stored</Badge>
        </CardTitle>
        <CardDescription className="max-w-prose">
          New CVEs the world published, by their original (source) score, and the product components they may hit by name. This comes before the
          Themis engine: the team assesses each alert, and a gather or a scan brings it into Themis.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <label className="sr-only" htmlFor="psirt-floor">
            Severity
          </label>
          <Select id="psirt-floor" className="w-auto" value={floor} onChange={(e) => setFloor(e.target.value as Floor)}>
            <option value="high">Critical and High</option>
            <option value="critical">Critical only</option>
          </Select>
          <span className="inline-flex gap-1" role="group" aria-label="Published within">
            {PSIRT_WINDOWS.map((d) => (
              <Button key={d} size="sm" variant={d === days ? "default" : "outline"} aria-pressed={d === days} onClick={() => setDays(d)}>
                {d === 1 ? "1 day" : `${d} days`}
              </Button>
            ))}
          </span>
          <span className="inline-flex gap-1" role="group" aria-label="Show">
            <Button
              size="sm"
              variant={tab === "products" ? "default" : "outline"}
              aria-pressed={tab === "products"}
              onClick={() => setTab("products")}
            >
              Our products{q.data ? ` (${matched.length})` : ""}
            </Button>
            <Button size="sm" variant={tab === "world" ? "default" : "outline"} aria-pressed={tab === "world"} onClick={() => setTab("world")}>
              All world{q.data ? ` (${alerts.length})` : ""}
            </Button>
          </span>
          {tab === "products" && products.length > 0 && (
            <>
              <label className="sr-only" htmlFor="psirt-product">
                Product
              </label>
              <Select id="psirt-product" className="w-auto" value={pick} onChange={(e) => setProduct(e.target.value)}>
                <option value="">All products</option>
                {products.map(([id, name]) => (
                  <option key={id} value={id}>
                    {name}
                  </option>
                ))}
              </Select>
            </>
          )}
        </div>

        <HealthStrip feeds={feeds} feedsError={feedsError} />
        {estateUnavailable && (
          <div role="alert" className="flex items-center gap-2 rounded-lg border border-warn/50 bg-warn/10 px-3 py-1.5 text-xs">
            <AlertTriangle className="size-3.5 text-warn" aria-hidden />
            The product inventory could not be read, so no row can say which product it hits. Use All world until it is back.
          </div>
        )}
        {!!q.data?.lookups_skipped && (
          <div className="text-xs text-ink-2">
            {q.data.lookups_skipped} new records were not checked at CVE.org this time (too many at once); they show as NVD gave them.
          </div>
        )}

        {q.isError ? (
          <ErrorPanel error={q.error} />
        ) : q.isPending ? (
          <Skeleton className="h-32 w-full" />
        ) : q.data === null ? (
          <Empty title="The alert is not available">This Knowledge node has no PSIRT alert read yet. Update it to the current build.</Empty>
        ) : rows.length === 0 ? (
          behind.length > 0 || feedsError ? (
            <Empty title={`No new issues, but ${behind.length || "some"} ${behind.length === 1 ? "source is" : "sources are"} behind`}>
              The list can be missing issues until the sources catch up.
            </Empty>
          ) : tab === "products" && estateUnavailable ? (
            <Empty title="Products could not be checked">See All world for every {floorWord} CVE.</Empty>
          ) : tab === "products" ? (
            <Empty title={`No ${floorWord} CVE in the last ${days === 1 ? "day" : `${days} days`} names one of our components`}>
              All world lists {alerts.length} {alerts.length === 1 ? "CVE" : "CVEs"} from the same window.
            </Empty>
          ) : (
            <Empty title={`No ${floorWord} CVE published in the last ${days === 1 ? "day" : `${days} days`}`} />
          )
        ) : (
          <Table rows={rows} product={tab === "products" ? pick : ""} estateUnavailable={estateUnavailable} />
        )}
      </CardContent>
    </Card>
  );
}
