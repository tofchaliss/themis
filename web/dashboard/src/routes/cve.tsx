// One CVE's card (EDR-GUI-02 G4): what Knowledge holds for it, the source ratings, and the
// releases it is filed under. Read only: decisions live on each release's Finding.
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Empty, ErrorPanel } from "@/components/states";
import { useCard, useCardRatings, useCardReleases, useProduct, useProject, useRelease, type SourceRatings } from "@/lib/queries";
import { releaseHash } from "@/lib/router";

function Row({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[150px_1fr] gap-2 border-b border-line py-2 last:border-0">
      <dt className="text-ink-2">{k}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  );
}

const None = ({ children = "none" }: { children?: ReactNode }) => <span className="text-muted">{children}</span>;

/** "Product / Project / vVersion" through the Registry's name chain. Each hop is optional: a
 * missing name leaves the id in place instead of failing the line. */
function ReleaseLine({ id }: { id: string }) {
  const rel = useRelease(id);
  const proj = useProject(rel.data?.project_id);
  const prod = useProduct(proj.data?.product_id);
  const parts = [prod.data?.name, proj.data?.name, rel.data?.version ? `v${rel.data.version}` : ""].filter(Boolean);
  return (
    <li className="py-0.5">
      <a className="text-accent" href={releaseHash(id, rel.data?.version)}>
        {parts.length ? parts.join(" / ") : <span className="font-mono text-xs">{id}</span>}
      </a>
    </li>
  );
}

/** The source ratings, one row per assessment (copies of the same assessment are grouped). */
function Ratings({ r }: { r: SourceRatings }) {
  if (!r.ratings.length) return <None>no source rating recorded</None>;
  const groups = new Map<string, SourceRatings["ratings"]>();
  for (const x of r.ratings) {
    const key = x.identity?.key ?? x.id;
    groups.set(key, [...(groups.get(key) ?? []), x]);
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead className="text-ink-2">
          <tr>
            <th className="py-1 pr-3 font-medium">Assessor</th>
            <th className="py-1 pr-3 font-medium">Rating</th>
            <th className="py-1 pr-3 font-medium">Seen in</th>
            <th className="py-1 pr-3 font-medium">Status</th>
          </tr>
        </thead>
        <tbody>
          {[...groups.entries()].map(([key, g]) => {
            const x = g[0] as SourceRatings["ratings"][number];
            const v = x.validation;
            return (
              <tr key={key} className="border-t border-line align-top">
                <td className="py-1.5 pr-3">
                  {x.assessor_key || x.assessor} {x.nvd_type && <Badge tone="info">{x.nvd_type}</Badge>}
                </td>
                <td className="py-1.5 pr-3">
                  CVSS {x.cvss_version} <span className="font-mono">{x.vector}</span>
                  {typeof v?.base_score === "number" && <b className="ml-1">{v.base_score.toFixed(1)}</b>}
                  {v?.result && v.result !== "valid" && (
                    <Badge tone="warn" className="ml-1">
                      {v.result.replace(/_/g, " ")}
                    </Badge>
                  )}
                </td>
                <td className="py-1.5 pr-3">
                  {g.map((y) => (
                    <div key={y.id}>{[y.publisher || y.source, y.feed].filter(Boolean).join(" via ")}</div>
                  ))}
                </td>
                <td className="py-1.5 pr-3">
                  {g.map((y) => (
                    <div key={y.id}>{y.status}</div>
                  ))}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function Cve({ cve }: { cve: string }) {
  const card = useCard(cve);
  const releases = useCardReleases(card.data?.id);
  const ratings = useCardRatings(card.data?.id);

  if (card.isError) return <ErrorPanel error={card.error} />;
  if (card.isPending) return <Skeleton className="h-40" />;
  if (!card.data) return <Empty title={`No card for ${cve}`}>Knowledge holds nothing for this CVE: no component here carries it, and nobody gathered it.</Empty>;
  const c = card.data;
  const v = c.view ?? {};
  const ranges = v.affected_range_statements?.length
    ? v.affected_range_statements.map((r) => [r.ecosystem, r.package, r.range].filter(Boolean).join(" "))
    : (v.affected_ranges ?? []);

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <span className="font-mono">{c.cve}</span> {c.stage && <Badge>{c.stage}</Badge>}
          </CardTitle>
          <CardDescription>
            {v.summary || "No stored summary yet; the next enrichment sweep fills it."}
            {v.summary_source && <span className="text-muted"> (from {v.summary_source})</span>}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <dl>
            <Row k="Severity">
              {v.severity || "unknown"}
              {typeof v.cvss_score === "number" && v.cvss_score > 0 ? ` · CVSS ${v.cvss_score.toFixed(1)}` : ""}
              {v.cvss_vector && <span className="ml-1 font-mono text-xs">{v.cvss_vector}</span>}
              {v.severity_source && <span className="text-muted"> (from {v.severity_source})</span>}
            </Row>
            <Row k="Exploit signals">
              <span className="inline-flex flex-wrap items-center gap-1">
                {v.kev && <Badge tone="crit">KEV</Badge>}
                {v.exploit_public && <Badge tone="warn">public exploit</Badge>}
                {typeof v.epss === "number" && <span>EPSS {(v.epss * 100).toFixed(1)}%</span>}
                {!v.kev && !v.exploit_public && typeof v.epss !== "number" && <None>none recorded</None>}
              </span>
            </Row>
            <Row k="Affected ranges">{ranges.length ? <span className="font-mono text-xs">{ranges.join(", ")}</span> : <None />}</Row>
            <Row k="Published fixes">{v.fixed_versions?.length ? <span className="font-mono text-xs">{v.fixed_versions.join(", ")}</span> : <None />}</Row>
            <Row k="Filed under">
              {releases.isPending ? (
                <Skeleton className="h-4 w-40" />
              ) : releases.isError ? (
                <None>could not be read</None>
              ) : releases.data.length ? (
                <ul>
                  {releases.data.map((id) => (
                    <ReleaseLine key={id} id={id} />
                  ))}
                </ul>
              ) : (
                <None>no release in the estate</None>
              )}
            </Row>
            <Row k="Source proposals">{c.proposals?.length ?? 0}</Row>
            <Row k="Source ratings">
              {ratings.isPending ? <Skeleton className="h-4 w-40" /> : ratings.data ? <Ratings r={ratings.data} /> : <None>unavailable (Knowledge did not answer)</None>}
            </Row>
          </dl>
        </CardContent>
      </Card>
    </div>
  );
}
