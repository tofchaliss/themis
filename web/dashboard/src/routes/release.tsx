// Release posture (EDR-GUI-02 G2, D13): one row per CVE, its other releases in a dropdown under
// the row, and a click on the CVE or the row opens the read-only drawer. Blast, Base, Band and
// the two-number priority column are gone; the list is still sorted by priority, which is on
// hover and in the drawer.
import { Fragment, useMemo, useState, type KeyboardEvent } from "react";
import { ArrowUpRight, ChevronDown, ChevronRight, Search } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { BANDS, bandSlices } from "@/components/bands";
import {
  BandBadge,
  FixCell,
  PackageCell,
  SlaCell,
  StanceBadge,
  allCarriersCleared,
  isSuppressed,
  packageSummary,
  priorityTitle,
} from "@/components/finding-bits";
import { FindingDrawer } from "@/components/finding-drawer";
import { Empty, ErrorPanel } from "@/components/states";
import { useCveReleases, usePosture, useProject, useRelease, type PostureEntry } from "@/lib/queries";
import { classicHref, releaseHash } from "@/lib/router";
import { cn } from "@/lib/utils";

function Tile({ value, label, note, tone }: { value: number; label: string; note: string; tone?: string }) {
  return (
    <Card className="px-3.5 py-3">
      <div className="font-medium text-ink-2">{label}</div>
      <div className={cn("mt-1 text-2xl font-semibold tabular-nums", tone)}>{value}</div>
      <div className="text-xs text-muted">{note}</div>
    </Card>
  );
}

function BandBar({ posture }: { posture: PostureEntry[] }) {
  const slices = bandSlices(posture.map((p) => p.band));
  const total = posture.length;
  return (
    <div>
      <div className="flex h-3 overflow-hidden rounded-full bg-mono-bg" role="img" aria-label={slices.map((s) => `${s.label} ${s.n}`).join(", ")}>
        {slices.map((s) => (
          <div key={s.id} style={{ width: `${(100 * s.n) / total}%`, background: s.color }} title={`${s.label}: ${s.n}`} />
        ))}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-2">
        {slices.map((s) => (
          <span key={s.id} className="inline-flex items-center gap-1.5">
            <i className="size-2 rounded-full" style={{ background: s.color }} />
            {s.label} <b className="text-ink tabular-nums">{s.n}</b>
          </span>
        ))}
      </div>
    </div>
  );
}

/** The dropdown under a CVE row: every release the CVE is filed under (D13). */
function ReleasesDropdown({ entry, releaseId }: { entry: PostureEntry; releaseId: string }) {
  const q = useCveReleases(entry.faultline_id, true);
  if (q.isPending) return <Skeleton className="m-3 h-4 w-1/3" />;
  if (q.isError) return <ErrorPanel error={q.error} />;
  const rows = [...(q.data ?? [])].sort((a, b) => `${a.project} ${a.version}`.localeCompare(`${b.project} ${b.version}`));
  if (!rows.length) return <p className="p-3 text-muted">Knowledge lists no releases for this CVE.</p>;
  return (
    <table className="w-full text-left">
      <thead className="text-xs text-ink-2">
        <tr>
          <th className="py-1.5 pr-3 pl-10 font-medium">Release</th>
          <th className="py-1.5 pr-3 font-medium">Decision</th>
          <th className="py-1.5 pr-3 font-medium">Package</th>
          <th className="py-1.5 pr-3 font-medium">Fix</th>
          <th className="py-1.5 pr-3 font-medium">Next SLA</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.releaseId} className="border-t border-line">
            <td className="py-1.5 pr-3 pl-10">
              {r.releaseId === releaseId ? (
                <span className="font-medium">
                  {r.project} v{r.version} <Badge tone="accent">this release</Badge>
                </span>
              ) : (
                <a className="font-medium text-accent" href={releaseHash(r.releaseId, r.version)}>
                  {r.project || "release"} v{r.version || r.releaseId.slice(0, 8)}
                </a>
              )}
            </td>
            <td className="py-1.5 pr-3">{r.entry ? <StanceBadge stance={r.entry.stance} decided={r.entry.has_position} /> : <span className="text-muted">—</span>}</td>
            <td className="py-1.5 pr-3">{r.entry ? <PackageCell components={r.entry.components} /> : "—"}</td>
            <td className="py-1.5 pr-3">{r.entry ? <FixCell entry={r.entry} /> : "—"}</td>
            <td className="py-1.5 pr-3">{r.entry ? <SlaCell sla={r.entry.sla} /> : "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

type Filter = "all" | "open" | "breached";

export function Release({ id, version: hashVersion }: { id: string; version: string }) {
  const posture = usePosture(id);
  const release = useRelease(id);
  const project = useProject(release.data?.project_id);
  const version = release.data?.version || hashVersion;

  const [filter, setFilter] = useState<Filter>("all");
  const [text, setText] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [drawer, setDrawer] = useState<PostureEntry | null>(null);

  const all = useMemo(
    () =>
      [...(posture.data ?? [])].sort(
        (a, b) => (b.residual_priority ?? 0) - (a.residual_priority ?? 0) || (b.effective_priority ?? 0) - (a.effective_priority ?? 0),
      ),
    [posture.data],
  );
  const breached = all.filter((p) => p.sla?.state === "breached");
  const needle = text.trim().toLowerCase();
  const rows = all
    .filter((p) => (filter === "open" ? !p.has_position : filter === "breached" ? p.sla?.state === "breached" : true))
    .filter((p) => !needle || (p.cve ?? "").toLowerCase().includes(needle) || (p.components ?? []).some((c) => (c.name ?? "").toLowerCase().includes(needle)));

  const toggle = (fid: string) =>
    setExpanded((s) => {
      const n = new Set(s);
      if (n.has(fid)) n.delete(fid);
      else n.add(fid);
      return n;
    });
  const onRowKey = (e: KeyboardEvent, p: PostureEntry) => {
    if (e.key === "Enter") setDrawer(p);
  };

  const oldPage = classicHref(releaseHash(id, version));

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h1 className="text-lg font-semibold">
          {project.data?.name ? `${project.data.name} ` : ""}
          {version ? `v${version}` : "Release"}
        </h1>
        <a className="inline-flex items-center gap-1 text-xs text-ink-2 hover:text-ink" href={oldPage}>
          Scans, remediation plan, VEX and publications: in the old GUI
          <ArrowUpRight className="size-3.5" aria-hidden />
        </a>
      </div>

      {posture.isError ? (
        <ErrorPanel error={posture.error} />
      ) : posture.isPending ? (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
          {BANDS.map((b) => (
            <Skeleton key={b.id} className="h-20" />
          ))}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
            <Tile value={all.length} label="CVEs" note="Findings on this release" />
            <Tile value={all.filter((p) => !p.has_position).length} label="Open" note="no decision yet" />
            <Tile value={all.filter(isSuppressed).length} label="Suppressed" note="not affected / accepted, kept" />
            <Tile value={all.filter(allCarriersCleared).length} label="Cleared" note="vendor fix proven on every copy" />
            <Tile value={breached.length} label="SLA breached" note="past the days to fix" tone={breached.length ? "text-crit" : undefined} />
          </div>

          {all.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Severity</CardTitle>
                <CardDescription>Knowledge's exploitability band: critical means CVSS 9 or more and listed in KEV.</CardDescription>
              </CardHeader>
              <CardContent>
                <BandBar posture={all} />
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
              <div>
                <CardTitle>Vulnerabilities</CardTitle>
                <CardDescription>One row per CVE, most urgent first. The arrow lists every release with this CVE; the row opens the details.</CardDescription>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative">
                  <Search className="pointer-events-none absolute top-1/2 left-2 size-3.5 -translate-y-1/2 text-muted" aria-hidden />
                  <Input aria-label="Filter by CVE or package" placeholder="CVE or package" className="w-52 pl-7" value={text} onChange={(e) => setText(e.target.value)} />
                </div>
                <div role="radiogroup" aria-label="Show" className="flex gap-0.5 rounded-lg border border-line p-0.5">
                  {(
                    [
                      ["all", `All (${all.length})`],
                      ["open", "Open"],
                      ["breached", `SLA breached (${breached.length})`],
                    ] as const
                  ).map(([f, label]) => (
                    <button
                      key={f}
                      type="button"
                      role="radio"
                      aria-checked={filter === f}
                      onClick={() => setFilter(f)}
                      className={cn("rounded-md px-2.5 py-1 text-xs font-medium text-ink-2 hover:text-ink", filter === f && "bg-accent text-on-accent hover:text-on-accent")}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
            </CardHeader>
            <CardContent className="overflow-x-auto px-0">
              {all.length === 0 ? (
                <Empty title="No findings">Either nothing correlates yet, or this release is clean.</Empty>
              ) : rows.length === 0 ? (
                <Empty title="Nothing matches">Change the filter or the search.</Empty>
              ) : (
                <table className="w-full min-w-[820px] text-left">
                  <thead className="border-y border-line text-xs text-ink-2">
                    <tr>
                      <th className="w-8" aria-label="Releases" />
                      <th className="py-2 pr-3 font-medium">CVE</th>
                      <th className="py-2 pr-3 font-medium">Severity</th>
                      <th className="py-2 pr-3 text-right font-medium">Score</th>
                      <th className="py-2 pr-3 font-medium">Package</th>
                      <th className="py-2 pr-3 font-medium">Decision</th>
                      <th className="py-2 pr-3 font-medium">Fix</th>
                      <th className="py-2 pr-3 font-medium">Next SLA</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((p) => {
                      const fid = p.finding_id ?? p.cve ?? "";
                      const isOpen = expanded.has(fid);
                      return (
                        <Fragment key={fid}>
                          <tr
                            className="cursor-pointer border-b border-line hover:bg-hover"
                            onClick={() => setDrawer(p)}
                            onKeyDown={(e) => onRowKey(e, p)}
                            tabIndex={0}
                            title={priorityTitle(p)}
                            aria-label={`${p.cve}, ${packageSummary(p.components).name}`}
                          >
                            <td className="pl-2">
                              <button
                                type="button"
                                className="rounded p-1 text-ink-2 hover:bg-mono-bg hover:text-ink"
                                aria-expanded={isOpen}
                                aria-label={`${isOpen ? "Hide" : "Show"} releases with ${p.cve}`}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  toggle(fid);
                                }}
                              >
                                {isOpen ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
                              </button>
                            </td>
                            <td className="py-2 pr-3 font-mono text-xs font-medium">
                              {p.cve}
                              {p.disposition_stale && (
                                <Badge tone="warn" className="ml-1.5" title={p.disposition_stale.reason}>
                                  re-surfaced
                                </Badge>
                              )}
                            </td>
                            <td className="py-2 pr-3">
                              <BandBadge band={p.band} />
                            </td>
                            <td className="py-2 pr-3 text-right tabular-nums">{p.base_score ?? "—"}</td>
                            <td className="py-2 pr-3">
                              <PackageCell components={p.components} />
                            </td>
                            <td className="py-2 pr-3">
                              <StanceBadge stance={p.stance} decided={p.has_position} />
                            </td>
                            <td className="py-2 pr-3">
                              <FixCell entry={p} />
                            </td>
                            <td className="py-2 pr-3">
                              <SlaCell sla={p.sla} />
                            </td>
                          </tr>
                          {isOpen && (
                            <tr className="border-b border-line bg-page/60">
                              <td colSpan={8}>
                                <ReleasesDropdown entry={p} releaseId={id} />
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </CardContent>
          </Card>
          <div>
            <Button variant="outline" asChild>
              <a href={oldPage}>
                Open this release in the old GUI
                <ArrowUpRight />
              </a>
            </Button>
          </div>
        </>
      )}
      <FindingDrawer entry={drawer} releaseId={id} version={version} onClose={() => setDrawer(null)} />
    </div>
  );
}
