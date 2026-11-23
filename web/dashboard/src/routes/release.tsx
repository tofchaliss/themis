// Release posture (EDR-GUI-02 G2, D13): one row per CVE, its other releases in a dropdown under
// the row, and a click on the CVE or the row opens the read-only drawer. Blast, Base, Band and
// the two-number priority column are gone; the list is still sorted by priority, which is on
// hover and in the drawer. D13 amendment (2026-11-23): "Score" is replaced by Original severity
// (the source's CVSS) and Expert severity (Themis's after the assessment), the exploitability
// band rides beside the CVE, and the summary is one small card with two donuts.
import { Fragment, useMemo, useState, type KeyboardEvent } from "react";
import { ArrowUpRight, ChevronDown, ChevronRight, Search } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Count } from "@/components/count";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { bandSlices, severitySlices } from "@/components/bands";
import { Donut } from "@/components/donut";
import {
  BandBadge,
  ExpertSeverity,
  FixCell,
  OriginalSeverity,
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
import { useCveReleases, useEvidence, usePosture, useProject, useRelease, useScanReport, useUploadOutcome, type PostureEntry, type UploadOutcome } from "@/lib/queries";
import { classicHref, releaseHash, scanHash } from "@/lib/router";
import { cn } from "@/lib/utils";

/** The release in one small card: the counts in a row, then two small donuts — the
 * exploitability band and the expert severity (D13 amendment: the tiles and the bar were
 * taking half the screen). */
function Summary({ all, breached }: { all: PostureEntry[]; breached: number }) {
  return (
    <Card className="flex flex-wrap items-center gap-x-8 gap-y-3 px-4 py-3">
      <div className="flex flex-wrap gap-x-6 gap-y-2">
        <Count value={all.length} label="CVEs" note="Findings on this release" />
        <Count value={all.filter((p) => !p.has_position).length} label="Open" note="no decision yet" />
        <Count value={all.filter(isSuppressed).length} label="Suppressed" note="not affected / accepted, kept" />
        <Count value={all.filter(allCarriersCleared).length} label="Cleared" note="vendor fix proven on every copy" />
        <Count value={breached} label="SLA breached" note="past the days to fix" tone={breached ? "text-crit" : undefined} />
      </div>
      {all.length > 0 && (
        <div className="flex flex-wrap gap-x-8 gap-y-3">
          <figure className="flex flex-col gap-1">
            <figcaption className="text-xs font-medium text-ink-2" title="Knowledge's band: critical means CVSS 9 or more and listed in KEV">
              Exploitability
            </figcaption>
            <Donut compact slices={bandSlices(all.map((p) => p.band))} total={all.length} />
          </figure>
          <figure className="flex flex-col gap-1">
            <figcaption className="text-xs font-medium text-ink-2" title="Themis's CVSS score after the assessment">
              Expert severity
            </figcaption>
            <Donut compact label="findings by expert severity" slices={severitySlices(all.map((p) => p.expert_severity))} total={all.length} />
          </figure>
        </div>
      )}
    </Card>
  );
}

/** D13: a person's decision is MANUAL, a rule's is AUTO; nothing else ever decides. */
function decidedBy(kind?: string) {
  if (!kind) return <span className="text-muted">—</span>;
  return kind === "human" ? <Badge>MANUAL</Badge> : <Badge tone="accent">AUTO</Badge>;
}

/** The dropdown under a CVE row: every release the CVE is filed under (D13). */
function ReleasesDropdown({ entry, releaseId }: { entry: PostureEntry; releaseId: string }) {
  const q = useCveReleases(entry.faultline_id, true);
  if (q.isPending) return <Skeleton className="m-3 h-4 w-1/3" />;
  if (q.isError) return <ErrorPanel error={q.error} />;
  const rows = [...(q.data ?? [])].sort((a, b) => `${a.project} ${a.version}`.localeCompare(`${b.project} ${b.version}`));
  if (!rows.length) return <p className="p-3 text-muted">Governance lists no releases for this CVE.</p>;
  return (
    <table className="w-full text-left">
      <thead className="text-xs text-ink-2">
        <tr>
          <th className="py-1.5 pr-3 pl-10 font-medium">Release</th>
          <th className="py-1.5 pr-3 font-medium">Decision</th>
          <th className="py-1.5 pr-3 font-medium">Decided by</th>
          <th className="py-1.5 pr-3 font-medium">Decided</th>
          <th className="py-1.5 pr-3 font-medium">Original severity</th>
          <th className="py-1.5 pr-3 font-medium">Expert severity</th>
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
            <td className="py-1.5 pr-3">
              <StanceBadge stance={r.entry.stance} decided={r.entry.has_position} />
            </td>
            <td className="py-1.5 pr-3">{decidedBy(r.entry.decided_by_kind)}</td>
            <td className="py-1.5 pr-3 font-mono text-xs">{r.entry.decided_at ? r.entry.decided_at.slice(0, 10) : "—"}</td>
            <td className="py-1.5 pr-3">
              <OriginalSeverity entry={r.entry} />
            </td>
            <td className="py-1.5 pr-3">
              <ExpertSeverity entry={r.entry} />
            </td>
            <td className="py-1.5 pr-3">
              <PackageCell components={r.entry.components} />
            </td>
            <td className="py-1.5 pr-3">
              <FixCell entry={r.entry} />
            </td>
            <td className="py-1.5 pr-3">
              <SlaCell sla={r.entry.sla} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/** What the latest SBOM changed (Governance's upload outcome). "No longer present" closes
 * nothing: those Findings stay open with their decisions until someone resolves them. */
function UploadOutcomeCard({ o }: { o: UploadOutcome }) {
  const cell = (n: number, label: string, cves?: string[], note?: string) => (
    <div className="min-w-[120px] flex-1">
      <div className="text-xl leading-tight font-semibold tabular-nums">{n}</div>
      <div className="text-xs text-ink-2">{label}</div>
      {note && <div className="text-xs text-muted">{note}</div>}
      {!!cves?.length && <div className="mt-1 font-mono text-[11px] break-words text-ink-2">{cves.join(", ")}</div>}
    </div>
  );
  return (
    <Card>
      <CardHeader>
        <CardTitle>What the latest SBOM changed</CardTitle>
        <CardDescription>
          SBOM <span className="font-mono">{o.sbom_id.slice(0, 16)}</span>, evaluated {o.evaluated_at.slice(0, 10)}
          {o.has_baseline ? ", against the SBOM filed before it" : ": the first SBOM of this release, so everything present is new"}. "No longer
          present" closes nothing: those findings stay open with their decisions.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-wrap gap-4">
        {cell(o.new, "New", o.new_cves)}
        {cell(o.reappeared, "Reappeared", o.reappeared_cves)}
        {cell(o.no_longer_present, "No longer present", o.no_longer_present_cves)}
        {cell(o.unchanged, "Unchanged", undefined, `${o.not_judged} not judged (in neither SBOM, or closed)`)}
      </CardContent>
    </Card>
  );
}

/** How many claims one report made: read from the stored document after the page shows. */
function ClaimCount({ id }: { id: string }) {
  const r = useScanReport(id);
  if (r.isPending) return <Skeleton className="ml-auto h-3 w-6" />;
  return <>{r.data?.findings ? r.data.findings.length : "?"}</>;
}

/** Each scanner report filed against the release. The stored document is the complete per-tool
 * record: match recording is first-wins, so only the document says what one tool claimed. */
function ScansCard({ releaseId, version }: { releaseId: string; version: string }) {
  const ev = useEvidence(releaseId);
  const scans = (ev.data ?? []).filter((e) => e.kind === "scanner-report");
  if (!scans.length) return null;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Scans</CardTitle>
        <CardDescription>Each scanner report filed against this release. Open one to see every claim beside what was decided.</CardDescription>
      </CardHeader>
      <CardContent className="overflow-x-auto px-0">
        <table className="w-full text-left">
          <thead className="border-y border-line text-xs text-ink-2">
            <tr>
              <th className="py-2 pr-3 pl-4 font-medium">Tool</th>
              <th className="py-2 pr-3 font-medium">Filed</th>
              <th className="py-2 pr-3 text-right font-medium">Claims</th>
              <th className="py-2 pr-3 font-medium">Evidence id</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id} className="border-b border-line">
                <td className="py-2 pr-3 pl-4">
                  <a className="font-medium text-accent" href={scanHash(s.id ?? "", releaseId, version)}>
                    {s.provenance_source || "scanner"}
                  </a>
                </td>
                <td className="py-2 pr-3 font-mono text-xs" title={s.filed_at}>
                  {(s.filed_at ?? "").slice(0, 10) || "—"}
                </td>
                <td className="py-2 pr-3 text-right tabular-nums">
                  <ClaimCount id={s.id ?? ""} />
                </td>
                <td className="py-2 pr-3 font-mono text-xs">{s.id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}

type Filter = "all" | "open" | "breached";

export function Release({ id, version: hashVersion }: { id: string; version: string }) {
  const posture = usePosture(id);
  const outcome = useUploadOutcome(id);
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
          Remediation plan, VEX and publications: in the old GUI
          <ArrowUpRight className="size-3.5" aria-hidden />
        </a>
      </div>

      {posture.isError ? (
        <ErrorPanel error={posture.error} />
      ) : posture.isPending ? (
        <Skeleton className="h-24" />
      ) : (
        <>
          <Summary all={all} breached={breached.length} />

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
                <table className="w-full min-w-[920px] text-left">
                  <thead className="border-y border-line text-xs text-ink-2">
                    <tr>
                      <th className="w-8" aria-label="Releases" />
                      <th className="py-2 pr-3 font-medium">CVE</th>
                      <th className="py-2 pr-3 font-medium" title="The source's own CVSS rating">
                        Original severity
                      </th>
                      <th className="py-2 pr-3 font-medium" title="Themis's CVSS score after the assessment">
                        Expert severity
                      </th>
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
                              <span className="ml-1.5 font-sans">
                                <BandBadge band={p.band} />
                              </span>
                              {p.disposition_stale && (
                                <Badge tone="warn" className="ml-1.5" title={p.disposition_stale.reason}>
                                  re-surfaced
                                </Badge>
                              )}
                            </td>
                            <td className="py-2 pr-3">
                              <OriginalSeverity entry={p} />
                            </td>
                            <td className="py-2 pr-3">
                              <ExpertSeverity entry={p} />
                            </td>
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
                              <td colSpan={9}>
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
          {outcome.data && <UploadOutcomeCard o={outcome.data} />}
          <ScansCard releaseId={id} version={version} />
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
