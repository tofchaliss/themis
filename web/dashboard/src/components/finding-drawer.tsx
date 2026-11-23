// The Finding drawer (EDR-GUI-02 G2): READ ONLY. Deciding happens on the full decision page
// (D14), which "Decide…" opens.
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Sheet } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { BandBadge, SlaCell, StanceBadge, isCleared } from "@/components/finding-bits";
import { ErrorPanel } from "@/components/states";
import { useAssessment, type Component, type PostureEntry } from "@/lib/queries";
import { classicHref, decideHash, releaseHash } from "@/lib/router";

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="border-b border-line px-5 py-4">
      <h3 className="mb-2 text-xs font-semibold tracking-wide text-ink-2 uppercase">{title}</h3>
      {children}
    </section>
  );
}

function Row({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-2 py-1">
      <dt className="text-ink-2">{k}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  );
}

const day = (iso?: string) => (iso ? iso.slice(0, 10) : "—");

function ComponentRow({ c }: { c: Component }) {
  return (
    <li className="flex flex-wrap items-center gap-1.5 py-1">
      <span className="font-mono text-xs">
        {c.name}
        {c.version ? ` ${c.version}` : ""}
      </span>
      {c.claim_class === "scope" && (
        <Badge tone="info" title="in the advisory's rebuild set; no evidence it carries the flaw">
          scope
        </Badge>
      )}
      {c.claim_class === "carrier" && <Badge title="evidence says this package carries the flaw">carrier</Badge>}
      {isCleared(c) && <Badge tone="accent">{c.verdict_grade === "inferred" ? "cleared, inferred" : "cleared, vendor fix"}</Badge>}
      {isCleared(c) && c.verdict_reason && <span className="w-full pl-2 text-xs text-muted">{c.verdict_reason}</span>}
    </li>
  );
}

export function FindingDrawer({
  entry,
  releaseId,
  version,
  onClose,
}: {
  entry: PostureEntry | null;
  releaseId: string;
  version: string;
  onClose: () => void;
}) {
  const a = useAssessment(entry?.finding_id);
  const k = a.data?.knowledge;
  const f = a.data?.finding;
  const pos = f?.current_position;
  const comps = f?.components ?? entry?.components ?? [];
  const open = comps.filter((c) => !isCleared(c));
  const cleared = comps.filter(isCleared);
  const oldRelease = classicHref(releaseHash(releaseId, version));

  return (
    <Sheet open={!!entry} onClose={onClose} labelledBy="drawer-title">
      {entry && (
        <>
          <header className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-4 pr-12">
            <h2 id="drawer-title" className="font-mono text-base font-semibold">
              {entry.cve}
            </h2>
            <BandBadge band={entry.band} />
            <StanceBadge stance={entry.stance} decided={entry.has_position} />
          </header>
          <div className="min-h-0 flex-1 overflow-auto">
            {a.isPending ? (
              <div className="space-y-2 p-5">
                <Skeleton className="h-4 w-3/4" />
                <Skeleton className="h-4 w-1/2" />
              </div>
            ) : a.isError ? (
              <div className="p-5">
                <ErrorPanel error={a.error} />
              </div>
            ) : (
              <>
                <Section title="What Knowledge knows">
                  {k?.summary && <p className="mb-2 leading-relaxed">{k.summary}</p>}
                  <dl>
                    <Row k="Severity">
                      {k?.severity || "unknown"}
                      {k?.cvss_score ? ` · CVSS ${k.cvss_score}` : ""}
                    </Row>
                    <Row k="Exploit signals">
                      <span className="inline-flex flex-wrap gap-1">
                        {k?.kev && <Badge tone="crit">KEV</Badge>}
                        {k?.exploit_public && <Badge tone="serious">public exploit</Badge>}
                        {typeof k?.epss === "number" && <Badge>EPSS {(k.epss * 100).toFixed(1)}%</Badge>}
                        {!k?.kev && !k?.exploit_public && typeof k?.epss !== "number" && <span className="text-muted">none recorded</span>}
                      </span>
                    </Row>
                    <Row k="Fixes">
                      {(k?.fixes ?? []).length ? (
                        <span className="flex flex-wrap gap-1.5 font-mono text-xs">
                          {(k?.fixes ?? []).map((x, i) => (
                            <span key={i}>
                              {x.package ? `${x.package} → ` : ""}
                              {x.version}
                            </span>
                          ))}
                        </span>
                      ) : (
                        <span className="text-muted">none for these components</span>
                      )}
                    </Row>
                  </dl>
                </Section>

                <Section title="Decision">
                  <dl>
                    <Row k="Decision">
                      <StanceBadge stance={pos?.stance ?? entry.stance} decided={entry.has_position} />
                    </Row>
                    {pos && (
                      <>
                        <Row k="Decided by">
                          {pos.actor_kind === "human" ? "MANUAL" : "AUTO"} <span className="text-ink-2">({pos.actor_id || pos.actor_kind})</span>
                        </Row>
                        <Row k="Decided">{day(pos.established_at)}</Row>
                        {pos.treatment && <Row k="Disposition">{pos.treatment}</Row>}
                        {pos.scope && pos.scope !== "release" && <Row k="Scope">decided for the {pos.scope}</Row>}
                        <Row k="Rationale">{pos.rationale || <span className="text-muted">none written</span>}</Row>
                        {pos.review_by && <Row k="Review by">{day(pos.review_by)}</Row>}
                      </>
                    )}
                    {entry.disposition_stale && (
                      <Row k="Re-surfaced">
                        <Badge tone="warn">since {day(entry.disposition_stale.since)}</Badge> {entry.disposition_stale.reason}
                      </Row>
                    )}
                    <Row k="SLA">
                      <SlaCell sla={entry.sla} />
                    </Row>
                    <Row k="Priority">
                      {(entry.residual_priority ?? 0).toFixed(1)} after decisions, {(entry.effective_priority ?? 0).toFixed(1)} before
                    </Row>
                  </dl>
                  <Button asChild className="mt-3">
                    <a href={decideHash(entry.finding_id ?? "", releaseId, version)}>Decide…</a>
                  </Button>
                </Section>

                <Section title={`Matched components (${comps.length})`}>
                  {comps.length === 0 ? (
                    <p className="text-muted">none recorded</p>
                  ) : (
                    <>
                      <ul>
                        {open.map((c, i) => (
                          <ComponentRow key={`o${i}`} c={c} />
                        ))}
                      </ul>
                      {cleared.length > 0 && (
                        <>
                          <p className="mt-2 text-xs text-ink-2">Checked and fine: the installed copy carries the vendor fix.</p>
                          <ul>
                            {cleared.map((c, i) => (
                              <ComponentRow key={`c${i}`} c={c} />
                            ))}
                          </ul>
                        </>
                      )}
                    </>
                  )}
                </Section>

                {(a.data?.vendor_statements ?? []).length > 0 && (
                  <Section title="Vendor statements">
                    <ul className="space-y-1">
                      {(a.data?.vendor_statements ?? []).map((s, i) => (
                        <li key={i} className="flex flex-wrap items-center gap-1.5">
                          <span className="font-mono text-xs">{s.package}</span>
                          <Badge>{s.status}</Badge>
                          <Badge tone={s.applicability === "applicable" ? "accent" : "info"} title="Themis's determination for this release">
                            {s.applicability}
                          </Badge>
                          {s.justification && <span className="text-xs text-muted">{s.justification}</span>}
                        </li>
                      ))}
                    </ul>
                  </Section>
                )}

                <Section title="Proposals on record">
                  {(f?.proposals ?? []).length === 0 ? (
                    <p className="text-muted">none</p>
                  ) : (
                    <ul className="space-y-1.5">
                      {(f?.proposals ?? []).map((p) => (
                        <li key={p.id} className="flex flex-wrap items-center gap-1.5">
                          <Badge>{p.stance}</Badge>
                          <span className="text-ink-2">
                            by {p.proposer_kind}
                            {p.proposer_id ? ` ${p.proposer_id}` : ""} · {day(p.raised_at)}
                          </span>
                          <Badge tone={p.status === "accepted" ? "good" : p.status === "rejected" ? "neutral" : "warn"}>{p.status}</Badge>
                          {p.evidence_trust && <Badge tone={p.evidence_trust === "inferred" ? "warn" : "neutral"}>{p.evidence_trust}</Badge>}
                          {p.rationale && <span className="w-full text-xs text-muted">{p.rationale}</span>}
                        </li>
                      ))}
                    </ul>
                  )}
                </Section>

                <p className="px-5 py-4 text-xs text-ink-2">
                  The AI explanation, similar past decisions and publishing are still in the{" "}
                  <a className="text-accent" href={oldRelease}>
                    old GUI
                  </a>{" "}
                  until the next step.
                </p>
              </>
            )}
          </div>
        </>
      )}
    </Sheet>
  );
}
