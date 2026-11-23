// The drawer's three remaining sections (EDR-GUI-02 G5):
// - "What it means here": explain_vulnerability runs when the drawer opens (GUI-1 D1), cached
//   for the session, never blocking the drawer, and shown only when the AI plane is on.
// - "How Themis got this score": Governance's stored assessment (EDR-SCORING-01 S5), read only.
//   Every number comes from the server; nothing is computed here.
// - "Similar past decisions": semantic precedent, retrieved with no model in the path.
import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { AiResultView, invokeCapability } from "@/components/ai-bits";
import { BandBadge, StanceBadge } from "@/components/finding-bits";
import { when } from "@/components/when";
import { apiGet } from "@/lib/api";
import type { components as Governance } from "@/types/api/governance";
import type { components as Intelligence } from "@/types/api/intelligence";

type FindingScore = Governance["schemas"]["FindingScore"];
type Similar = Intelligence["schemas"]["SimilarFindings"];

export function Section({ title, badge, children }: { title: string; badge?: ReactNode; children: ReactNode }) {
  return (
    <section className="border-b border-line px-5 py-4">
      <h3 className="mb-2 flex items-center gap-2 text-xs font-semibold tracking-wide text-ink-2 uppercase">
        {title}
        {badge}
      </h3>
      {children}
    </section>
  );
}

const Muted = ({ children }: { children: ReactNode }) => <p className="text-muted">{children}</p>;

/* ---------- AI explanation ---------- */

export function Explanation({ findingId }: { findingId: string }) {
  const q = useQuery({
    queryKey: ["explain", findingId],
    queryFn: () => invokeCapability("explain_vulnerability", { type: "finding", ids: [findingId] }),
    staleTime: Infinity,
    gcTime: Infinity,
    retry: false,
  });
  // Enabled-only: an AI plane that is off, unreachable or missing leaves no dead placeholder.
  if (q.isError) return null;
  const r = q.data;
  if (r?.kind === "missing") return null;
  if (r?.kind === "none" && (r.reason === "disabled" || r.reason === "unreachable")) return null;
  return (
    <Section
      title="What it means here"
      badge={
        <Badge tone="ai" title="Information: never stored. The summary above is evidence; this is the AI's reading of it for these components">
          AI · local-only
        </Badge>
      }
    >
      {q.isPending ? (
        <div className="flex flex-col gap-1.5" role="status" aria-label="Explaining">
          <Skeleton className="h-4 w-3/4" />
          <p className="text-xs text-muted">Local model: may take a minute. The drawer stays usable; the answer fills in here.</p>
        </div>
      ) : (
        r && <AiResultView r={r} missing="" />
      )}
    </Section>
  );
}

/* ---------- Score ---------- */

const STATE_WORDS: Record<string, string> = {
  no_components: "No component is currently matched",
  no_carrier: "Only rebuild-set (scope) components; none is evidenced to carry the flaw",
  no_open_occurrences: "Every carrier copy is cleared by a vendor fix",
  unavailable: "No usable rating for any open component",
};
const COND_WORDS: Record<string, string> = {
  independent_assessor_disagreement: "two assessors give different vectors",
  assessor_self_inconsistency: "one assessor gives two different vectors",
  unscorable_peer_assessment: "another assessor's rating is CVSS 4.0 or 2.0, which Themis cannot score yet",
  higher_class_unresolved: "a higher-ranked rating (for example the vendor's) may apply; not yet decided",
  same_class_unresolved: "a rating of the same rank may apply; not yet decided",
};
const UNSCORED_WORDS: Record<string, string> = {
  unsupported_cvss_version: "only CVSS 4.0 / 2.0 ratings, which are not scored yet",
  invalid_vector: "the rating's vector is invalid",
  no_calculable_rating: "no rating Themis can calculate",
  no_vector: "no source gave a CVSS vector",
  no_applicable_rating: "no rating applies to this component",
  rating_applicability_unresolved: "a vendor rating may apply; not yet decided",
};
const CLASS_WORDS: Record<string, string> = {
  vendor_platform: "platform vendor",
  cna: "CNA",
  adp: "CISA ADP",
  nvd_analyst: "NVD",
  other_assessor: "other assessor",
  unattributed: "assessor unknown",
};
const DISP_WORDS: Record<string, string> = {
  reference: "used",
  supporting: "same assessment, another copy",
  competing: "disagrees",
  unresolved: "may apply, not decided",
  available_not_selected: "lower rank, not used",
  available_not_compared: "cannot be calculated",
  not_selected: "set aside",
  rejected: "not used",
};
const say = (map: Record<string, string>, code?: string) => (code ? (map[code] ?? code.replace(/_/g, " ")) : "");
const num = (x?: number) => (typeof x === "number" ? x.toFixed(1) : "—");

type Ratio = { value?: string; numerator?: number; denominator?: number };
type Rollup = {
  state?: string;
  score?: number;
  band?: string;
  score_status?: string;
  contributors?: string[];
  at_maximum?: string[];
  scoring_coverage?: Ratio;
  assessment_finality?: Ratio;
  unassessed?: { purl: string; reason: string }[];
};
type Candidate = {
  assessor?: string;
  publisher?: string;
  feed?: string;
  class?: string;
  cvss_version?: string;
  vector?: string;
  scores?: { environmental: number };
  disposition?: string;
  contribution?: number;
};
type Comp = {
  score_status?: string;
  eligible?: boolean;
  open?: boolean;
  outcome?: string;
  unscored_reason?: string;
  conflict_conditions?: string[];
  applicability_conditions?: string[];
  scores?: { base: number; temporal: number; environmental: number };
  assessment_vector?: string;
  candidates?: Candidate[];
};

function StatusBadge({ status }: { status?: string }) {
  if (status === "final") return <Badge tone="good">final</Badge>;
  if (status === "provisional") return <Badge tone="warn" title="a condition keeps this score open; the conditions say which">provisional</Badge>;
  return <Badge tone="info">unavailable</Badge>;
}

function Coverage({ r, noun }: { r?: Ratio; noun: string }) {
  if (!r || r.value === "not_applicable") return <span className="text-muted">not applicable</span>;
  return (
    <>
      {r.numerator} of {r.denominator} {noun} <Badge tone="info">{r.value}</Badge>
    </>
  );
}

function Kv({ k, children }: { k: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-2 py-1">
      <dt className="text-ink-2">{k}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  );
}

export function ScoreSection({ findingId }: { findingId: string }) {
  const q = useQuery({ queryKey: ["score", findingId], queryFn: () => apiGet<FindingScore>("governance", `/findings/${encodeURIComponent(findingId)}/score`), retry: false });
  const badge = (
    <Badge tone="info" title="EDR-SCORING-01: shown for review; priority, SLA and notifications still use the old score">
      shadow
    </Badge>
  );
  if (q.isPending)
    return (
      <Section title="How Themis got this score" badge={badge}>
        <Skeleton className="h-4 w-1/2" />
      </Section>
    );
  if (q.isError)
    return (
      <Section title="How Themis got this score" badge={badge}>
        <Muted>Score unavailable: Governance did not answer, or the assessment is not wired on this node.</Muted>
      </Section>
    );
  if (!q.data?.rollup)
    return (
      <Section title="How Themis got this score" badge={badge}>
        <Muted>Not yet assessed: the assessment sweep has not reached this finding.</Muted>
      </Section>
    );
  const r = q.data.rollup.snapshot as Rollup;
  const comps = q.data.components;
  const conds = new Set<string>();
  for (const c of comps) {
    const s = c.snapshot as Comp;
    if ((r.at_maximum ?? []).includes(c.purl)) [...(s.conflict_conditions ?? []), ...(s.applicability_conditions ?? [])].forEach((x) => conds.add(x));
  }
  const n = (r.contributors ?? []).length;
  return (
    <Section title="How Themis got this score" badge={badge}>
      <dl>
        <Kv k="Score">
          {r.state === "scored" ? (
            <span className="inline-flex flex-wrap items-center gap-1.5">
              <b>{num(r.score)}</b> <BandBadge band={r.band} /> <StatusBadge status={r.score_status} />
              <span className="text-xs text-ink-2">
                highest Environmental score among {n} contributing component{n === 1 ? "" : "s"}
              </span>
            </span>
          ) : (
            <span>
              <Badge tone="info">{say(STATE_WORDS, r.state)}</Badge> <span className="text-xs text-ink-2">no number, and never 0</span>
            </span>
          )}
        </Kv>
        {r.score_status === "provisional" && conds.size > 0 && <Kv k="Why provisional">{[...conds].map((c) => say(COND_WORDS, c)).join("; ")}</Kv>}
        <Kv k="Scoring coverage">
          <Coverage r={r.scoring_coverage} noun="open carrier components scored" />
        </Kv>
        <Kv k="Finality">
          <Coverage r={r.assessment_finality} noun="scored components final" />
        </Kv>
        {!!r.unassessed?.length && (
          <Kv k="Not scored">
            {r.unassessed.map((u) => (
              <div key={u.purl}>
                <span className="font-mono text-xs">{u.purl}</span> <span className="text-xs text-ink-2">{say(UNSCORED_WORDS, u.reason)}</span>
              </div>
            ))}
          </Kv>
        )}
      </dl>
      {comps.map((c) => {
        const s = c.snapshot as Comp;
        const cs = [...(s.conflict_conditions ?? []), ...(s.applicability_conditions ?? [])];
        return (
          <details key={c.purl} className="mt-2 rounded-lg border border-line p-2">
            <summary className="flex cursor-pointer flex-wrap items-center gap-1.5">
              <span className="font-mono text-xs">{c.purl}</span>
              {s.scores && <b>{num(s.scores.environmental)}</b>}
              <StatusBadge status={s.score_status} />
              {s.eligible === false && <Badge tone="info">scope, not counted</Badge>}
              {s.open === false && <Badge tone="good">cleared, not counted</Badge>}
              <span className="text-xs text-ink-2">
                revision {c.revision} · {c.cause} · {when(c.recorded_at)}
              </span>
            </summary>
            <dl className="mt-1">
              <Kv k="Outcome">
                {s.outcome || <span className="text-muted">no outcome</span>}
                {s.unscored_reason && ` · ${say(UNSCORED_WORDS, s.unscored_reason)}`}
              </Kv>
              {cs.length > 0 && <Kv k="Conditions">{cs.map((x) => say(COND_WORDS, x)).join("; ")}</Kv>}
              {s.scores && (
                <Kv k="Scores">
                  Base {num(s.scores.base)} · Temporal {num(s.scores.temporal)} · Environmental {num(s.scores.environmental)}
                  <div className="font-mono text-xs break-all">{s.assessment_vector}</div>
                </Kv>
              )}
            </dl>
            {!!s.candidates?.length && (
              <table className="mt-1 w-full text-left text-xs">
                <thead className="text-ink-2">
                  <tr>
                    <th className="py-1 pr-2 font-medium">Assessor</th>
                    <th className="py-1 pr-2 font-medium">Rank</th>
                    <th className="py-1 pr-2 font-medium">Rating</th>
                    <th className="py-1 pr-2 font-medium">Result</th>
                  </tr>
                </thead>
                <tbody>
                  {s.candidates.map((x, i) => (
                    <tr key={i} className={x.disposition === "rejected" ? "border-t border-line text-muted" : "border-t border-line"}>
                      <td className="py-1 pr-2">
                        {x.assessor || "unknown"}
                        <div className="text-ink-2">{[x.publisher, x.feed].filter(Boolean).join(" via ")}</div>
                      </td>
                      <td className="py-1 pr-2">{say(CLASS_WORDS, x.class) || "—"}</td>
                      <td className="py-1 pr-2">
                        {x.scores && <b>{num(x.scores.environmental)} </b>}CVSS {x.cvss_version ?? "?"}
                        <div className="font-mono break-all">{x.vector}</div>
                      </td>
                      <td className="py-1 pr-2">{say(DISP_WORDS, x.disposition)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </details>
        );
      })}
      {q.data.history.length > 1 && (
        <details className="mt-2">
          <summary className="cursor-pointer text-xs text-ink-2">History ({q.data.history.length} revisions; older ones are kept unchanged)</summary>
          <table className="mt-1 w-full text-left text-xs">
            <tbody>
              {q.data.history.map((h, i) => (
                <tr key={i} className="border-t border-line">
                  <td className="py-1 pr-2">{when(h.recorded_at)}</td>
                  <td className="py-1 pr-2 font-mono">{h.purl}</td>
                  <td className="py-1 pr-2">{h.revision}</td>
                  <td className="py-1 pr-2">{h.cause}</td>
                  <td className="py-1 pr-2">
                    {num(h.score)} <StatusBadge status={h.score_status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </Section>
  );
}

/* ---------- Similar past decisions ---------- */

export function SimilarDecisions({ findingId }: { findingId: string }) {
  const q = useQuery({
    queryKey: ["similar", findingId],
    queryFn: () => apiGet<Similar>("intelligence", `/findings/${encodeURIComponent(findingId)}/similar?k=5`),
    retry: false,
  });
  const precedents = q.data?.precedents;
  return (
    <Section
      title="Similar past decisions"
      badge={
        <Badge tone="accent" title="semantic precedent: retrieved, no model runs">
          no AI
        </Badge>
      }
    >
      {q.isPending ? (
        <Skeleton className="h-4 w-1/2" />
      ) : q.isError || !precedents ? (
        <Muted>Precedent unavailable: the Intelligence node is not running, or has no retrieval store.</Muted>
      ) : !precedents.length ? (
        <Muted>No precedent found: nothing decided so far resembles this finding, the usual answer on a young deployment.</Muted>
      ) : (
        <ul className="flex flex-col gap-2">
          {precedents.map((p, i) => (
            <li key={i} className="rounded-lg border border-line p-2">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="font-mono text-xs">{p.source_cve || "same CVE"}</span>
                <StanceBadge stance={p.stance} decided />
                <Badge tone="info">release {p.release_id.slice(0, 8)}</Badge>
                <span className="ml-auto text-xs tabular-nums">{p.score ? p.score.toFixed(2) : "exact"}</span>
              </div>
              {p.rationale && <p className="mt-1 text-xs text-ink-2">{p.rationale}</p>}
            </li>
          ))}
        </ul>
      )}
      <p className="mt-2 text-xs text-muted">Contradictory decisions here are information, not an error: it is exactly when the AI declines and a person should look.</p>
    </Section>
  );
}
