// What's new (EDR-GUI-02 G4): the newest CVEs that entered this estate's knowledge, and, on
// request, what the world published lately, read live from NVD and stored nowhere until a
// person presses Gather (the explicit act that admits a CVE into the estate's knowledge).
import { useState, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/native-select";
import { Skeleton } from "@/components/ui/skeleton";
import { SeverityBadge } from "@/components/finding-bits";
import { Paged } from "@/components/pager";
import { Empty, ErrorPanel } from "@/components/states";
import { apiGet, apiPost } from "@/lib/api";
import { errorText } from "@/lib/intake";
import { cardsOnTag, useRecentCards, type PublishedCVE, type RecentFaultline } from "@/lib/queries";
import { asArray } from "@/lib/utils";

export const cveHash = (cve: string) => `#/cve/${encodeURIComponent(cve)}`;

const ago = (iso?: string) => {
  if (!iso) return "—";
  const d = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 86_400_000));
  return d === 0 ? "today" : `${d} d ago`;
};

const cut = (s = "", n: number) => (s.length > n ? `${s.slice(0, n)}…` : s);

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
/** Worst first, then by score, then newest. */
export function bySeverity(a: PublishedCVE, b: PublishedCVE) {
  const ra = SEV_RANK[(a.severity ?? "").toLowerCase()] ?? 4;
  const rb = SEV_RANK[(b.severity ?? "").toLowerCase()] ?? 4;
  if (ra !== rb) return ra - rb;
  if ((a.cvss_score ?? 0) !== (b.cvss_score ?? 0)) return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
  return String(b.published).localeCompare(String(a.published));
}

/** Find a CVE: opens its card, which lists the releases it is filed under. */
export function CveSearch() {
  const [v, setV] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const cve = v.trim().toUpperCase();
    if (/^CVE-\d{4}-\d{4,}$/.test(cve)) window.location.hash = cveHash(cve);
  };
  return (
    <form onSubmit={submit} className="flex flex-wrap items-center gap-2" role="search">
      <Input aria-label="Find a CVE" placeholder="Find a CVE, e.g. CVE-2026-21441" className="w-72" value={v} onChange={(e) => setV(e.target.value)} />
      <Button type="submit" variant="outline">
        Find
      </Button>
      <span className="text-xs text-ink-2">opens its card and the releases it is filed under</span>
    </form>
  );
}

function Signals({ v }: { v?: RecentFaultline["card"]["view"] }) {
  return (
    <span className="inline-flex flex-wrap gap-1">
      {v?.kev && <Badge tone="crit">KEV</Badge>}
      {v?.exploit_public && <Badge tone="warn">exploit</Badge>}
      {typeof v?.epss === "number" && v.epss > 0 && <Badge title="probability of exploitation in 30 days">EPSS {(v.epss * 100).toFixed(1)}%</Badge>}
    </span>
  );
}

function Fixes({ v }: { v?: RecentFaultline["card"]["view"] }) {
  const fx = v?.fixed_versions ?? [];
  if (!fx.length) return <span className="text-xs text-muted">none published</span>;
  return (
    <span className="font-mono text-xs">
      {fx.slice(0, 3).join(", ")}
      {fx.length > 3 && <span className="text-muted"> +{fx.length - 3}</span>}
    </span>
  );
}

function Recent() {
  const cards = useRecentCards();
  const [draft, setDraft] = useState("");
  const [tag, setTag] = useState("");
  const tagged = useQuery({
    queryKey: ["recent-cards-tag", tag, cards.dataUpdatedAt],
    enabled: !!tag && !!cards.data,
    queryFn: () => cardsOnTag(cards.data ?? [], tag),
  });
  const rows = tag ? tagged.data : cards.data;
  const err = cards.error ?? tagged.error;
  return (
    <Card>
      <CardHeader>
        <CardTitle>What's new</CardTitle>
        <CardDescription>
          The newest CVEs that entered this estate's knowledge, newest first: a card is made when a component carries the CVE, a feed sweep finds
          it for a component you ship, or someone gathers it. Not the world's feed: what concerns you.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 px-0">
        <div className="flex flex-col gap-2 px-4">
          <CveSearch />
          <form
            className="flex flex-wrap items-center gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              setTag(draft.trim().toLowerCase());
            }}
          >
            <Input aria-label="Only CVEs on releases tagged" placeholder="tag, e.g. team:payments" className="w-56 font-mono" value={draft} onChange={(e) => setDraft(e.target.value)} />
            <Button type="submit" variant="outline">
              Apply
            </Button>
            {tag && rows && (
              <span className="text-xs text-ink-2">
                {rows.length} of the newest {cards.data?.length ?? 0} cards are on releases tagged {tag}
              </span>
            )}
          </form>
        </div>
        {err ? (
          <div className="px-4">
            <ErrorPanel error={err} />
          </div>
        ) : !rows ? (
          <Skeleton className="mx-4 h-24" />
        ) : !rows.length ? (
          <Empty title="No cards yet">Upload an SBOM, or gather a CVE, and it appears here.</Empty>
        ) : (
          <Paged rows={rows}>
            {(page) => (
              <table className="w-full min-w-[900px] text-left">
                <thead className="border-y border-line text-xs text-ink-2">
                  <tr>
                    <th className="py-2 pr-3 pl-4 font-medium">Entered</th>
                    <th className="py-2 pr-3 font-medium">CVE</th>
                    <th className="py-2 pr-3 font-medium">Severity</th>
                    <th className="py-2 pr-3 font-medium">Signals</th>
                    <th className="py-2 pr-3 font-medium">What it is</th>
                    <th className="py-2 pr-3 font-medium">Published fix</th>
                    <th className="py-2 pr-3 font-medium">Stage</th>
                  </tr>
                </thead>
                <tbody>
                  {page.map((r) => {
                    const v = r.card.view;
                    return (
                      <tr key={r.card.id ?? r.card.cve} className="border-b border-line align-top">
                        <td className="py-2 pr-3 pl-4 whitespace-nowrap" title={r.created_at}>
                          {ago(r.created_at)}
                        </td>
                        <td className="py-2 pr-3">
                          <a className="font-mono text-xs font-medium text-accent" href={cveHash(r.card.cve ?? "")}>
                            {r.card.cve}
                          </a>
                        </td>
                        <td className="py-2 pr-3 whitespace-nowrap">
                          <SeverityBadge severity={v?.severity} />
                          {typeof v?.cvss_score === "number" && v.cvss_score > 0 && <span className="ml-1 tabular-nums">{v.cvss_score.toFixed(1)}</span>}
                        </td>
                        <td className="py-2 pr-3">
                          <Signals v={v} />
                        </td>
                        <td className="py-2 pr-3 text-ink-2">{cut(v?.summary, 220)}</td>
                        <td className="py-2 pr-3">
                          <Fixes v={v} />
                        </td>
                        <td className="py-2 pr-3">
                          <Badge>{r.card.stage}</Badge>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </Paged>
        )}
      </CardContent>
    </Card>
  );
}

function GatherCell({ row, onGathered }: { row: PublishedCVE; onGathered: (cve: string) => void }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  if (row.carded) return <Badge tone="good">carded</Badge>;
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <Button
        size="sm"
        variant="outline"
        disabled={busy}
        aria-label={`Gather ${row.cve}`}
        onClick={async () => {
          setBusy(true);
          setErr("");
          try {
            await apiPost("knowledge", "/faultlines/gather", { cve: row.cve });
            onGathered(row.cve);
          } catch (e) {
            setErr(errorText(e));
            setBusy(false);
          }
        }}
      >
        {busy ? "gathering…" : "Gather"}
      </Button>
      {err && <span className="text-xs text-crit">gather failed: {err}</span>}
    </span>
  );
}

function Published() {
  const qc = useQueryClient();
  const [days, setDays] = useState("7");
  const [rows, setRows] = useState<PublishedCVE[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  async function load() {
    setBusy(true);
    setErr("");
    try {
      setRows(asArray<PublishedCVE>(await apiGet("knowledge", `/faultlines/published-recently?days=${encodeURIComponent(days)}`)).sort(bySeverity));
    } catch (e) {
      setErr(errorText(e));
    }
    setBusy(false);
  }
  const gathered = (cve: string) => {
    setRows((rs) => (rs ?? []).map((r) => (r.cve === cve ? { ...r, carded: true } : r)));
    void qc.invalidateQueries({ queryKey: ["recent-cards"] });
  };
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Latest published <Badge title="fetched live from NVD when you ask; nothing is stored until you gather it">live, not stored</Badge>
        </CardTitle>
        <CardDescription>
          What the world published in the last days, read live from NVD and shown as is. A row becomes a card only when you press Gather.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 px-0">
        <div className="flex flex-wrap items-center gap-2 px-4">
          <label className="flex items-center gap-2 text-xs text-ink-2">
            Days
            <Select className="w-20" value={days} onChange={(e) => setDays(e.target.value)}>
              {["3", "7", "14", "30"].map((d) => (
                <option key={d}>{d}</option>
              ))}
            </Select>
          </label>
          <Button variant="outline" onClick={load} disabled={busy}>
            {busy && <Loader2 className="animate-spin" aria-hidden />}
            Load from NVD
          </Button>
          {rows && (
            <span className="text-xs text-ink-2">
              {rows.length} published in the last {days} days, worst first; {rows.filter((r) => r.carded).length} already carded
            </span>
          )}
        </div>
        {err && (
          <div className="px-4">
            <ErrorPanel error={new Error(err)} />
          </div>
        )}
        {rows &&
          (rows.length ? (
            <Paged rows={rows}>
              {(page) => (
                <table className="w-full min-w-[760px] text-left">
                  <thead className="border-y border-line text-xs text-ink-2">
                    <tr>
                      <th className="py-2 pr-3 pl-4 font-medium">Published</th>
                      <th className="py-2 pr-3 font-medium">CVE</th>
                      <th className="py-2 pr-3 font-medium">Severity</th>
                      <th className="py-2 pr-3 font-medium">What it is</th>
                      <th className="py-2 pr-3 font-medium">In the estate</th>
                    </tr>
                  </thead>
                  <tbody>
                    {page.map((r) => (
                      <tr key={r.cve} className="border-b border-line align-top">
                        <td className="py-2 pr-3 pl-4 whitespace-nowrap" title={r.published}>
                          {ago(r.published)}
                        </td>
                        <td className="py-2 pr-3 font-mono text-xs">
                          {r.carded ? (
                            <a className="text-accent" href={cveHash(r.cve)}>
                              {r.cve}
                            </a>
                          ) : (
                            r.cve
                          )}
                        </td>
                        <td className="py-2 pr-3 whitespace-nowrap">
                          <SeverityBadge severity={r.severity} />
                          {typeof r.cvss_score === "number" && r.cvss_score > 0 && <span className="ml-1 tabular-nums">{r.cvss_score.toFixed(1)}</span>}
                        </td>
                        <td className="py-2 pr-3 text-ink-2">{cut(r.summary, 200)}</td>
                        <td className="py-2 pr-3">
                          <GatherCell row={r} onGathered={gathered} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Paged>
          ) : (
            <Empty title="Nothing published in that window">NVD answered with no CVEs for these days.</Empty>
          ))}
      </CardContent>
    </Card>
  );
}

export function WhatsNew() {
  return (
    <div className="flex flex-col gap-4">
      <Recent />
      <Published />
    </div>
  );
}
