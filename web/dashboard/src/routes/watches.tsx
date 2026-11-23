// Watches (EDR-GUI-02 G5, EDR-INCIDENT-01 step B): name a wave of CVEs and Red Hat advisories,
// and read one table of every release that has any of them, with its state now. The table is
// computed on every open; it stores nothing and decides nothing. "Fix available" is the
// vendor's statement; "patched" is proven only by a new scan or SBOM of the release.
import { useState, type FormEvent } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { StanceBadge } from "@/components/finding-bits";
import { Empty, ErrorPanel } from "@/components/states";
import { ago, when } from "@/components/when";
import { ApiError, apiPost, apiRaw } from "@/lib/api";
import { errorText } from "@/lib/intake";
import { useWhoAmI } from "@/lib/queries";
import { asArray, cn } from "@/lib/utils";
import { cveHash } from "@/routes/whats-new";
import type { components as Governance } from "@/types/api/governance";

type Watch = Governance["schemas"]["WatchView"];
type Status = Governance["schemas"]["WatchStatusView"];
type Row = Governance["schemas"]["WatchRowView"];
type Tone = "crit" | "warn" | "elevated" | "good" | "neutral" | "info";

export const WATCH_STATES: [Row["state"], Tone, string][] = [
  ["open_fix_available", "crit", "open, a vendor fix is on record for the package: re-scan to prove it applied"],
  ["open_no_fix", "warn", "open, no vendor fix known for the package"],
  ["accepted", "elevated", "a person accepted, mitigated or deferred it; the decision stands"],
  ["fixed", "good", "every occurrence is cleared by evidence newer than the fix"],
  ["not_affected", "neutral", "no component of the release matches, or a not_affected decision stands"],
  ["unknown", "info", "no card for the CVE, or the advisory names nothing Themis has seen"],
];

export const watchHash = (id: string) => `#/watches/${encodeURIComponent(id)}`;

function StateBadge({ state }: { state: string }) {
  const [, tone, title] = WATCH_STATES.find(([k]) => k === state) ?? [state, "neutral" as Tone, ""];
  return (
    <Badge tone={tone} title={title}>
      {state.replace(/_/g, " ")}
    </Badge>
  );
}

/** A read that says "not on this node" (503) apart from a failure. */
async function readGov<T>(path: string): Promise<T | null> {
  const r = await apiRaw("governance", path);
  if (r.status === 404) return null;
  if (!r.ok) {
    const j = (await r.json().catch(() => ({}))) as { detail?: string; title?: string };
    throw new ApiError(r.status, r.status === 503 ? j.detail || "This Governance node does not serve watches yet (older build)." : j.detail || j.title || `governance ${path}: ${r.status}`);
  }
  return (await r.json()) as T;
}

const Ids = ({ value, onChange, label, rows = 4 }: { value: string; onChange: (v: string) => void; label: string; rows?: number }) => (
  <label className="flex flex-col gap-1 text-xs font-medium text-ink-2">
    {label}
    <textarea
      rows={rows}
      required
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder="CVE-2026-1234 CVE-2026-2345 RHSA-2026:1234, any separator"
      className="rounded-lg border border-line bg-card p-2 font-mono text-[13px] text-ink focus-visible:outline-2 focus-visible:outline-accent"
    />
  </label>
);

export function Watches() {
  const who = useWhoAmI();
  const list = useQuery({ queryKey: ["watches"], queryFn: async () => asArray<Watch>(await readGov("/watches")) });
  const [name, setName] = useState("");
  const [ids, setIds] = useState("");
  const [msg, setMsg] = useState("");

  async function create(e: FormEvent) {
    e.preventDefault();
    setMsg("Creating…");
    try {
      const { data } = await apiPost<Governance["schemas"]["WatchCreated"]>("governance", "/watches", { name, identifiers: ids, created_by: who.data?.user ?? "" });
      if (data) window.location.hash = watchHash(data.watch.id);
    } catch (x) {
      setMsg(errorText(x));
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Watches</CardTitle>
          <CardDescription>
            Paste the CVE and Red Hat advisory ids of a wave (RHSA-, RHBA-, RHEA-), name the list, and read one table: every release that has any
            of them, with its state now. Fix available is the vendor's statement; patched is proven only by a new scan or SBOM of the release.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="grid max-w-xl gap-3" onSubmit={create}>
            <label className="flex flex-col gap-1 text-xs font-medium text-ink-2">
              Name
              <Input required placeholder="e.g. wave 2026-11" value={name} onChange={(e) => setName(e.target.value)} autoComplete="off" />
            </label>
            <Ids label="Identifiers" value={ids} onChange={setIds} />
            <div className="flex items-center gap-2">
              <Button type="submit">Create watch</Button>
              <span className="text-xs text-ink-2">{msg}</span>
            </div>
          </form>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Your watches</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto px-0">
          {list.isError ? (
            <div className="px-4">
              <ErrorPanel error={list.error} />
            </div>
          ) : list.isPending ? (
            <Skeleton className="mx-4 h-16" />
          ) : !list.data.length ? (
            <Empty title="No watch yet">Create one above; it appears here and opens as a table.</Empty>
          ) : (
            <table className="w-full text-left">
              <thead className="border-y border-line text-xs text-ink-2">
                <tr>
                  <th className="py-2 pr-3 pl-4 font-medium">Name</th>
                  <th className="py-2 pr-3 text-right font-medium">Identifiers</th>
                  <th className="py-2 pr-3 text-right font-medium">Resolved CVEs</th>
                  <th className="py-2 pr-3 font-medium">Created</th>
                  <th className="py-2 pr-3 font-medium">By</th>
                </tr>
              </thead>
              <tbody>
                {list.data.map((w) => (
                  <tr key={w.id} className="border-b border-line">
                    <td className="py-2 pr-3 pl-4">
                      <a className="font-medium text-accent" href={watchHash(w.id)}>
                        {w.name}
                      </a>
                    </td>
                    <td className="py-2 pr-3 text-right tabular-nums">{w.identifiers.length}</td>
                    <td className="py-2 pr-3 text-right tabular-nums">{w.resolved_at ? w.resolved_cves.length : "—"}</td>
                    <td className="py-2 pr-3">{ago(w.created_at)}</td>
                    <td className="py-2 pr-3">{w.created_by}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

/** The CSV of what is shown, one line per row. */
export function watchCsv(rows: Row[]): string {
  const q = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const head = ["product", "project", "version", "release_id", "cve", "state", "stance", "packages", "vendor_fixes", "last_evidence_kind", "last_evidence_at", "finding_id"];
  const lines = rows.map((x) =>
    [
      x.product_name || x.product_id,
      x.project_name || x.project_id,
      x.version,
      x.release_id,
      x.cve,
      x.state,
      x.stance,
      x.packages.join(" "),
      x.fixes.join(" "),
      x.last_evidence_kind,
      x.last_evidence_at,
      x.finding_id,
    ]
      .map(q)
      .join(","),
  );
  return [head.join(","), ...lines].join("\n") + "\n";
}

function download(name: string, text: string) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/csv" }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

export function WatchView({ id }: { id: string }) {
  const qc = useQueryClient();
  const st = useQuery({ queryKey: ["watch", id], queryFn: () => readGov<Status>(`/watches/${encodeURIComponent(id)}/status`) });
  const [filter, setFilter] = useState("");
  const [more, setMore] = useState("");
  const [msg, setMsg] = useState("");

  if (st.isError) return <ErrorPanel error={st.error} />;
  if (st.isPending) return <Skeleton className="h-40" />;
  if (!st.data)
    return (
      <Empty title="No such watch">
        It may have been deleted.{" "}
        <a className="text-accent" href="#/watches">
          Back to watches
        </a>
      </Empty>
    );
  const { watch: w, rows, identifiers, counts } = st.data;
  const shown = filter ? rows.filter((x) => x.state === filter) : rows;
  const unresolved = identifiers.filter((i) => !i.resolved);

  async function add(e: FormEvent) {
    e.preventDefault();
    setMsg("Adding…");
    try {
      const { data } = await apiPost<{ added: number; rejected?: string[] }>("governance", `/watches/${encodeURIComponent(id)}/identifiers`, { identifiers: more });
      const rej = data?.rejected ?? [];
      setMsg(`${data?.added ?? 0} identifier(s) added${rej.length ? `, not understood: ${rej.join(", ")}` : ""}`);
      setMore("");
      await qc.invalidateQueries({ queryKey: ["watch", id] });
    } catch (x) {
      setMsg(errorText(x));
    }
  }

  async function remove() {
    if (!window.confirm(`Delete the watch "${w.name}"? Nothing else changes.`)) return;
    try {
      const r = await apiRaw("governance", `/watches/${encodeURIComponent(id)}`, { method: "DELETE" });
      if (!r.ok) {
        const j = (await r.json().catch(() => ({}))) as { detail?: string };
        setMsg(j.detail || `delete refused (${r.status})`);
        return;
      }
      await qc.invalidateQueries({ queryKey: ["watches"] });
      window.location.hash = "#/watches";
    } catch (x) {
      setMsg(errorText(x));
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>{w.name}</CardTitle>
          <CardDescription>
            {identifiers.length} identifier(s) · {w.resolved_cves.length} CVE(s) · created {ago(w.created_at)} by {w.created_by}. {st.data.note} Computed{" "}
            {when(st.data.generated_at)}.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div role="radiogroup" aria-label="Show" className="flex flex-wrap items-center gap-1.5">
            {[["", `all ${rows.length}`] as const, ...WATCH_STATES.map(([k]) => [k, `${k.replace(/_/g, " ")} ${counts[k] ?? 0}`] as const)].map(([k, label]) => (
              <button
                key={k || "all"}
                type="button"
                role="radio"
                aria-checked={filter === k}
                onClick={() => setFilter(k)}
                className={cn("rounded-md border border-line px-2.5 py-1 text-xs font-medium text-ink-2 hover:text-ink", filter === k && "bg-accent text-on-accent hover:text-on-accent")}
              >
                {label}
              </button>
            ))}
            <span className="flex-1" />
            <Button variant="outline" size="sm" onClick={() => download(`watch-${(w.name || id).replace(/[^A-Za-z0-9_-]+/g, "_")}${filter ? `-${filter}` : ""}.csv`, watchCsv(shown))}>
              Export CSV
            </Button>
            <Button variant="outline" size="sm" onClick={remove} title="admin only; the Findings are untouched">
              Delete watch
            </Button>
          </div>
          {unresolved.length > 0 && (
            <p className="text-xs text-ink-2">
              Not resolved: <span className="font-mono">{unresolved.map((i) => i.id).join(", ")}</span>.{" "}
              {unresolved.some((i) => i.kind === "advisory")
                ? "An advisory resolves through the cards' recorded RHSA ids; one Themis has not seen on any card names nothing."
                : "No card exists for it yet; gather it from What's new."}
            </p>
          )}
          {msg && <p className="text-xs text-ink-2">{msg}</p>}
        </CardContent>
      </Card>
      <Card>
        <CardContent className="overflow-x-auto px-0 pt-0">
          {shown.length ? (
            <table className="w-full min-w-[900px] text-left">
              <thead className="border-b border-line text-xs text-ink-2">
                <tr>
                  <th className="py-2 pr-3 pl-4 font-medium">Product</th>
                  <th className="py-2 pr-3 font-medium">Project · version</th>
                  <th className="py-2 pr-3 font-medium">CVE</th>
                  <th className="py-2 pr-3 font-medium">State</th>
                  <th className="py-2 pr-3 font-medium">Decision</th>
                  <th className="py-2 pr-3 font-medium">Packages</th>
                  <th className="py-2 pr-3 font-medium">Vendor fix</th>
                  <th className="py-2 pr-3 font-medium">Last proof</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((x, i) => (
                  <tr key={`${x.release_id}-${x.cve}-${i}`} className="border-b border-line">
                    <td className="py-2 pr-3 pl-4">{x.product_name || x.product_id}</td>
                    <td className="py-2 pr-3">
                      {x.release_id ? (
                        `${x.project_name || x.project_id || ""} ${x.version || ""}`.trim() || <span className="font-mono text-xs">{x.release_id}</span>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                    <td className="py-2 pr-3">
                      <a className="font-mono text-xs text-accent" href={cveHash(x.cve)}>
                        {x.cve}
                      </a>
                    </td>
                    <td className="py-2 pr-3">
                      <StateBadge state={x.state} />
                    </td>
                    <td className="py-2 pr-3">{x.stance ? <StanceBadge stance={x.stance} decided /> : <span className="text-xs text-muted">undecided</span>}</td>
                    <td className="py-2 pr-3 font-mono text-xs">{x.packages.join(", ")}</td>
                    <td className="py-2 pr-3 font-mono text-xs">{x.fixes.join(", ")}</td>
                    <td className="py-2 pr-3 text-xs">
                      {x.last_evidence_at ? `${x.last_evidence_kind || "evidence"} ${when(x.last_evidence_at)}` : x.release_id ? <span className="text-muted">none filed</span> : ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty title={rows.length ? "Nothing in this state" : "Nothing to show"}>
              {rows.length ? "Pick another filter." : "No release in the estate has a finding for these identifiers."}
            </Empty>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Add identifiers</CardTitle>
          <CardDescription>A watch only grows: paste more ids; nothing already listed is dropped.</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="grid max-w-xl gap-3" onSubmit={add}>
            <Ids label="More identifiers" value={more} onChange={setMore} rows={3} />
            <div>
              <Button type="submit" variant="outline">
                Add
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
