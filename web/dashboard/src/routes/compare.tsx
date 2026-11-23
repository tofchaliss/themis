// Compare two releases (EDR-GUI-02 G4, IDEA-1). "Fixed" is absence proven by new evidence: the
// candidate's evidence opens no Finding for the CVE while the baseline keeps its record.
// Governance owns the join, the buckets, the order and the honesty guard (422 when a side has no
// evidence, 502 when Evidence cannot be asked); this screen only shows its answer.
import { useState, type ReactNode } from "react";
import { Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select } from "@/components/ui/native-select";
import { Count } from "@/components/count";
import { AiResultView, invokeCapability, type AiResult } from "@/components/ai-bits";
import { FindingDrawer } from "@/components/finding-drawer";
import { FindingTable } from "@/components/finding-table";
import { Empty, ErrorPanel } from "@/components/states";
import { apiRaw } from "@/lib/api";
import { errorText } from "@/lib/intake";
import { useProducts, useProjects, useReleases, type PostureEntry } from "@/lib/queries";
import type { components as Governance } from "@/types/api/governance";

type Comparison = Governance["schemas"]["ReleaseComparison"];
type Side = { id: string; version: string };

function Bucket({ title, tone, rows, children, empty, onOpen }: { title: string; tone: "good" | "crit" | "warn"; rows: PostureEntry[]; children: ReactNode; empty: string; onOpen: (p: PostureEntry) => void }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {title} <Badge tone={tone}>{rows.length}</Badge>
        </CardTitle>
        <CardDescription>{children}</CardDescription>
      </CardHeader>
      <CardContent className="overflow-x-auto px-0">{rows.length ? <FindingTable rows={rows} onOpen={onOpen} /> : <Empty title={empty} />}</CardContent>
    </Card>
  );
}

function Advisor({ a, b }: { a: Side; b: Side }) {
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<AiResult | null>(null);
  const [err, setErr] = useState("");
  async function ask() {
    setBusy(true);
    setErr("");
    setRes(null);
    try {
      setRes(await invokeCapability("compare_releases", { type: "release", ids: [a.id, b.id] }));
    } catch (e) {
      setErr(errorText(e));
    }
    setBusy(false);
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>Ask the advisor</CardTitle>
        <CardDescription>
          A local-model narration of exactly the buckets above (compare_releases). It cites only what the comparison holds and decides nothing.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div>
          <Button variant="outline" onClick={ask} disabled={busy}>
            {busy && <Loader2 className="animate-spin" aria-hidden />}
            {busy ? "Narrating…" : "Narrate this comparison"}
          </Button>
        </div>
        {err && <ErrorPanel error={new Error(err)} />}
        {res && <AiResultView r={res} missing="This Intelligence node predates compare_releases." />}
      </CardContent>
    </Card>
  );
}

export function Compare() {
  const products = useProducts();
  const [product, setProduct] = useState("");
  const [project, setProject] = useState("");
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const projects = useProjects(product || null);
  const releases = useReleases(project || null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [result, setResult] = useState<{ cmp: Comparison; a: Side; b: Side } | null>(null);
  const [drawer, setDrawer] = useState<PostureEntry | null>(null);

  const ver = (id: string) => (releases.data ?? []).find((r) => r.id === id)?.version ?? id;

  async function run() {
    setBusy(true);
    setErr("");
    setResult(null);
    const sa = { id: a, version: `v${ver(a)}` };
    const sb = { id: b, version: `v${ver(b)}` };
    try {
      const r = await apiRaw("governance", `/releases/${encodeURIComponent(a)}/compare/${encodeURIComponent(b)}`);
      if (!r.ok) {
        // The refusal is an honest answer (a side has no evidence; Evidence cannot be asked).
        // It names releases by id; the person picked them by version.
        const j = (await r.json().catch(() => ({}))) as { title?: string; detail?: string };
        const text = [j.title, j.detail].filter(Boolean).join(": ") || `governance answered ${r.status}`;
        setErr(text.replaceAll(a, sa.version).replaceAll(b, sb.version));
      } else setResult({ cmp: (await r.json()) as Comparison, a: sa, b: sb });
    } catch (e) {
      setErr(errorText(e));
    }
    setBusy(false);
  }

  if (products.isError) return <ErrorPanel error={products.error} />;
  const fixed = result?.cmp.fixed ?? [];
  const fresh = result?.cmp.new ?? [];
  const persisting = result?.cmp.persisting ?? [];

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Compare two releases</CardTitle>
          <CardDescription>
            A CVE is fixed when the new release's evidence opens no Finding for it while the old release keeps its record. Pick the release you
            shipped (baseline) and the build that claims to fix things (candidate), from the same project.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-4">
            <label className="flex flex-col gap-1 text-xs font-medium text-ink-2">
              Product
              <Select
                value={product}
                onChange={(e) => {
                  setProduct(e.target.value);
                  setProject("");
                  setA("");
                  setB("");
                }}
              >
                <option value="">— pick a product —</option>
                {(products.data ?? []).map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
              </Select>
            </label>
            <label className="flex flex-col gap-1 text-xs font-medium text-ink-2">
              Project
              <Select
                value={project}
                disabled={!product}
                onChange={(e) => {
                  setProject(e.target.value);
                  setA("");
                  setB("");
                }}
              >
                <option value="">— pick a project —</option>
                {(projects.data ?? []).map((j) => (
                  <option key={j.id} value={j.id}>
                    {j.name}
                  </option>
                ))}
              </Select>
            </label>
            {(
              [
                ["Baseline release", a, setA, "— baseline —"],
                ["Candidate release", b, setB, "— candidate —"],
              ] as const
            ).map(([label, v, set, none]) => (
              <label key={label} className="flex flex-col gap-1 text-xs font-medium text-ink-2">
                {label}
                <Select value={v} disabled={!project} onChange={(e) => set(e.target.value)}>
                  <option value="">{none}</option>
                  {(releases.data ?? []).map((r) => (
                    <option key={r.id} value={r.id}>
                      v{r.version}
                    </option>
                  ))}
                </Select>
              </label>
            ))}
          </div>
          <Button className="mt-4" disabled={!a || !b || a === b || busy} onClick={run}>
            {busy && <Loader2 className="animate-spin" aria-hidden />}
            {busy ? "Comparing…" : "Compare"}
          </Button>
        </CardContent>
      </Card>

      {err && <ErrorPanel error={new Error(err)} />}

      {result && (
        <>
          <Card className="flex flex-wrap gap-x-6 gap-y-2 px-4 py-3">
            <Count value={fixed.length} label="Fixed" note={`on ${result.a.version}, no Finding on ${result.b.version}`} tone="text-good" />
            <Count value={fresh.length} label="New" note={`on ${result.b.version} only`} tone={fresh.length ? "text-crit" : undefined} />
            <Count value={persisting.length} label="Persisting" note="open on both: the fix did not cover these" />
            <Count value={persisting.filter((p) => p.has_position).length} label="Decided" note="of the persisting, carry a decision" />
          </Card>
          <Bucket title={`Fixed in ${result.b.version}`} tone="good" rows={fixed} empty="Nothing fixed" onOpen={setDrawer}>
            On {result.a.version} and no Finding on {result.b.version}, shown with the baseline's state, which stays on record. A just-uploaded
            candidate may still be correlating; check again once it settles.
          </Bucket>
          <Bucket title={`New in ${result.b.version}`} tone="crit" rows={fresh} empty="Nothing new" onOpen={setDrawer}>
            No Finding on {result.a.version}: brought in by new components, or published after the baseline's last correlation.
          </Bucket>
          <Bucket title="Persisting" tone="warn" rows={persisting} empty="Nothing persists" onOpen={setDrawer}>
            Open on both releases, shown with the candidate's state. Decisions do not carry across releases.
          </Bucket>
          <Advisor key={`${result.a.id}-${result.b.id}`} a={result.a} b={result.b} />
        </>
      )}
      <FindingDrawer
        entry={drawer}
        releaseId={drawer?.release_id ?? ""}
        version={drawer?.release_id === result?.a.id ? ver(result?.a.id ?? "") : ver(result?.b.id ?? "")}
        onClose={() => setDrawer(null)}
      />
    </div>
  );
}
