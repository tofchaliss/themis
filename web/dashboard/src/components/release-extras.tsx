// The release page's remaining cards (EDR-GUI-02 G5): the remediation plan (AI, ephemeral), the
// customer VEX document (preview, view, publish), and the publications with the publishable
// queue. Publishing is always a person's act; a preview records nothing.
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Sheet } from "@/components/ui/sheet";
import { AiResultView, invokeCapability, type AiResult } from "@/components/ai-bits";
import { StanceBadge } from "@/components/finding-bits";
import { Empty, ErrorPanel } from "@/components/states";
import { apiGet, apiPost } from "@/lib/api";
import { errorText } from "@/lib/intake";
import { asArray } from "@/lib/utils";
import type { components as Communication } from "@/types/api/communication";

type Publication = Communication["schemas"]["PublicationView"];
type Queued = Communication["schemas"]["QueueEntryView"];
type RollupStatus = Communication["schemas"]["RollupStatus"];
type Rollup = Communication["schemas"]["RollupView"];

/** The plan groups the release's open findings into the package upgrades that clear them; the
 * grouping is deterministic, the model writes only the narrative. Nothing is recorded. */
export function RemediationPlanCard({ releaseId }: { releaseId: string }) {
  const [busy, setBusy] = useState(false);
  const [res, setRes] = useState<AiResult | null>(null);
  const [err, setErr] = useState("");
  async function draft() {
    setBusy(true);
    setErr("");
    setRes(null);
    try {
      setRes(await invokeCapability("plan_remediation", { type: "release", ids: [releaseId] }));
    } catch (e) {
      setErr(errorText(e));
    }
    setBusy(false);
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          Remediation plan{" "}
          <Badge tone="ai" title="Information: shown now, stored nowhere; the worst outcome is you disagreeing with it">
            AI · ephemeral
          </Badge>
        </CardTitle>
        <CardDescription>
          Groups this release's open findings into the package upgrades that clear them. The grouping is deterministic; the model only writes the
          narrative. Nothing is recorded; ask again any time.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div>
          <Button onClick={draft} disabled={busy}>
            {busy && <Loader2 className="animate-spin" aria-hidden />}
            {busy ? "Drafting, may take a minute…" : "Draft a remediation plan"}
          </Button>
        </div>
        {err && <ErrorPanel error={new Error(err)} />}
        {res && <AiResultView r={res} missing="This Intelligence node does not offer plan_remediation." />}
      </CardContent>
    </Card>
  );
}

type Doc = { title: string; format: string; stance?: string; note?: string; payload: string };

/** The reading surface for a published document and for a preview: the same view, differing only
 * in its note. JSON is shown indented; markdown and text stay as they are. */
export function DocSheet({ doc, onClose }: { doc: Doc | null; onClose: () => void }) {
  let text = doc?.payload ?? "";
  try {
    text = JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    /* not JSON: shown as is */
  }
  const ext = ({ markdown: "md", text: "txt" } as Record<string, string>)[doc?.format ?? ""] ?? "json";
  const download = () => {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([doc?.payload ?? ""], { type: "text/plain" }));
    a.download = `${doc?.title || "publication"}.${doc?.format || "artifact"}.${ext}`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };
  return (
    <Sheet open={!!doc} onClose={onClose} labelledBy="doc-title" className="max-w-[820px]">
      {doc && (
        <>
          <header className="flex flex-wrap items-center gap-2 border-b border-line px-5 py-4 pr-12">
            <h2 id="doc-title" className="font-mono text-base font-semibold">
              {doc.title}
            </h2>
            <Badge>{doc.format}</Badge>
            {doc.stance && <StanceBadge stance={doc.stance} decided />}
            {doc.note && <Badge tone="warn">{doc.note}</Badge>}
            <Button size="sm" variant="outline" onClick={download}>
              Download
            </Button>
          </header>
          <pre className="min-h-0 flex-1 overflow-auto p-5 font-mono text-xs whitespace-pre-wrap">{text}</pre>
        </>
      )}
    </Sheet>
  );
}

function RollupLine({ r }: { r: RollupStatus | null | undefined }) {
  if (r === undefined) return <Badge tone="info" title="the communication node did not answer the status read">status unavailable</Badge>;
  if (!r?.found) return <Badge tone="info">none published yet</Badge>;
  const meta = (
    <span className="font-mono text-xs text-ink-2">
      {r.statements} statements · as of {r.as_of}
    </span>
  );
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      {r.stale ? (
        <Badge tone="warn" title="the live posture differs from what the published document was built from; republish when ready">
          {r.summary || "STALE"}
        </Badge>
      ) : (
        <Badge tone="accent" title="the live posture matches the published document's inputs exactly">
          current
        </Badge>
      )}
      {meta}
    </span>
  );
}

/** One multi-statement OpenVEX file for the whole release: decided findings speak their
 * decision, everything else is under_investigation, machine clearances annotate, never assert. */
export function CustomerVexCard({ releaseId, canWrite, onDoc }: { releaseId: string; canWrite: boolean; onDoc: (d: Doc) => void }) {
  const qc = useQueryClient();
  const status = useQuery({
    queryKey: ["rollup-status", releaseId],
    queryFn: () => apiGet<RollupStatus>("communication", `/releases/${encodeURIComponent(releaseId)}/rollup-status?audience=customer`),
    retry: false,
  });
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  const r = status.isError ? undefined : (status.data ?? null);

  async function run(what: string, fn: () => Promise<void>) {
    setBusy(what);
    setErr("");
    try {
      await fn();
    } catch (e) {
      setErr(errorText(e));
    }
    setBusy("");
  }
  const preview = () =>
    run("preview", async () => {
      const { data } = await apiPost<{ payload?: string }>("communication", "/previews", { release_id: releaseId, artifact_type: "vex", format: "openvex" });
      onDoc({ title: "Customer VEX", format: "openvex", note: "preview, not recorded", payload: data?.payload ?? "" });
    });
  const view = () =>
    run("view", async () => {
      const doc = await apiGet<Rollup>("communication", `/rollups/${encodeURIComponent(r?.publication_id ?? "")}`);
      onDoc({ title: "Customer VEX", format: "openvex", note: `as of ${doc?.as_of ?? ""}`, payload: doc?.payload ?? "" });
    });
  const publish = () =>
    run("publish", async () => {
      await apiPost("communication", "/publications", { release_id: releaseId, artifact_type: "vex", format: "openvex", audience: "customer" });
      await qc.invalidateQueries({ queryKey: ["rollup-status", releaseId] });
      await qc.invalidateQueries({ queryKey: ["publications", releaseId] });
    });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Customer VEX document</CardTitle>
        <CardDescription>
          One OpenVEX file for this whole release: decided findings speak their decision; everything else is under_investigation; machine
          clearances annotate, never assert. Publishing is always a person's act.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div>{status.isPending ? <Loader2 className="size-4 animate-spin" aria-label="Loading status" /> : <RollupLine r={r} />}</div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" onClick={preview} disabled={!!busy}>
            Preview
          </Button>
          {r?.found && (
            <Button variant="outline" onClick={view} disabled={!!busy}>
              View published
            </Button>
          )}
          {canWrite && (
            <Button onClick={publish} disabled={!!busy}>
              {busy === "publish" && <Loader2 className="animate-spin" aria-hidden />}
              {r?.found ? "Republish (supersedes the current one)" : "Publish"}
            </Button>
          )}
        </div>
        {err && <ErrorPanel error={new Error(err)} />}
      </CardContent>
    </Card>
  );
}

/** What was published for this release, and the decisions waiting to be. */
export function PublicationsCard({ releaseId, onDoc }: { releaseId: string; onDoc: (d: Doc) => void }) {
  const pubs = useQuery({
    queryKey: ["publications", releaseId],
    queryFn: async () => asArray<Publication>(await apiGet("communication", `/publications?release=${encodeURIComponent(releaseId)}`)),
    retry: false,
  });
  const queue = useQuery({
    queryKey: ["publishable", releaseId],
    queryFn: async () => asArray<Queued>(await apiGet("communication", "/publishable-positions")).filter((q) => q.release_id === releaseId),
    retry: false,
  });
  const [err, setErr] = useState("");

  const open = async (id: string) => {
    setErr("");
    try {
      const p = await apiGet<Publication>("communication", `/publications/${encodeURIComponent(id)}`);
      if (!p) return setErr("Publication not found.");
      onDoc({ title: p.cve ?? "publication", format: p.format ?? "", stance: p.stance, note: p.superseded ? "superseded" : undefined, payload: p.payload ?? "" });
    } catch (e) {
      setErr(errorText(e));
    }
  };
  // A preview renders the decision as the document it would publish, recording nothing (D9).
  const preview = async (q: Queued) => {
    setErr("");
    try {
      const { data } = await apiPost<{ payload?: string }>("communication", "/previews", { finding_id: q.finding_id, artifact_type: "vex", format: "openvex" });
      onDoc({ title: q.cve ?? "preview", format: "openvex", stance: q.stance, note: "preview, not recorded", payload: data?.payload ?? "" });
    } catch (e) {
      setErr(errorText(e));
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Publications</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3 overflow-x-auto px-0">
        {err && (
          <div className="px-4">
            <ErrorPanel error={new Error(err)} />
          </div>
        )}
        {pubs.isError ? (
          <div className="px-4">
            <ErrorPanel error={pubs.error} />
          </div>
        ) : !pubs.data?.length ? (
          <Empty title="Nothing published for this release">Decide, then publish: publication is always a person's act.</Empty>
        ) : (
          <table className="w-full text-left">
            <thead className="border-y border-line text-xs text-ink-2">
              <tr>
                <th className="py-2 pr-3 pl-4 font-medium">Artifact</th>
                <th className="py-2 pr-3 font-medium">Format</th>
                <th className="py-2 pr-3 font-medium">CVE</th>
                <th className="py-2 pr-3 font-medium">Decision</th>
                <th className="py-2 pr-3 font-medium">Delivery</th>
                <th className="py-2 pr-3 font-medium">Superseded</th>
              </tr>
            </thead>
            <tbody>
              {pubs.data.map((p) => (
                <tr key={p.id} className="cursor-pointer border-b border-line hover:bg-hover" onClick={() => open(p.id ?? "")} tabIndex={0} onKeyDown={(e) => e.key === "Enter" && open(p.id ?? "")} aria-label={`Open the ${p.format} document for ${p.cve}`}>
                  <td className="py-2 pr-3 pl-4">{p.artifact_type}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{p.format}</td>
                  <td className="py-2 pr-3 font-mono text-xs">{p.cve}</td>
                  <td className="py-2 pr-3">
                    <StanceBadge stance={p.stance} decided />
                  </td>
                  <td className="py-2 pr-3">{p.delivery_status}</td>
                  <td className="py-2 pr-3">{p.superseded ? "yes" : "no"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {!!queue.data?.length && (
          <>
            <h3 className="px-4 pt-2 text-sm font-semibold">Publishable queue</h3>
            <table className="w-full text-left">
              <thead className="border-y border-line text-xs text-ink-2">
                <tr>
                  <th className="py-2 pr-3 pl-4 font-medium">CVE</th>
                  <th className="py-2 pr-3 font-medium">Decision</th>
                  <th className="py-2 pr-3 text-right font-medium">Version</th>
                  <th className="py-2 pr-3 font-medium">Stale</th>
                  <th className="py-2 pr-3" />
                </tr>
              </thead>
              <tbody>
                {queue.data.map((q) => (
                  <tr key={`${q.finding_id}-${q.version}`} className="border-b border-line">
                    <td className="py-2 pr-3 pl-4 font-mono text-xs">{q.cve}</td>
                    <td className="py-2 pr-3">
                      <StanceBadge stance={q.stance} decided />
                    </td>
                    <td className="py-2 pr-3 text-right tabular-nums">{q.version}</td>
                    <td className="py-2 pr-3">{q.stale ? <Badge tone="warn">stale</Badge> : "current"}</td>
                    <td className="py-2 pr-3">
                      <Button size="sm" variant="outline" onClick={() => preview(q)} aria-label={`Preview ${q.cve}`}>
                        Preview
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )}
      </CardContent>
    </Card>
  );
}

export type { Doc };
