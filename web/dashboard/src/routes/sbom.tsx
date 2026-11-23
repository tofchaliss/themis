// SBOM manager (EDR-GUI-02 G3): file an SBOM, a scanner report or a VEX against a release, and
// list what a release has on file. A build that is not registered yet is the normal case: pick
// "New…" and the release (and, if needed, its product and project) is registered on upload,
// the same Product → Project → Release chain scripts/gf-upload-sbom.sh drives.
import { useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/native-select";
import { Skeleton } from "@/components/ui/skeleton";
import { Empty, ErrorPanel } from "@/components/states";
import {
  errorText,
  followReceipt,
  intakeContentType,
  isPending,
  needsScanDate,
  reasonMeaning,
  receiptOutcome,
  register,
  sendIntake,
  sendVex,
  type Outcome,
} from "@/lib/intake";
import { useEvidence, useProducts, useProjects, useReleases } from "@/lib/queries";
import { releaseHash } from "@/lib/router";
import { cn } from "@/lib/utils";

const NEW = "__new__";

function Field({ label, htmlFor, children, note }: { label: string; htmlFor: string; children: ReactNode; note?: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <label htmlFor={htmlFor} className="text-xs font-medium text-ink-2">
        {label}
      </label>
      {children}
      {note && <span className="text-xs text-muted">{note}</span>}
    </div>
  );
}

function OutcomePanel({ o }: { o: Outcome }) {
  return (
    <div
      role={o.tone === "err" ? "alert" : "status"}
      className={cn("mt-3 rounded-lg border p-3", o.tone === "err" ? "border-crit/40 bg-crit/10" : "border-line bg-page")}
    >
      <b>{o.title}</b>
      {o.reason && (
        <div className="mt-1">
          Reason <code className="font-mono text-xs">{o.reason}</code> <span className="text-ink-2">: {reasonMeaning(o.reason)}</span>
        </div>
      )}
      <div className="mt-1 text-ink-2">{o.detail}</div>
    </div>
  );
}

const ago = (iso?: string) => {
  if (!iso) return "—";
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
};

function EvidenceList({ releaseId, where }: { releaseId: string; where: string }) {
  const ev = useEvidence(releaseId);
  if (!releaseId) return <Empty title="Pick a release">Its documents are listed here.</Empty>;
  return (
    <>
      <p className="mb-2 px-4 text-ink-2">
        <b className="text-ink">{where}</b> <span className="font-mono text-xs text-muted">({releaseId})</span>
      </p>
      {ev.isPending ? (
        <Skeleton className="mx-4 h-16" />
      ) : ev.isError ? (
        <div className="px-4">
          <ErrorPanel error={ev.error} />
        </div>
      ) : !ev.data.length ? (
        <Empty title="No evidence filed yet">Upload the first SBOM above.</Empty>
      ) : (
        <table className="w-full text-left">
          <thead className="border-y border-line text-xs text-ink-2">
            <tr>
              <th className="py-2 pr-3 pl-4 font-medium">Kind</th>
              <th className="py-2 pr-3 font-medium">Source</th>
              <th className="py-2 pr-3 font-medium">Evidence id</th>
              <th className="py-2 pr-3 font-medium">Fingerprint</th>
              <th className="py-2 pr-3 font-medium">Filed</th>
            </tr>
          </thead>
          <tbody>
            {ev.data.map((e) => (
              <tr key={e.id} className="border-b border-line">
                <td className="py-2 pr-3 pl-4">{e.kind}</td>
                <td className="py-2 pr-3">
                  {e.provenance_source ? (
                    <Badge tone="accent" title="who produced the document: a label, never authority">
                      {e.provenance_source}
                    </Badge>
                  ) : (
                    "—"
                  )}
                </td>
                <td className="py-2 pr-3 font-mono text-xs">{e.id}</td>
                <td className="py-2 pr-3 font-mono text-xs">{(e.fingerprint ?? "").slice(0, 16)}…</td>
                <td className="py-2 pr-3" title={e.filed_at}>
                  {ago(e.filed_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="px-4 pt-3">
        <a className="text-accent" href={releaseHash(releaseId)}>
          Open this release →
        </a>
      </p>
    </>
  );
}

export function Sbom() {
  const qc = useQueryClient();
  const products = useProducts();
  const [product, setProduct] = useState("");
  const [project, setProject] = useState("");
  const [release, setRelease] = useState("");
  const [names, setNames] = useState({ product: "", project: "", release: "" });
  const projects = useProjects(product && product !== NEW ? product : null);
  const releases = useReleases(project && project !== NEW ? project : null);
  const [kind, setKind] = useState<"sbom" | "vex">("sbom");
  const [file, setFile] = useState<File | null>(null);
  const [scanDate, setScanDate] = useState("");
  const [busy, setBusy] = useState(false);
  const [outcome, setOutcome] = useState<Outcome | null>(null);

  const pickProduct = (v: string) => {
    setProduct(v);
    setProject(v === NEW ? NEW : "");
    setRelease(v === NEW ? NEW : "");
    setNames({ product: "", project: "", release: "" });
  };
  const pickProject = (v: string) => {
    setProject(v);
    setRelease(v === NEW ? NEW : "");
    setNames((n) => ({ ...n, project: "", release: "" }));
  };

  const ready =
    !!file &&
    !!release &&
    (release !== NEW ||
      (!!names.release.trim() && (project !== NEW || !!names.project.trim()) && (product !== NEW || !!names.product.trim())));

  // Register the "New…" chain first, product → project → release. A name that already exists is
  // refused: reuse is a pick from the list, never a second registration.
  async function resolveRelease(): Promise<string> {
    if (release !== NEW) return release;
    let productId = product;
    if (productId === NEW) {
      const name = names.product.trim();
      if ((products.data ?? []).some((p) => (p.name ?? "").toLowerCase() === name.toLowerCase()))
        throw new Error(`A product named “${name}” already exists. Pick it from the list instead.`);
      productId = await register("/products", { name }, "product");
      await qc.invalidateQueries({ queryKey: ["products"] });
      setProduct(productId);
    }
    let projectId = project;
    if (projectId === NEW) {
      const name = names.project.trim();
      if ((projects.data ?? []).some((j) => (j.name ?? "").toLowerCase() === name.toLowerCase()))
        throw new Error(`A project named “${name}” already exists here. Pick it from the list instead.`);
      projectId = await register("/projects", { product_id: productId, name }, "project");
      await qc.invalidateQueries({ queryKey: ["projects", productId] });
      setProject(projectId);
    }
    const version = names.release.trim();
    if ((releases.data ?? []).some((r) => r.version === version)) throw new Error(`Release v${version} already exists. Pick it from the list instead.`);
    const releaseId = await register("/releases", { project_id: projectId, version }, "release");
    await qc.invalidateQueries({ queryKey: ["releases", projectId] });
    setRelease(releaseId);
    setNames({ product: "", project: "", release: "" });
    return releaseId;
  }

  async function upload() {
    if (!file) return;
    setBusy(true);
    setOutcome(null);
    try {
      const releaseId = await resolveRelease();
      if (kind === "vex") setOutcome(await sendVex(file, releaseId));
      else {
        const res = await sendIntake(file, releaseId, scanDate);
        if ("tone" in res) setOutcome(res);
        else {
          setOutcome(receiptOutcome(res));
          if (isPending(res)) {
            const done = await followReceipt(res);
            setOutcome(
              done
                ? receiptOutcome(done)
                : { tone: "note", title: "Still working", detail: `Read the receipt later at /api/v1/intake/${res.intake_id}.` },
            );
          }
        }
      }
      await qc.invalidateQueries({ queryKey: ["evidence", releaseId] });
    } catch (e) {
      setOutcome({ tone: "err", title: "Upload failed", detail: errorText(e) });
    }
    setBusy(false);
  }

  if (products.isError) return <ErrorPanel error={products.error} />;

  const nameOf = (list: { id?: string; name?: string; version?: string }[] | undefined, id: string, v = false) => {
    const x = (list ?? []).find((i) => i.id === id);
    return x ? (v ? `v${x.version}` : (x.name ?? "")) : "";
  };
  const shownRelease = release && release !== NEW ? release : "";
  const where = `${nameOf(products.data, product)} / ${nameOf(projects.data, project)} / ${nameOf(releases.data, release, true)}`;

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Upload evidence</CardTitle>
          <CardDescription>
            An SBOM (CycloneDX or SPDX), a scanner report, or a VEX, filed against a release. SBOMs and reports go through the one intake door,
            which identifies the format itself: Trivy, Grype and Cortex JSON, Cortex and Nessus CSV upload as the tool wrote them. A Nessus
            .nessus export is filed as the release's SBOM; the Nessus CSV of the same scan is its report and needs the scan date. A report needs
            the release's SBOM first. The same bytes again keep the same evidence id; the same bytes on another release are refused.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-3">
            <Field label="Product" htmlFor="sb-product">
              <Select id="sb-product" value={product} onChange={(e) => pickProduct(e.target.value)} disabled={products.isPending}>
                <option value="">— pick a product —</option>
                {(products.data ?? []).map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}
                  </option>
                ))}
                <option value={NEW}>+ New product…</option>
              </Select>
              {product === NEW && (
                <Input aria-label="New product name" placeholder="new product name" value={names.product} onChange={(e) => setNames({ ...names, product: e.target.value })} />
              )}
            </Field>
            <Field label="Project" htmlFor="sb-project">
              <Select id="sb-project" value={project} onChange={(e) => pickProject(e.target.value)} disabled={!product || product === NEW}>
                {product === NEW ? (
                  <option value={NEW}>+ New project…</option>
                ) : (
                  <>
                    <option value="">— pick a project —</option>
                    {(projects.data ?? []).map((j) => (
                      <option key={j.id} value={j.id}>
                        {j.name}
                      </option>
                    ))}
                    <option value={NEW}>+ New project…</option>
                  </>
                )}
              </Select>
              {project === NEW && (
                <Input aria-label="New project name" placeholder="new project name" value={names.project} onChange={(e) => setNames({ ...names, project: e.target.value })} />
              )}
            </Field>
            <Field label="Release" htmlFor="sb-release">
              <Select id="sb-release" value={release} onChange={(e) => setRelease(e.target.value)} disabled={!project || project === NEW}>
                {project === NEW ? (
                  <option value={NEW}>+ New release…</option>
                ) : (
                  <>
                    <option value="">— pick a release —</option>
                    {(releases.data ?? []).map((r) => (
                      <option key={r.id} value={r.id}>
                        v{r.version}
                      </option>
                    ))}
                    <option value={NEW}>+ New release…</option>
                  </>
                )}
              </Select>
              {release === NEW && (
                <Input aria-label="New release version" placeholder="version, e.g. 1.4.0" value={names.release} onChange={(e) => setNames({ ...names, release: e.target.value })} />
              )}
            </Field>
            <Field label="Kind" htmlFor="sb-kind">
              <Select id="sb-kind" value={kind} onChange={(e) => setKind(e.target.value as "sbom" | "vex")}>
                <option value="sbom">SBOM or scanner report</option>
                <option value="vex">VEX</option>
              </Select>
            </Field>
            <Field
              label="Document"
              htmlFor="sb-file"
              note={
                file
                  ? `${file.name} · ${(file.size / 1024).toFixed(0)} KB · sent as ${intakeContentType(file.name)}; the door identifies it`
                  : "A .json, .csv or .nessus file (CycloneDX, SPDX, Nessus, Trivy, Grype, Cortex, or already curated)."
              }
            >
              <input
                id="sb-file"
                type="file"
                accept=".json,.csv,.nessus,.xml,application/json,text/csv,application/xml"
                className="text-[13px]"
                onChange={(e) => {
                  const f = e.target.files?.[0] ?? null;
                  setFile(f);
                  setOutcome(null);
                  if (!f || !needsScanDate(f.name)) setScanDate("");
                }}
              />
            </Field>
            {file && needsScanDate(file.name) && (
              <Field label="Scan date" htmlFor="sb-observed" note="When the scan ran. A CSV does not say, and Themis never stamps “now”.">
                <Input id="sb-observed" type="date" value={scanDate} onChange={(e) => setScanDate(e.target.value)} />
              </Field>
            )}
          </div>
          <Button className="mt-4" disabled={!ready || busy} onClick={upload}>
            {busy && <Loader2 className="animate-spin" aria-hidden />}
            {busy ? "Uploading…" : "Upload"}
          </Button>
          {outcome && <OutcomePanel o={outcome} />}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Evidence on the selected release</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto px-0">
          {release === NEW ? (
            <Empty title="A new release starts empty">Upload its first document above; it is registered on upload.</Empty>
          ) : (
            <EvidenceList releaseId={shownRelease} where={where} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
