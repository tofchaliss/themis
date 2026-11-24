// The PSIRT bulletin register (EDR-PSIRT-01 revision 3): the team's own write-ups, kept in
// Knowledge with every change in a history. Anyone signed in reads it; an admin adds, edits
// and removes (R2). Type is derived, never typed (R6): a CVE makes it a Vulnerability.
import { useState, type FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Sheet } from "@/components/ui/sheet";
import { Paged } from "@/components/pager";
import { ago, when } from "@/components/when";
import { apiDelete, apiPost, apiPut, type WhoAmI } from "@/lib/api";
import type { Bulletin, BulletinInput, PSIRTAlert } from "@/lib/queries";

/** Who may change the register: the admin scope when the session states scopes, else (auth
 * off, where no scopes are stated) whoever may write. */
export function canEditBulletins(who: WhoAmI | undefined): boolean {
  if (!who) return false;
  return who.scopes ? who.scopes.includes("admin") : who.can_write;
}

/** What the form opens on: an existing bulletin to edit, or a new one (maybe for a CVE). */
export type BulletinDraft = { bulletin?: Bulletin; cve?: string };

const nvdURL = (cve: string) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`;
const field = "flex flex-col gap-1 text-xs font-medium text-ink-2";

function Link({ href, children }: { href: string; children: string }) {
  return (
    <a className="text-accent" href={href} target="_blank" rel="noreferrer">
      {children}
    </a>
  );
}

export function BulletinForm({ draft, onClose }: { draft: BulletinDraft; onClose: () => void }) {
  const b = draft.bulletin;
  const qc = useQueryClient();
  const [f, setF] = useState({
    bulletin_id: b?.bulletin_id ?? "",
    title: b?.title ?? "",
    cve: b?.cve ?? draft.cve ?? "",
    report_date: b?.report_date ?? "",
    bulletin_url: b?.bulletin_url ?? "",
    alert_url: b?.alert_url ?? "",
    note: b?.note ?? "",
  });
  const [confirmRemove, setConfirmRemove] = useState(false);
  const done = () => {
    void qc.invalidateQueries({ queryKey: ["psirt-bulletins"] });
    void qc.invalidateQueries({ queryKey: ["psirt-alerts"] });
    onClose();
  };
  const save = useMutation({
    mutationFn: async (input: BulletinInput) => {
      if (b) return apiPut<Bulletin>("knowledge", `/psirt/bulletins/${encodeURIComponent(b.id)}`, input);
      return (await apiPost<Bulletin>("knowledge", "/psirt/bulletins", input)).data;
    },
    onSuccess: done,
  });
  const remove = useMutation({
    mutationFn: () => apiDelete("knowledge", `/psirt/bulletins/${encodeURIComponent(b?.id ?? "")}`),
    onSuccess: done,
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const { report_date, ...rest } = f;
    save.mutate(report_date ? { ...rest, report_date } : rest);
  };
  const text = (key: keyof typeof f, label: string, extra?: React.ComponentProps<"input">) => (
    <label className={field}>
      {label}
      <Input value={f[key]} onChange={(e) => setF({ ...f, [key]: e.target.value })} {...extra} />
    </label>
  );
  const failed = save.error ?? remove.error;

  return (
    <Sheet open onClose={onClose} labelledBy="bulletin-form-title">
      <form onSubmit={submit} className="flex h-full flex-col gap-3 overflow-y-auto p-5">
        <h2 id="bulletin-form-title" className="text-base font-semibold">
          {b ? `Edit bulletin ${b.bulletin_id}` : "Add a bulletin"}
        </h2>
        {text("bulletin_id", "Bulletin ID", { required: true, maxLength: 64 })}
        {text("title", "Title", { required: true, maxLength: 300 })}
        {text("cve", "CVE (leave empty for a risk with no CVE)", { placeholder: "CVE-2026-12345" })}
        {text("report_date", "Report date (empty: today)", { type: "date" })}
        {text("bulletin_url", "Bulletin link", { type: "url", placeholder: "https://" })}
        {text("alert_url", "TSN / Alert link", { type: "url", placeholder: "https://" })}
        <label className={field}>
          Note
          <textarea
            className="min-h-24 rounded-lg border border-line bg-card px-2.5 py-1.5 text-[13px] text-ink focus-visible:outline-2 focus-visible:outline-accent"
            maxLength={4000}
            value={f.note}
            onChange={(e) => setF({ ...f, note: e.target.value })}
          />
        </label>
        {failed && (
          <div role="alert" className="rounded-lg border border-crit/50 bg-crit/10 px-3 py-1.5 text-xs">
            {failed.message}
          </div>
        )}
        <div className="flex flex-wrap items-center gap-2">
          <Button type="submit" disabled={save.isPending}>
            {b ? "Save" : "Add bulletin"}
          </Button>
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          {b && !confirmRemove && (
            <Button type="button" variant="ghost" className="ml-auto" onClick={() => setConfirmRemove(true)}>
              Remove
            </Button>
          )}
          {b && confirmRemove && (
            <Button type="button" variant="danger" className="ml-auto" disabled={remove.isPending} onClick={() => remove.mutate()}>
              Yes, remove it
            </Button>
          )}
        </div>
        {b && (
          <p className="text-[11px] text-muted">
            Last changed {when(b.updated_at)}. Every change is kept in the bulletin's history; a removed bulletin leaves the list, its history stays.
          </p>
        )}
      </form>
    </Sheet>
  );
}

export function BulletinTable({
  rows,
  alerts,
  canEdit,
  onEdit,
}: {
  rows: Bulletin[];
  alerts: PSIRTAlert[];
  canEdit: boolean;
  onEdit: (b: Bulletin) => void;
}) {
  const world = new Map(alerts.map((a) => [a.cve, a]));
  return (
    <Paged rows={rows} size={25}>
      {(page) => (
        <table className="w-full text-left text-[13px]">
          <thead className="text-xs text-ink-2">
            <tr className="border-b border-line">
              <th className="py-2 pr-3 pl-4 font-medium">ID</th>
              <th className="py-2 pr-3 font-medium">CVE</th>
              <th className="py-2 pr-3 font-medium">Vulnerability name</th>
              <th className="py-2 pr-3 font-medium">Report date</th>
              <th className="py-2 pr-3 font-medium">Bulletin</th>
              <th className="py-2 pr-3 font-medium">Additional info</th>
              <th className="py-2 pr-3 font-medium">Technology area</th>
              <th className="py-2 pr-3 font-medium">Type</th>
              {canEdit && <th className="py-2 pr-3 font-medium sr-only">Change</th>}
            </tr>
          </thead>
          <tbody>
            {page.map((b) => {
              const a = b.cve ? world.get(b.cve) : undefined;
              return (
                <tr key={b.id} className="border-b border-line align-top last:border-0">
                  <td className="py-2 pr-3 pl-4 font-mono text-xs font-medium whitespace-nowrap">{b.bulletin_id}</td>
                  <td className="py-2 pr-3 font-mono text-xs whitespace-nowrap">{b.cve || <span className="text-muted">none</span>}</td>
                  <td className="py-2 pr-3">{b.title}</td>
                  <td className="py-2 pr-3 whitespace-nowrap">{b.report_date}</td>
                  <td className="py-2 pr-3">
                    {b.bulletin_url ? <Link href={b.bulletin_url}>Bulletin</Link> : <span className="text-xs text-muted">no link</span>}
                  </td>
                  <td className="py-2 pr-3">
                    <span className="flex flex-col gap-0.5 text-xs">
                      {b.cve && <Link href={nvdURL(b.cve)}>CVE record</Link>}
                      {b.alert_url && <Link href={b.alert_url}>TSN / Alert</Link>}
                      {a?.modified && <span title={when(a.modified)}>CVE updated {ago(a.modified)}</span>}
                      {b.note && <span className="max-w-prose whitespace-pre-wrap text-ink-2">{b.note}</span>}
                    </span>
                  </td>
                  <td className="py-2 pr-3">{a?.issue_type || <span className="text-xs text-muted">not stated</span>}</td>
                  <td className="py-2 pr-3">
                    <Badge tone={b.type === "Vulnerability" ? "warn" : "info"}>{b.type}</Badge>
                  </td>
                  {canEdit && (
                    <td className="py-2 pr-3">
                      <Button size="sm" variant="outline" onClick={() => onEdit(b)} aria-label={`Edit bulletin ${b.bulletin_id}`}>
                        Edit
                      </Button>
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </Paged>
  );
}
