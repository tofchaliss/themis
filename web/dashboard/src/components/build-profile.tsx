// The build profile of a Project or a Release (EDR-REBUILD-01 D10, step R2a): a JSON block that
// tells a build system how to rebuild the image. Themis stores it and passes it on; it does not
// read inside it. This form checks only that the text is one JSON object. Every other rule is
// the Registry's, and its refusal is shown as it came.
import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorPanel } from "@/components/states";
import { when } from "@/components/when";
import { apiDelete, apiGet, apiPut, ApiError } from "@/lib/api";
import type { components as Registry } from "@/types/api/registry";

type History = Registry["schemas"]["BuildProfileHistory"];
type Resolved = Registry["schemas"]["ResolvedBuildProfile"];

export type BuildProfileKind = "project" | "release";

/** The profile as text, or why it cannot be sent. */
export function parseProfile(text: string): { profile: Record<string, unknown> } | { error: string } {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    return { error: "this is not valid JSON" };
  }
  if (v === null || typeof v !== "object" || Array.isArray(v)) return { error: "the profile must be one JSON object, in { }" };
  return { profile: v as Record<string, unknown> };
}

const failure = (e: unknown) => (e instanceof ApiError ? e.message : "request failed");

export function BuildProfileEditor({ kind, id, name, actor, canWrite }: { kind: BuildProfileKind; id: string; name: string; actor: string; canWrite: boolean }) {
  const qc = useQueryClient();
  const path = `/${kind}s/${encodeURIComponent(id)}/build-profile`;
  const key = ["build-profile", kind, id];
  const stored = useQuery({ queryKey: key, queryFn: () => apiGet<History>("registry", path) });
  const resolved = useQuery({
    queryKey: ["build-profile-resolved", id],
    enabled: kind === "release",
    queryFn: () => apiGet<Resolved>("registry", `${path}/resolved`),
  });
  const current = stored.data?.current;
  const [draft, setDraft] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const value = draft ?? (current ? JSON.stringify(current.profile, null, 2) : "");
  const done = (said: string) => {
    setDraft(null);
    setNote(said);
    void qc.invalidateQueries({ queryKey: key });
    void qc.invalidateQueries({ queryKey: ["build-profile-resolved"] });
  };
  const save = useMutation({
    mutationFn: (profile: Record<string, unknown>) => apiPut("registry", path, { profile, actor }),
    onSuccess: () => done("saved"),
    onError: (e) => setNote(`not saved: ${failure(e)}`),
  });
  const remove = useMutation({
    mutationFn: () => apiDelete("registry", `${path}?actor=${encodeURIComponent(actor)}`),
    onSuccess: () => done("removed"),
    onError: (e) => setNote(`not removed: ${failure(e)}`),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const parsed = parseProfile(value);
    if ("error" in parsed) {
      setNote(`not saved: ${parsed.error}`);
      return;
    }
    save.mutate(parsed.profile);
  };
  const onRemove = () => {
    if (!window.confirm(`Remove the build profile of this ${kind}? The history is kept.`)) return;
    remove.mutate();
  };
  const busy = save.isPending || remove.isPending;
  const history = stored.data?.history ?? [];
  const inForce = resolved.data;

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Build profile — {kind} {name}
        </CardTitle>
        <CardDescription>
          Tells your build system how to rebuild the image of a release. Themis stores it and passes it on with a rebuild request; it does not
          read inside it. A profile is stored on a project. A release may have its own, which then replaces the project's as a whole. It must be
          one JSON object, at most 16 KiB and 5 levels deep. Needs a write-capable key.
        </CardDescription>
        <CardDescription>
          <b>No secrets here.</b> Passwords, tokens and keys stay on the build side; a key named like one is refused. With no profile, Themis only
          recommends a rebuild and never asks for one.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {stored.isError ? (
          <ErrorPanel error={stored.error} />
        ) : stored.isPending ? (
          <p className="text-ink-2">reading…</p>
        ) : stored.data === null ? (
          <p className="text-ink-2">This Registry has no build profiles yet. Upgrade the Registry node.</p>
        ) : (
          <>
            <p className="text-ink-2">
              {current
                ? `Stored here: revision ${current.revision}, saved by ${current.actor}, ${when(current.recorded_at)}.`
                : `No profile is stored on this ${kind}.`}
              {inForce?.found && ` In force for this release: the ${inForce.scope}'s profile, revision ${inForce.record?.revision}.`}
              {inForce && !inForce.found && " No profile is in force for this release: a rebuild can only be recommended."}
            </p>
            <form onSubmit={submit} className="flex flex-col gap-2">
              <label htmlFor="build-profile-input" className="sr-only">
                Build profile
              </label>
              <textarea
                id="build-profile-input"
                rows={10}
                spellCheck={false}
                className="w-full rounded-lg border border-line bg-card p-2 font-mono text-[13px] text-ink focus-visible:outline-2 focus-visible:outline-accent"
                placeholder='{"image": "registry.example/app", "branch": "main"}'
                value={value}
                onChange={(e) => setDraft(e.target.value)}
              />
              <div className="flex flex-wrap items-center gap-2">
                <Button type="submit" disabled={!canWrite || busy} title={canWrite ? undefined : "Your key is read-only"}>
                  Save profile
                </Button>
                {current && (
                  <Button type="button" variant="outline" disabled={!canWrite || busy} onClick={onRemove}>
                    Remove profile
                  </Button>
                )}
                <span className="text-ink-2" role="status">
                  {busy ? "working…" : note}
                </span>
              </div>
            </form>
            {history.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-left">
                  <caption className="pb-1 text-left font-medium">History</caption>
                  <thead>
                    <tr className="text-ink-2">
                      <th className="py-1.5 pr-3 font-medium">Revision</th>
                      <th className="py-1.5 pr-3 font-medium">Change</th>
                      <th className="py-1.5 pr-3 font-medium">By</th>
                      <th className="py-1.5 pr-3 font-medium">When</th>
                      <th className="py-1.5 pr-3 font-medium">SHA-256</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((h) => (
                      <tr key={h.revision} className="border-t border-line">
                        <td className="py-1.5 pr-3">{h.revision}</td>
                        <td className="py-1.5 pr-3">{h.removed ? "removed" : "saved"}</td>
                        <td className="py-1.5 pr-3">{h.actor}</td>
                        <td className="py-1.5 pr-3">{when(h.recorded_at)}</td>
                        <td className="py-1.5 pr-3 font-mono">{(h.sha256 ?? "").slice(0, 12)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
