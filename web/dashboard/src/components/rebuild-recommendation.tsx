// The rebuild recommendation of a Release and the "Start rebuild" action (EDR-REBUILD-01 step
// R4). In mode ask Themis only recommends a rebuild; a person starts it here. The page shows
// what Governance recorded and sends the approval; every rule is Governance's, and its answer
// is shown as it came. A Release with no recommendation shows nothing.
import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ErrorPanel } from "@/components/states";
import { when } from "@/components/when";
import { apiGet, apiRaw } from "@/lib/api";
import type { components as Governance } from "@/types/api/governance";

type Recommendation = Governance["schemas"]["RebuildRecommendation"];
type Answer = Governance["schemas"]["RebuildApprovalAnswer"];

const stateText: Record<Recommendation["state"], string> = {
  standing: "waiting for a person",
  approved: "approved, rebuild requested",
  superseded: "replaced by a newer recommendation",
  expired: "expired after 7 days with no answer",
  withdrawn: "withdrawn",
};

/** What an approval answer means, in plain words. */
export function answerText(a: Answer): string {
  switch (a.result) {
    case "approved":
      return "Rebuild requested. Themis sent the request to the build side.";
    case "not_standing":
      return a.standing_decision_id
        ? "Not started: a newer recommendation replaced this one. The page now shows the newer one."
        : "Not started: this recommendation can no longer be approved.";
    case "expired":
      return "Not started: this recommendation expired. The next change evaluates the release again.";
    case "withdrawn":
      return `Not started: the rebuild mode of this release is now "${a.effective_mode ?? "unknown"}", not "ask". The recommendation was withdrawn and the release is evaluated again.`;
    default:
      return "Not started: no build profile applies to this release, so there is nothing to ask a build system. Add a build profile on the project first.";
  }
}

/** POST the approval. 200 and 409 both carry an answer; anything else is the node's refusal. */
async function approve(decisionId: string, actor: string): Promise<Answer> {
  const r = await apiRaw("governance", `/rebuild-recommendations/${encodeURIComponent(decisionId)}/approve`, {
    method: "POST",
    body: JSON.stringify({ actor_id: actor }),
  });
  const body = (await r.json().catch(() => ({}))) as Partial<Answer> & { detail?: string; title?: string };
  if ((r.status === 200 || r.status === 409) && body.result) return body as Answer;
  throw new Error(body.detail || body.title || `${r.status}`);
}

export function RebuildRecommendationCard({ releaseId, actor, canWrite }: { releaseId: string; actor: string; canWrite: boolean }) {
  const qc = useQueryClient();
  const key = ["rebuild-recommendation", releaseId];
  const rec = useQuery({
    queryKey: key,
    queryFn: () => apiGet<Recommendation>("governance", `/releases/${encodeURIComponent(releaseId)}/rebuild-recommendation`),
  });
  const [note, setNote] = useState("");
  const start = useMutation({
    mutationFn: (decisionId: string) => approve(decisionId, actor),
    onSuccess: (a) => {
      setNote(answerText(a));
      void qc.invalidateQueries({ queryKey: key });
    },
    onError: (e) => setNote(`Not started: ${e instanceof Error ? e.message : "request failed"}`),
  });
  if (rec.isError) return <ErrorPanel error={rec.error} />;
  const r = rec.data;
  if (!r) return null;
  const d = r.decision;
  const cves = [...new Set(d.targeted.map((t) => t.cve))];
  const noProfile = d.recommend_reason === "no_build_profile";
  const onStart = () => {
    if (!window.confirm(`Start a rebuild of this release for ${d.targeted.length} component(s)? Themis sends the request to your build system.`)) return;
    start.mutate(d.decision_id);
  };
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex flex-wrap items-center gap-2">
          Rebuild recommendation <Badge tone={r.state === "standing" ? "warn" : "neutral"}>{stateText[r.state]}</Badge>
        </CardTitle>
        <CardDescription>
          Themis found components of this release that a rebuild would fix. In mode "ask" nothing is built until a person starts it here. Starting
          sends one request to your build system with exactly the facts below.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-2">
        <p>
          {d.targeted.length} component(s) with a known fix, {cves.length} CVE(s): {cves.slice(0, 8).join(", ")}
          {cves.length > 8 && ` and ${cves.length - 8} more`}.
        </p>
        <p className="text-ink-2">
          Recommended {when(d.decided_at)}.{r.state === "standing" && ` It waits until ${when(r.expires_at)} and then expires.`}
          {d.supersedes && " It replaced an earlier recommendation."}
          {noProfile && " No build profile applies to this release, so a rebuild cannot be requested yet. Add a build profile on the project."}
        </p>
        {r.approval && (
          <p className="text-ink-2">
            Started by {r.approval.actor}, {when(r.approval.approved_at)}
            {r.approval.key_name && ` (key ${r.approval.key_name})`}.{r.cycle_closed ? " The rebuild cycle has closed." : " The rebuild cycle is open."}
          </p>
        )}
        <div className="flex flex-wrap items-center gap-2">
          {r.can_approve && (
            <Button type="button" disabled={!canWrite || start.isPending} title={canWrite ? undefined : "Your key is read-only"} onClick={onStart}>
              Start rebuild
            </Button>
          )}
          <span className="text-ink-2" role="status">
            {start.isPending ? "working…" : note}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
