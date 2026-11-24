// EDR-GUI-02 D5: one place for the read queries, so two parts of a screen that need the
// same answer share one request and back-navigation is instant.
import { useQuery } from "@tanstack/react-query";
import { apiGet, getAdminStatus, getWhoAmI } from "./api";
import { asArray } from "./utils";
import type { components as Registry } from "@/types/api/registry";
import type { components as Knowledge } from "@/types/api/knowledge";
import type { components as Governance } from "@/types/api/governance";
import type { components as Evidence } from "@/types/api/evidence";

export type Product = Registry["schemas"]["ProductView"];
export type Project = Registry["schemas"]["ProjectView"];
export type Release = Registry["schemas"]["ReleaseView"];
export type TagSet = Registry["schemas"]["TagSet"];
export type FeedHealth = Knowledge["schemas"]["FeedHealthReport"];
export type PostureEntry = Governance["schemas"]["PostureEntry"];

const tagQ = (tag: string) => (tag ? `?tag=${encodeURIComponent(tag)}` : "");
const enc = encodeURIComponent;

export const useWhoAmI = () => useQuery({ queryKey: ["whoami"], queryFn: getWhoAmI, staleTime: 60_000 });
export const useAdminStatus = () => useQuery({ queryKey: ["admin-status"], queryFn: getAdminStatus, staleTime: 60_000 });

export const useProducts = (tag = "") =>
  useQuery({ queryKey: ["products", tag], queryFn: async () => asArray<Product>(await apiGet("registry", `/products${tagQ(tag)}`)) });

export const useProjects = (productId: string | null, tag = "") =>
  useQuery({
    queryKey: ["projects", productId, tag],
    enabled: !!productId,
    queryFn: async () => asArray<Project>(await apiGet("registry", `/products/${enc(productId ?? "")}/projects${tagQ(tag)}`)),
  });

export const useReleases = (projectId: string | null, tag = "") =>
  useQuery({
    queryKey: ["releases", projectId, tag],
    enabled: !!projectId,
    queryFn: async () => asArray<Release>(await apiGet("registry", `/projects/${enc(projectId ?? "")}/releases${tagQ(tag)}`)),
  });

export type TagKind = "product" | "project" | "release";
export const useTags = (kind: TagKind, id: string | null) =>
  useQuery({
    queryKey: ["tags", kind, id],
    enabled: !!id,
    queryFn: async () => (await apiGet<TagSet>("registry", `/${kind}s/${enc(id ?? "")}/tags`)) ?? { tags: [], effective: [] },
  });

export const useFeeds = () => useQuery({ queryKey: ["feeds"], queryFn: () => apiGet<FeedHealth>("knowledge", "/feeds") });

/** Every open Finding across every release, for the Overview's estate risk. One read per
 * release (the DASH-2 posture), fanned out in parallel — fine at estate scale. */
export async function sweepEstate(products: Product[]) {
  const projects = (
    await Promise.all(products.map((p) => apiGet("registry", `/products/${enc(p.id ?? "")}/projects`).then(asArray<Project>).catch(() => [])))
  ).flat();
  const releases = (
    await Promise.all(projects.map((j) => apiGet("registry", `/projects/${enc(j.id ?? "")}/releases`).then(asArray<Release>).catch(() => [])))
  ).flat();
  const findings = (
    await Promise.all(
      releases.map((r) => apiGet("governance", `/releases/${enc(r.id ?? "")}/posture`).then(asArray<PostureEntry>).catch(() => [])),
    )
  ).flat();
  return { releases: releases.length, findings };
}

export const useEstateSweep = (products: Product[] | undefined) =>
  useQuery({ queryKey: ["estate-sweep", products?.map((p) => p.id)], enabled: !!products, queryFn: () => sweepEstate(products ?? []) });

export type Assessment = Governance["schemas"]["FindingAssessment"];
export type Component = Governance["schemas"]["Component"];
export type SLA = Governance["schemas"]["SLAStatus"];
export type ProposalView = Governance["schemas"]["ProposalView"];

export const useRelease = (id: string) =>
  useQuery({ queryKey: ["release", id], queryFn: () => apiGet<Release>("registry", `/releases/${enc(id)}`) });

export const useProduct = (id: string | undefined) =>
  useQuery({ queryKey: ["product", id], enabled: !!id, queryFn: () => apiGet<Product>("registry", `/products/${enc(id ?? "")}`) });

export const useProject = (id: string | undefined) =>
  useQuery({ queryKey: ["project", id], enabled: !!id, queryFn: () => apiGet<Project>("registry", `/projects/${enc(id ?? "")}`) });

const postureQuery = (releaseId: string) => ({
  queryKey: ["posture", releaseId],
  queryFn: async () => asArray<PostureEntry>(await apiGet("governance", `/releases/${enc(releaseId)}/posture`)),
});

export const usePosture = (releaseId: string) => useQuery(postureQuery(releaseId));

export const useAssessment = (findingId: string | undefined) =>
  useQuery({
    queryKey: ["assessment", findingId],
    enabled: !!findingId,
    queryFn: () => apiGet<Assessment>("governance", `/findings/${enc(findingId ?? "")}/assessment`),
  });

/** One row of a CVE's releases dropdown (EDR-GUI-02 D13). */
export type CveRelease = { releaseId: string; version: string; project: string; entry: PostureEntry };

/** Every release a CVE is filed under, with that release's Finding for it: ONE Governance
 * read (GET /faultlines/{id}/findings), then Registry names, shared per project. A release
 * whose name cannot be read still shows, by id. */
export async function cveReleases(faultlineId: string): Promise<CveRelease[]> {
  const rows = asArray<PostureEntry>(await apiGet("governance", `/faultlines/${enc(faultlineId)}/findings`));
  const projects = new Map<string, Promise<Project | null>>();
  const projectOf = (id: string) => {
    if (!projects.has(id)) projects.set(id, apiGet<Project>("registry", `/projects/${enc(id)}`).catch(() => null));
    return projects.get(id) as Promise<Project | null>;
  };
  return Promise.all(
    rows.map(async (entry) => {
      const releaseId = entry.release_id ?? "";
      const rel = await apiGet<Release>("registry", `/releases/${enc(releaseId)}`).catch(() => null);
      const proj = rel?.project_id ? await projectOf(rel.project_id) : null;
      return { releaseId, version: rel?.version ?? "", project: proj?.name ?? "", entry };
    }),
  );
}

/** Loaded only when a row's dropdown is opened. */
export const useCveReleases = (faultlineId: string | undefined, open: boolean) =>
  useQuery({ queryKey: ["cve-releases", faultlineId], enabled: open && !!faultlineId, queryFn: () => cveReleases(faultlineId ?? "") });

export type EvidenceSummary = Evidence["schemas"]["EvidenceSummary"];
export type EvidenceFacts = Evidence["schemas"]["EvidenceFacts"];
export type UploadOutcome = Governance["schemas"]["UploadOutcome"];

/** Every document filed against a release (SBOMs, VEX, scanner reports). */
export const useEvidence = (releaseId: string) =>
  useQuery({
    queryKey: ["evidence", releaseId],
    enabled: !!releaseId,
    queryFn: async () => asArray<EvidenceSummary>(await apiGet("evidence", `/evidence?release=${enc(releaseId)}`)),
  });

export const useEvidenceFacts = (id: string) =>
  useQuery({ queryKey: ["evidence-facts", id], queryFn: () => apiGet<EvidenceFacts>("evidence", `/evidence/${enc(id)}`) });

/** A scanner report as filed: the curated {findings:[…]} document. A document that is not one
 * reads as null findings, never as an empty report. */
export type ScanClaim = { cve?: string; severity?: string; cvss_score?: number; component?: { name?: string; version?: string }; fixed?: string[] };
export async function scanReport(id: string): Promise<{ findings: ScanClaim[] | null } | null> {
  const doc = await apiGet<{ kind: string; document: string }>("evidence", `/evidence/${enc(id)}/document`);
  if (!doc) return null;
  try {
    const j = JSON.parse(doc.document) as { findings?: unknown };
    return { findings: Array.isArray(j.findings) ? (j.findings as ScanClaim[]) : null };
  } catch {
    return { findings: null };
  }
}
export const useScanReport = (id: string) => useQuery({ queryKey: ["scan-report", id], queryFn: () => scanReport(id), staleTime: Infinity });

/** What the latest SBOM changed on a release; null before the first one (or on an older node). */
export const useUploadOutcome = (releaseId: string) =>
  useQuery({ queryKey: ["upload-outcome", releaseId], queryFn: () => apiGet<UploadOutcome>("governance", `/releases/${enc(releaseId)}/upload-outcome`) });

export type Faultline = Knowledge["schemas"]["FaultlineView"];
export type RecentFaultline = Knowledge["schemas"]["RecentFaultline"];
export type PublishedCVE = Knowledge["schemas"]["PublishedCVE"];
export type SourceRatings = Knowledge["schemas"]["SourceRatings"];

/** The newest cards that entered this estate's knowledge, newest first. */
export const useRecentCards = () =>
  useQuery({ queryKey: ["recent-cards"], queryFn: async () => asArray<RecentFaultline>(await apiGet("knowledge", "/faultlines/recent?limit=100")) });

/** Narrow cards to those whose Findings sit on releases carrying `tag` (EDR-REMEDIATION-01 D7):
 * one Registry read for the tagged releases, one blast-radius read per card. A card whose read
 * fails is left out, never guessed in. */
export async function cardsOnTag(rows: RecentFaultline[], tag: string): Promise<RecentFaultline[]> {
  const tagged = new Set(asArray<Release>(await apiGet("registry", `/tagged-releases?tag=${enc(tag)}`)).map((r) => r.id));
  if (!tagged.size) return [];
  const keep = await Promise.all(
    rows.map(async (r) => {
      const id = r.card.id;
      if (!id) return false;
      try {
        return asArray<string>(await apiGet("governance", `/faultlines/${enc(id)}/blast-radius`)).some((rel) => tagged.has(rel));
      } catch {
        return false;
      }
    }),
  );
  return rows.filter((_, i) => keep[i]);
}

export const useCard = (cve: string) =>
  useQuery({ queryKey: ["card", cve], queryFn: () => apiGet<Faultline>("knowledge", `/faultlines?cve=${enc(cve)}`) });

export const useCardReleases = (id: string | undefined) =>
  useQuery({ queryKey: ["card-releases", id], enabled: !!id, queryFn: async () => asArray<string>(await apiGet("knowledge", `/faultlines/${enc(id ?? "")}/releases`)) });

export const useCardRatings = (id: string | undefined) =>
  useQuery({ queryKey: ["card-ratings", id], enabled: !!id, queryFn: () => apiGet<SourceRatings>("knowledge", `/faultlines/${enc(id ?? "")}/ratings`) });

export type PSIRTAlerts = Knowledge["schemas"]["PSIRTAlerts"];
export type PSIRTAlert = Knowledge["schemas"]["PSIRTAlert"];

/** The PSIRT early alert (EDR-PSIRT-01 P3): CVEs the world published in the last `days`
 * days at or above `floor`, each with the product components it may hit. Live at Knowledge
 * (cached there 5 minutes), so it is not re-asked more often than that. null = the node has
 * no alert read (an older Knowledge). */
export const usePSIRTAlerts = (days: number, floor: "critical" | "high") =>
  useQuery({
    queryKey: ["psirt-alerts", days, floor],
    staleTime: 5 * 60_000,
    queryFn: () => apiGet<PSIRTAlerts>("knowledge", `/psirt/alerts?days=${days}&min_severity=${floor}`),
  });

export type Bulletin = Knowledge["schemas"]["Bulletin"];
export type BulletinInput = Knowledge["schemas"]["BulletinInput"];

/** The PSIRT bulletin register (EDR-PSIRT-01 revision 3), newest report date first. null = the
 * node has no register (an older Knowledge). */
export const useBulletins = () =>
  useQuery({ queryKey: ["psirt-bulletins"], queryFn: () => apiGet<Bulletin[]>("knowledge", "/psirt/bulletins") });
