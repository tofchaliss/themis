// EDR-GUI-02 D5: one place for the read queries, so two parts of a screen that need the
// same answer share one request and back-navigation is instant.
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { apiGet, getAdminStatus, getWhoAmI } from "./api";
import { asArray } from "./utils";
import type { components as Registry } from "@/types/api/registry";
import type { components as Knowledge } from "@/types/api/knowledge";
import type { components as Governance } from "@/types/api/governance";

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
export type CveRelease = { releaseId: string; version: string; project: string; entry: PostureEntry | null };

/** Every release a CVE is filed under, with that release's Finding for it. Built from the
 * existing reads (Knowledge's rollup, Registry names, each release's posture), one release at
 * a time, until Governance answers it in one call (the D13 API gap). Posture reads are shared
 * with the release screen through the query cache. */
export async function cveReleases(
  faultlineId: string,
  readPosture: (releaseId: string) => Promise<PostureEntry[]>,
): Promise<CveRelease[]> {
  const ids = asArray<string>(await apiGet("knowledge", `/faultlines/${enc(faultlineId)}/releases`));
  return Promise.all(
    ids.map(async (releaseId) => {
      const rel = await apiGet<Release>("registry", `/releases/${enc(releaseId)}`).catch(() => null);
      const proj = rel?.project_id ? await apiGet<Project>("registry", `/projects/${enc(rel.project_id)}`).catch(() => null) : null;
      const posture = await readPosture(releaseId).catch(() => []);
      return {
        releaseId,
        version: rel?.version ?? "",
        project: proj?.name ?? "",
        entry: posture.find((p) => p.faultline_id === faultlineId) ?? null,
      };
    }),
  );
}

/** Loaded only when a row's dropdown is opened. */
export function useCveReleases(faultlineId: string | undefined, open: boolean) {
  const qc = useQueryClient();
  return useQuery({
    queryKey: ["cve-releases", faultlineId],
    enabled: open && !!faultlineId,
    queryFn: () => cveReleases(faultlineId ?? "", (id) => qc.fetchQuery(postureQuery(id))),
  });
}
