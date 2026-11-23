// EDR-GUI-02 D5: one place for the read queries, so two parts of a screen that need the
// same answer share one request and back-navigation is instant.
import { useQuery } from "@tanstack/react-query";
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
