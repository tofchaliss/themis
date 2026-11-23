// EDR-GUI-02 D4: hash routes with today's shapes, so links already sent by the webhook,
// Teams and mail routes keep working once this GUI becomes the default.
import { useSyncExternalStore } from "react";

export type Route =
  | { view: "overview" }
  | { view: "estate" }
  | { view: "release"; id: string; version: string }
  | { view: "classic"; hash: string };

/** Screens built in this GUI so far. Everything else opens in the classic GUI (D11). */
export function parseHash(hash: string): Route {
  const h = hash.replace(/^#/, "") || "/";
  const path = h.split("?")[0] ?? "/";
  if (path === "/" || path === "") return { view: "overview" };
  if (path === "/estate") return { view: "estate" };
  const rel = /^\/release\/([^/]+)$/.exec(path);
  if (rel?.[1]) {
    const q = new URLSearchParams(h.split("?")[1] ?? "");
    return { view: "release", id: decodeURIComponent(rel[1]), version: q.get("v") ?? "" };
  }
  return { view: "classic", hash: `#${h}` };
}

/** The classic GUI's URL for a hash route that is not built here yet. */
export function classicHref(hash: string): string {
  return `/old/${hash.startsWith("#") ? hash : `#${hash}`}`;
}

function subscribe(cb: () => void) {
  window.addEventListener("hashchange", cb);
  return () => window.removeEventListener("hashchange", cb);
}

export function useHash(): string {
  return useSyncExternalStore(subscribe, () => window.location.hash);
}

export function useRoute(): Route {
  return parseHash(useHash());
}

/** The hash of a release's posture (today's shape, so sent links keep working). */
export function releaseHash(id: string, version?: string): string {
  return `#/release/${encodeURIComponent(id)}${version ? `?v=${encodeURIComponent(version)}` : ""}`;
}
