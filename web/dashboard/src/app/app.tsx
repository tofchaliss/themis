import { lazy, Suspense, useEffect, useState } from "react";
import { Rail } from "./rail";
import { TopBar, type Crumb } from "./topbar";
import { applyTheme, loadTheme, type ThemeId } from "@/lib/theme";
import { classicHref, releaseHash, useRoute, type Route } from "@/lib/router";
import { useAdminStatus, useWhoAmI } from "@/lib/queries";
import { Loading } from "@/components/states";

// EDR-GUI-02 D8: one lazy chunk per screen; the first load carries the shell and the screen opened.
const Overview = lazy(() => import("@/routes/overview").then((m) => ({ default: m.Overview })));
const Estate = lazy(() => import("@/routes/estate").then((m) => ({ default: m.Estate })));
const Decide = lazy(() => import("@/routes/decide").then((m) => ({ default: m.Decide })));
const Sbom = lazy(() => import("@/routes/sbom").then((m) => ({ default: m.Sbom })));
const Compare = lazy(() => import("@/routes/compare").then((m) => ({ default: m.Compare })));
const WhatsNew = lazy(() => import("@/routes/whats-new").then((m) => ({ default: m.WhatsNew })));
const Cve = lazy(() => import("@/routes/cve").then((m) => ({ default: m.Cve })));
const Reports = lazy(() => import("@/routes/reports").then((m) => ({ default: m.Reports })));
const Feeds = lazy(() => import("@/routes/feeds").then((m) => ({ default: m.Feeds })));
const Admin = lazy(() => import("@/routes/admin").then((m) => ({ default: m.Admin })));
const Watches = lazy(() => import("@/routes/watches").then((m) => ({ default: m.Watches })));
const WatchView = lazy(() => import("@/routes/watches").then((m) => ({ default: m.WatchView })));
const Scan = lazy(() => import("@/routes/scan").then((m) => ({ default: m.Scan })));
const Release = lazy(() => import("@/routes/release").then((m) => ({ default: m.Release })));

const CRUMBS: Record<string, Crumb[]> = {
  overview: [{ label: "Overview" }],
  estate: [{ label: "Overview", href: "#/" }, { label: "Estate" }],
  sbom: [{ label: "Overview", href: "#/" }, { label: "SBOM manager" }],
  compare: [{ label: "Overview", href: "#/" }, { label: "Compare releases" }],
  new: [{ label: "Overview", href: "#/" }, { label: "What's new" }],
  reports: [{ label: "Overview", href: "#/" }, { label: "Reports" }],
  feeds: [{ label: "Overview", href: "#/" }, { label: "Feed health" }],
  admin: [{ label: "Overview", href: "#/" }, { label: "Admin" }],
  watches: [{ label: "Overview", href: "#/" }, { label: "Watches" }],
  watch: [{ label: "Overview", href: "#/" }, { label: "Watches", href: "#/watches" }, { label: "Watch" }],
};

function crumbsFor(route: Route): Crumb[] {
  if (route.view === "release")
    return [{ label: "Overview", href: "#/" }, { label: "Estate", href: "#/estate" }, { label: route.version ? `Release v${route.version}` : "Release" }];
  if (route.view === "decide")
    return [
      { label: "Overview", href: "#/" },
      { label: "Estate", href: "#/estate" },
      ...(route.releaseId ? [{ label: route.version ? `Release v${route.version}` : "Release", href: releaseHash(route.releaseId, route.version) }] : []),
      { label: "Decide" },
    ];
  if (route.view === "cve") return [{ label: "Overview", href: "#/" }, { label: "What's new", href: "#/new" }, { label: route.cve }];
  if (route.view === "scan")
    return [
      { label: "Overview", href: "#/" },
      { label: "Estate", href: "#/estate" },
      { label: route.version ? `Release v${route.version}` : "Release", href: releaseHash(route.releaseId, route.version) },
      { label: "Scan report" },
    ];
  return CRUMBS[route.view] ?? [];
}

function railFor(route: Route): string {
  if (route.view === "release" || route.view === "decide" || route.view === "scan") return "estate";
  if (route.view === "cve") return "new";
  if (route.view === "watch") return "watches";
  return route.view;
}

/** A screen not built here yet: hand the route to the classic GUI (EDR-GUI-02 D11). */
function Classic({ hash }: { hash: string }) {
  useEffect(() => {
    window.location.replace(classicHref(hash));
  }, [hash]);
  return <p className="p-4 text-ink-2">Opening this screen in the old GUI…</p>;
}

export function App() {
  const route = useRoute();
  const [theme, setTheme] = useState<ThemeId>(loadTheme);
  const who = useWhoAmI();
  const admin = useAdminStatus();

  useEffect(() => applyTheme(theme), [theme]);

  const isAdmin = !!who.data?.scopes?.includes("admin");
  const status = admin.data && !("forbidden" in admin.data) ? admin.data : null;
  const authOff = status?.auth_enabled === false;

  return (
    <div className="grid h-full grid-cols-[60px_1fr]">
      <Rail active={railFor(route)} showAdmin={isAdmin || authOff} />
      <div className="flex min-w-0 flex-col">
        <TopBar
          crumbs={crumbsFor(route)}
          who={who.data}
          theme={theme}
          onTheme={setTheme}
          defaultPassword={isAdmin && !!status?.auth_enabled && !!status?.is_default_password}
        />
        <main className="min-h-0 flex-1 overflow-auto px-[22px] py-5" tabIndex={-1}>
          <Suspense fallback={<Loading what="screen" />}>
            {route.view === "overview" && <Overview />}
            {route.view === "estate" && <Estate />}
            {route.view === "decide" && <Decide key={route.findingId} findingId={route.findingId} releaseId={route.releaseId} version={route.version} />}
            {route.view === "release" && <Release key={route.id} id={route.id} version={route.version} />}
            {route.view === "sbom" && <Sbom />}
            {route.view === "compare" && <Compare />}
            {route.view === "new" && <WhatsNew />}
            {route.view === "reports" && <Reports />}
            {route.view === "feeds" && <Feeds />}
            {route.view === "admin" && <Admin />}
            {route.view === "watches" && <Watches />}
            {route.view === "watch" && <WatchView key={route.id} id={route.id} />}
            {route.view === "cve" && <Cve key={route.cve} cve={route.cve} />}
            {route.view === "scan" && <Scan key={route.evidenceId} evidenceId={route.evidenceId} releaseId={route.releaseId} version={route.version} />}
            {route.view === "classic" && <Classic hash={route.hash} />}
          </Suspense>
        </main>
      </div>
    </div>
  );
}
