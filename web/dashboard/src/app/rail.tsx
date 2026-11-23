// The left rail. Screens built in this GUI route here; the rest open in the classic GUI
// until their step lands (EDR-GUI-02 D11), marked with a small arrow.
import { Boxes, Eye, GitCompareArrows, LayoutGrid, Network, Rss, ShieldCheck, Sparkles, ChartColumn, ArrowUpRight } from "lucide-react";
import type { ComponentType } from "react";
import { cn } from "@/lib/utils";
import { classicHref } from "@/lib/router";

type Item = { id: string; label: string; hash: string; icon: ComponentType<{ className?: string }>; here: boolean; adminOnly?: boolean };

export const RAIL: Item[] = [
  { id: "overview", label: "Overview", hash: "#/", icon: LayoutGrid, here: true },
  { id: "estate", label: "Estate", hash: "#/estate", icon: Network, here: true },
  { id: "sbom", label: "SBOM manager", hash: "#/sbom", icon: Boxes, here: false },
  { id: "compare", label: "Compare", hash: "#/compare", icon: GitCompareArrows, here: false },
  { id: "new", label: "What's new", hash: "#/new", icon: Sparkles, here: false },
  { id: "reports", label: "Reports", hash: "#/reports", icon: ChartColumn, here: false },
  { id: "watches", label: "Watches", hash: "#/watches", icon: Eye, here: false },
  { id: "feeds", label: "Feeds", hash: "#/feeds", icon: Rss, here: false },
  { id: "admin", label: "Admin", hash: "#/admin", icon: ShieldCheck, here: false, adminOnly: true },
];

export function Rail({ active, showAdmin }: { active: string; showAdmin: boolean }) {
  return (
    <nav aria-label="Primary" className="flex w-[60px] flex-col items-center gap-1 border-r border-line bg-rail pt-3">
      <span className="mb-3.5 text-xl font-bold text-accent" title="Themis">
        Θ
      </span>
      {RAIL.filter((i) => !i.adminOnly || showAdmin).map((i) => {
        const Icon = i.icon;
        const href = i.here ? i.hash : classicHref(i.hash);
        const title = i.here ? i.label : `${i.label} (opens the old GUI)`;
        return (
          <a
            key={i.id}
            href={href}
            title={title}
            aria-label={title}
            aria-current={active === i.id ? "page" : undefined}
            className={cn(
              "relative grid size-10 place-items-center rounded-[9px] text-ink-2 hover:bg-hover hover:text-ink",
              active === i.id && "bg-accent-soft text-accent hover:bg-accent-soft hover:text-accent",
            )}
          >
            <Icon className="size-[18px]" />
            {!i.here && <ArrowUpRight aria-hidden className="absolute right-1 bottom-1 size-2.5 text-muted" />}
          </a>
        );
      })}
    </nav>
  );
}
