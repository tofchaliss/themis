import { useState, type FormEvent } from "react";
import { Network, Rss, Search, Upload } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Donut } from "@/components/donut";
import { bandSlices } from "@/components/bands";
import { Empty, ErrorPanel } from "@/components/states";
import { PSIRTCard } from "@/components/psirt-card";
import { useEstateSweep, useFeeds, useProducts } from "@/lib/queries";
import { asArray } from "@/lib/utils";

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

// One small figure of the status card: a label, the value, and a short note.
function Stat({ value, label, note, loading }: { value: string; label: string; note: string; loading: boolean }) {
  return (
    <div className="min-w-0">
      <div className="truncate text-xs text-ink-2">{label}</div>
      {loading ? <Skeleton className="mt-1 h-5 w-10" /> : <div className="text-lg leading-tight font-semibold tabular-nums">{value}</div>}
      <div className="truncate text-[11px] text-muted" title={note}>
        {note}
      </div>
    </div>
  );
}

function CveSearch() {
  const [cve, setCve] = useState("");
  const [bad, setBad] = useState(false);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const id = cve.trim().toUpperCase();
    if (!CVE_RE.test(id)) {
      setBad(true);
      return;
    }
    window.location.hash = `#/cve/${encodeURIComponent(id)}`;
  };
  return (
    <form onSubmit={submit} className="flex flex-col gap-1.5" autoComplete="off">
      <div className="flex items-center gap-1.5">
        <label htmlFor="cve-search" className="sr-only">
          Find a CVE
        </label>
        <Input
          id="cve-search"
          value={cve}
          onChange={(e) => {
            setCve(e.target.value);
            setBad(false);
          }}
          placeholder="CVE-2026-21441"
          className="min-w-0 flex-1 font-mono"
          aria-invalid={bad}
        />
        <Button type="submit" variant="outline" size="sm" aria-label="Find">
          <Search />
        </Button>
      </div>
      {bad && <span className="text-xs text-crit">That is not a CVE id.</span>}
    </form>
  );
}

function QuickLink({ href, icon: Icon, label }: { href: string; icon: typeof Network; label: string }) {
  return (
    <a href={href} className="flex items-center gap-2 rounded-md px-1.5 py-1 hover:bg-hover">
      <Icon className="size-4 shrink-0 text-accent" aria-hidden />
      <span>{label}</span>
    </a>
  );
}

// EDR-PSIRT-01 P4 layout (owner, 2026-11-24): one compact row on top (find a CVE, the status
// figures in one card, the estate risk, quick links) and the rest of the page is the PSIRT list.
export function Overview() {
  const products = useProducts();
  const feeds = useFeeds();
  const sweep = useEstateSweep(products.data);
  const entries = asArray<{ status?: string }>(feeds.data?.feeds);
  const healthy = entries.filter((f) => f.status === "healthy").length;

  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <Card>
          <CardHeader className="px-3 pt-3">
            <CardTitle>Find a CVE</CardTitle>
          </CardHeader>
          <CardContent className="px-3 pt-2 pb-3">
            <CveSearch />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="px-3 pt-3">
            <CardTitle>Status</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-x-3 gap-y-2 px-3 pt-2 pb-3">
            <Stat loading={products.isPending} value={products.data ? String(products.data.length) : "—"} label="Products" note="registered" />
            <Stat loading={feeds.isPending} value={feeds.data ? `${healthy}/${entries.length}` : "—"} label="Feeds healthy" note="sources reporting" />
            <Stat
              loading={feeds.isPending}
              value={feeds.data ? (feeds.data.signals_stale ? "STALE" : "OK") : "—"}
              label="Exploit signals"
              note={feeds.data?.signals_stale ? "a critical feed has gone quiet" : "tier-1 feeds current"}
            />
            <Stat
              loading={feeds.isPending}
              value={feeds.data ? String(asArray(feeds.data.degraded_feeds).length) : "—"}
              label="Degraded feeds"
              note="failing, non-blocking"
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="px-3 pt-3">
            <CardTitle>Estate risk</CardTitle>
          </CardHeader>
          <CardContent className="px-3 pt-2 pb-3">
            {products.isError ? (
              <ErrorPanel error={products.error} />
            ) : sweep.isError ? (
              <ErrorPanel error={sweep.error} />
            ) : !sweep.data ? (
              <Skeleton className="h-20 w-full" />
            ) : sweep.data.findings.length === 0 ? (
              <Empty title="No findings anywhere yet">Upload an SBOM to fill this in.</Empty>
            ) : (
              <Donut compact slices={bandSlices(sweep.data.findings.map((f) => f.band))} total={sweep.data.findings.length} />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="px-3 pt-3">
            <CardTitle>Quick links</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col px-1.5 pt-1 pb-2">
            <QuickLink href="#/estate" icon={Network} label="Releases" />
            <QuickLink href="#/sbom" icon={Upload} label="Upload an SBOM" />
            <QuickLink href="#/feeds" icon={Rss} label="Feed health" />
          </CardContent>
        </Card>
      </div>

      <PSIRTCard feeds={feeds.data} feedsError={feeds.isError} />
    </div>
  );
}
