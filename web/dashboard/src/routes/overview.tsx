import { useState, type FormEvent } from "react";
import { ArrowUpRight, Network, Rss, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Donut } from "@/components/donut";
import { bandSlices } from "@/components/bands";
import { Empty, ErrorPanel } from "@/components/states";
import { useEstateSweep, useFeeds, useProducts } from "@/lib/queries";
import { classicHref } from "@/lib/router";
import { asArray } from "@/lib/utils";

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;

function Tile({ value, label, note, loading }: { value: string; label: string; note: string; loading: boolean }) {
  return (
    <Card className="px-3.5 py-3">
      <div className="font-medium text-ink-2">{label}</div>
      {loading ? <Skeleton className="mt-1.5 h-7 w-16" /> : <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>}
      <div className="text-xs text-muted">{note}</div>
    </Card>
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
    // The CVE page is not built in this GUI yet (EDR-GUI-02 G4): it opens in the classic one.
    window.location.href = classicHref(`#/cve/${encodeURIComponent(id)}`);
  };
  return (
    <form onSubmit={submit} className="flex flex-wrap items-center gap-2" autoComplete="off">
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
        placeholder="Find a CVE, e.g. CVE-2026-21441"
        className="w-72 font-mono"
        aria-invalid={bad}
      />
      <Button type="submit" variant="outline">
        <Search />
        Find
      </Button>
      <span className={bad ? "text-crit" : "text-muted"}>{bad ? "That is not a CVE id." : "lists the products, projects and releases it is filed under"}</span>
    </form>
  );
}

export function Overview() {
  const products = useProducts();
  const feeds = useFeeds();
  const sweep = useEstateSweep(products.data);
  const entries = asArray<{ status?: string }>(feeds.data?.feeds);
  const healthy = entries.filter((f) => f.status === "healthy").length;

  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <span className="text-xs font-semibold tracking-wider text-accent uppercase">Themis · Enterprise security decisions</span>
            <h1 className="text-xl font-semibold">Evidence in, positions out</h1>
            <CardDescription className="max-w-prose">
              SBOMs become Findings, Findings get governed Positions, Positions publish as VEX. Pick a release to see its posture. Every number
              here is read live from the pipeline, and the AI only ever proposes.
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex flex-wrap gap-2">
              <Button asChild>
                <a href="#/estate">Browse the estate</a>
              </Button>
              <Button asChild variant="outline">
                <a href={classicHref("#/sbom")}>
                  Upload an SBOM
                  <ArrowUpRight />
                </a>
              </Button>
            </div>
            <CveSearch />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Estate risk</CardTitle>
            <CardDescription>Every open Finding across every release, by exploitability band.</CardDescription>
          </CardHeader>
          <CardContent>
            {products.isError ? (
              <ErrorPanel error={products.error} />
            ) : sweep.isError ? (
              <ErrorPanel error={sweep.error} />
            ) : !sweep.data ? (
              <Skeleton className="h-40 w-full" />
            ) : sweep.data.findings.length === 0 ? (
              <Empty title="No findings anywhere yet">Upload an SBOM and correlation fills this in.</Empty>
            ) : (
              <Donut slices={bandSlices(sweep.data.findings.map((f) => f.band))} total={sweep.data.findings.length} />
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Tile loading={products.isPending} value={products.data ? String(products.data.length) : "—"} label="Products" note="registered in the estate" />
        <Tile loading={feeds.isPending} value={feeds.data ? `${healthy}/${entries.length}` : "—"} label="Feeds healthy" note="enrichment sources reporting" />
        <Tile
          loading={feeds.isPending}
          value={feeds.data ? (feeds.data.signals_stale ? "STALE" : "OK") : "—"}
          label="Exploit signals"
          note={feeds.data?.signals_stale ? "a critical feed has gone quiet" : "tier-1 feeds current"}
        />
        <Tile
          loading={feeds.isPending}
          value={feeds.data ? String(asArray(feeds.data.degraded_feeds).length) : "—"}
          label="Degraded feeds"
          note="failing, non-blocking"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Quick links</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          <a href="#/estate" className="flex items-start gap-3 rounded-lg border border-line p-3 hover:bg-hover">
            <Network className="mt-0.5 size-5 text-accent" aria-hidden />
            <span>
              <b className="block">Releases</b>
              <span className="text-ink-2">Products, projects and releases, down to a posture</span>
            </span>
          </a>
          <a href={classicHref("#/feeds")} className="flex items-start gap-3 rounded-lg border border-line p-3 hover:bg-hover">
            <Rss className="mt-0.5 size-5 text-accent" aria-hidden />
            <span>
              <b className="block">Feed health</b>
              <span className="text-ink-2">OSV, NVD, EPSS/KEV, Red Hat, CSAF-VEX: who is delivering</span>
            </span>
          </a>
        </CardContent>
      </Card>
    </div>
  );
}
