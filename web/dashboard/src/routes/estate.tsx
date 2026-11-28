// The estate cascade: products → projects → releases, with the tag filter and the tag editor
// (EDR-REMEDIATION-01 D7: tags are filters only) and, for a project or a release, the build
// profile editor (EDR-REBUILD-01 D10). A release opens its posture. An admin can correct a
// project's name (EDR-KERNEL-01 D5): only the name changes, everything keyed to it stays.
import { useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { BuildProfileEditor } from "@/components/build-profile";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Empty, ErrorPanel, Loading } from "@/components/states";
import { apiPatch, apiPut, ApiError } from "@/lib/api";
import { useProducts, useProjects, useReleases, useTags, useWhoAmI, type Project, type TagKind, type TagSet } from "@/lib/queries";
import { releaseHash } from "@/lib/router";
import { cn } from "@/lib/utils";

type Target = { kind: TagKind; id: string; name: string };

function Tags({ tags }: { tags?: string[] }) {
  return (
    <>
      {(tags ?? []).map((t) => (
        <Badge key={t} tone="info" className="font-mono">
          {t}
        </Badge>
      ))}
    </>
  );
}

function Row({ active, onClick, children, id }: { active: boolean; onClick: () => void; children: ReactNode; id?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        "flex w-full flex-wrap items-center gap-1.5 rounded-lg px-2.5 py-2 text-left hover:bg-hover",
        active && "bg-accent-soft text-accent hover:bg-accent-soft",
      )}
    >
      {children}
      {id && <span className="ml-auto font-mono text-[11px] text-muted">{id.slice(0, 8)}</span>}
    </button>
  );
}

function Column({ title, children }: { title: string; children: ReactNode }) {
  return (
    <Card className="min-w-0">
      <CardHeader className="pb-1">
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-0.5 pt-2">{children}</CardContent>
    </Card>
  );
}

function TagEditor({ target, canWrite }: { target: Target; canWrite: boolean }) {
  const qc = useQueryClient();
  const tags = useTags(target.kind, target.id);
  const own = tags.data?.tags ?? [];
  const inherited = (tags.data?.effective ?? []).filter((t) => !own.includes(t));
  const [draft, setDraft] = useState<string | null>(null);
  const value = draft ?? own.join(", ");
  const save = useMutation({
    mutationFn: (list: string[]) => apiPut<TagSet>("registry", `/${target.kind}s/${encodeURIComponent(target.id)}/tags`, { tags: list }),
    onSuccess: (ts) => {
      qc.setQueryData(["tags", target.kind, target.id], ts);
      void qc.invalidateQueries({ queryKey: ["products"] });
      void qc.invalidateQueries({ queryKey: ["projects"] });
      void qc.invalidateQueries({ queryKey: ["releases"] });
      setDraft(null);
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate(
      value
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    );
  };
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          Tags — {target.kind} {target.name}
        </CardTitle>
        <CardDescription>
          Filters only: tags never change a priority. A release also carries its project's and product's tags (
          {inherited.length ? inherited.join(", ") : "none"}). Lower-case letters, digits and <span className="font-mono">: . _ / -</span>; up to
          20. Needs a write-capable key.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {tags.isError ? (
          <ErrorPanel error={tags.error} />
        ) : (
          <form onSubmit={submit} className="flex flex-wrap items-center gap-2">
            <label htmlFor="tag-editor-input" className="sr-only">
              Tags
            </label>
            <Input
              id="tag-editor-input"
              className="w-80 font-mono"
              placeholder="team:payments, env:prod"
              value={value}
              onChange={(e) => setDraft(e.target.value)}
              disabled={tags.isPending}
              autoComplete="off"
            />
            <Button type="submit" disabled={!canWrite || save.isPending} title={canWrite ? undefined : "Your key is read-only"}>
              Save tags
            </Button>
            <span className="text-ink-2" role="status">
              {save.isPending
                ? "saving…"
                : save.isError
                  ? `not saved: ${save.error instanceof ApiError ? save.error.message : "request failed"}`
                  : save.isSuccess
                    ? "saved"
                    : ""}
            </span>
          </form>
        )}
      </CardContent>
    </Card>
  );
}

function RenameProject({ project, canRename, onRenamed }: { project: { id: string; name: string }; canRename: boolean; onRenamed: (name: string) => void }) {
  const qc = useQueryClient();
  const [draft, setDraft] = useState(project.name);
  const save = useMutation({
    mutationFn: (name: string) => apiPatch<Project>("registry", `/projects/${encodeURIComponent(project.id)}`, { name }),
    onSuccess: (p) => {
      void qc.invalidateQueries({ queryKey: ["projects"] });
      onRenamed(p.name ?? draft.trim());
    },
  });
  const name = draft.trim();
  const submit = (e: FormEvent) => {
    e.preventDefault();
    save.mutate(name);
  };
  return (
    <Card>
      <CardHeader>
        <CardTitle>Rename project {project.name}</CardTitle>
        <CardDescription>
          Only the name changes. Findings, decisions, watches and tickets stay with this project. Change the name in every CI job that uploads
          to it too, or its next upload creates a new project with the old name. Needs an admin key.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={submit} className="flex flex-wrap items-center gap-2">
          <label htmlFor="rename-project-input" className="sr-only">
            New project name
          </label>
          <Input id="rename-project-input" className="w-80" value={draft} onChange={(e) => setDraft(e.target.value)} autoComplete="off" />
          <Button
            type="submit"
            disabled={!canRename || save.isPending || name === "" || name === project.name}
            title={canRename ? undefined : "Renaming needs an admin key"}
          >
            Rename
          </Button>
          <span className="text-ink-2" role="status">
            {save.isPending
              ? "renaming…"
              : save.isError
                ? `not renamed: ${save.error instanceof ApiError ? save.error.message : "request failed"}`
                : save.isSuccess
                  ? "renamed"
                  : ""}
          </span>
        </form>
      </CardContent>
    </Card>
  );
}

export function Estate() {
  const who = useWhoAmI();
  const [tag, setTag] = useState("");
  const [tagDraft, setTagDraft] = useState("");
  const [product, setProduct] = useState<{ id: string; name: string } | null>(null);
  const [project, setProject] = useState<{ id: string; name: string } | null>(null);
  const [target, setTarget] = useState<Target | null>(null);

  const products = useProducts(tag);
  const projects = useProjects(product?.id ?? null, tag);
  const releases = useReleases(project?.id ?? null, tag);

  const applyTag = (e: FormEvent) => {
    e.preventDefault();
    setTag(tagDraft.trim().toLowerCase());
    setProduct(null);
    setProject(null);
    setTarget(null);
  };

  return (
    <div className="flex flex-col gap-4">
      <Card>
        <CardContent>
          <form onSubmit={applyTag} className="flex flex-wrap items-center gap-2">
            <label htmlFor="estate-tag" className="text-ink-2">
              Filter by tag
            </label>
            <Input id="estate-tag" className="w-64 font-mono" placeholder="e.g. team:payments" value={tagDraft} onChange={(e) => setTagDraft(e.target.value)} autoComplete="off" />
            <Button type="submit" variant="outline">
              Apply
            </Button>
            {tag && (
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  setTag("");
                  setTagDraft("");
                }}
              >
                Clear
              </Button>
            )}
            <span className="text-muted">A release carries its project's and product's tags too.</span>
          </form>
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-3">
        <Column title="Products">
          {products.isPending ? (
            <Loading what="products" />
          ) : products.isError ? (
            <ErrorPanel error={products.error} />
          ) : products.data.length === 0 ? (
            tag ? (
              <Empty title={`No product carries ${tag}`} />
            ) : (
              <Empty title="No products yet">
                <span>
                  Upload the first SBOM in the{" "}
                  <a className="text-accent" href="#/sbom">
                    SBOM manager
                  </a>
                  , or run scripts/gf-upload-sbom.sh.
                </span>
              </Empty>
            )
          ) : (
            products.data.map((p) => (
              <Row
                key={p.id}
                id={p.id}
                active={product?.id === p.id}
                onClick={() => {
                  setProduct({ id: p.id ?? "", name: p.name ?? "" });
                  setProject(null);
                  setTarget({ kind: "product", id: p.id ?? "", name: p.name ?? "" });
                }}
              >
                <span className="font-medium">{p.name}</span>
                <Tags tags={p.tags} />
              </Row>
            ))
          )}
        </Column>

        <Column title="Projects">
          {!product ? (
            <Empty title="Pick a product" />
          ) : projects.isPending ? (
            <Loading what="projects" />
          ) : projects.isError ? (
            <ErrorPanel error={projects.error} />
          ) : projects.data.length === 0 ? (
            <Empty title="No projects">under {product.name}</Empty>
          ) : (
            projects.data.map((p) => (
              <Row
                key={p.id}
                id={p.id}
                active={project?.id === p.id}
                onClick={() => {
                  setProject({ id: p.id ?? "", name: p.name ?? "" });
                  setTarget({ kind: "project", id: p.id ?? "", name: p.name ?? "" });
                }}
              >
                <span className="font-medium">{p.name}</span>
                <Tags tags={p.tags} />
              </Row>
            ))
          )}
        </Column>

        <Column title="Releases">
          {!project ? (
            <Empty title="Pick a project" />
          ) : releases.isPending ? (
            <Loading what="releases" />
          ) : releases.isError ? (
            <ErrorPanel error={releases.error} />
          ) : releases.data.length === 0 ? (
            <Empty title="No releases">under {project.name}: register one, then upload its SBOM.</Empty>
          ) : (
            releases.data.map((r) => (
              <div key={r.id} className="flex flex-wrap items-center gap-1.5 rounded-lg px-2.5 py-2 hover:bg-hover">
                <a
                  className="flex items-center gap-1 font-medium text-ink hover:text-accent"
                  href={releaseHash(r.id ?? "", r.version)}
                  title="Open this release's posture"
                >
                  v{r.version}
                </a>
                <Tags tags={r.tags} />
                <button
                  type="button"
                  className="text-xs text-ink-2 hover:text-accent"
                  onClick={() => setTarget({ kind: "release", id: r.id ?? "", name: `v${r.version}` })}
                >
                  tags, build profile…
                </button>
                <span className="ml-auto font-mono text-[11px] text-muted">{(r.id ?? "").slice(0, 8)}</span>
              </div>
            ))
          )}
        </Column>
      </div>

      {target && <TagEditor key={`${target.kind}:${target.id}`} target={target} canWrite={who.data?.can_write !== false} />}
      {target && target.kind !== "product" && (
        <BuildProfileEditor
          key={`bp:${target.kind}:${target.id}`}
          kind={target.kind}
          id={target.id}
          name={target.name}
          actor={who.data?.user ?? "operator"}
          canWrite={who.data?.can_write !== false}
        />
      )}
      {target?.kind === "project" && project && (
        <RenameProject
          key={project.id}
          project={project}
          canRename={who.data?.scopes ? who.data.scopes.includes("admin") : who.data?.can_write !== false}
          onRenamed={(name) => {
            setProject({ id: project.id, name });
            setTarget({ kind: "project", id: project.id, name });
          }}
        />
      )}
    </div>
  );
}
