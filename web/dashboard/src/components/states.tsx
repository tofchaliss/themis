// Shared loading / error / empty panels. A node that does not answer is named, never
// blurred into "something went wrong" (the same honesty as the classic GUI).
import { AlertTriangle, Loader2 } from "lucide-react";
import type { ReactNode } from "react";
import { NodeDownError } from "@/lib/api";

export function Loading({ what }: { what: string }) {
  return (
    <div role="status" className="flex items-center gap-2 p-4 text-ink-2">
      <Loader2 className="size-4 animate-spin" aria-hidden />
      Loading {what}…
    </div>
  );
}

export function ErrorPanel({ error }: { error: unknown }) {
  const text =
    error instanceof NodeDownError
      ? `The ${error.node} node did not answer. Check its service and the dashboard's proxy target for it, then reload.`
      : error instanceof Error
        ? error.message
        : "The request failed.";
  return (
    <div role="alert" className="flex items-start gap-2 rounded-lg border border-crit/40 bg-crit/10 p-3 text-ink">
      <AlertTriangle className="mt-0.5 size-4 shrink-0 text-crit" aria-hidden />
      <span>{text}</span>
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col gap-1 p-4 text-center text-ink-2">
      <b className="text-ink">{title}</b>
      {children}
    </div>
  );
}
