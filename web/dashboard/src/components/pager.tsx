// Ten rows a page, with ← → on the focused table (the classic GUI's pager, kept for long lists).
import { useState, type KeyboardEvent, type ReactNode } from "react";
import { Button } from "@/components/ui/button";

export const PAGE_SIZE = 10;

export function Paged<T>({ rows, children, size = PAGE_SIZE }: { rows: T[]; size?: number; children: (page: T[]) => ReactNode }) {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(rows.length / size));
  const p = Math.min(page, pages - 1);
  const from = p * size;
  const to = Math.min(from + size, rows.length);
  const onKey = (e: KeyboardEvent) => {
    if (e.key === "ArrowRight" && p < pages - 1) setPage(p + 1);
    if (e.key === "ArrowLeft" && p > 0) setPage(p - 1);
  };
  return (
    <div>
      <div className="overflow-x-auto" tabIndex={0} onKeyDown={onKey} title="← → move between pages">
        {children(rows.slice(from, to))}
      </div>
      {rows.length > size && (
        <div className="flex items-center justify-between px-4 pt-2 text-xs text-ink-2">
          <span>
            {from + 1}–{to} of {rows.length}
          </span>
          <span className="flex items-center gap-2">
            <Button size="sm" variant="outline" aria-label="Previous page" disabled={p === 0} onClick={() => setPage(p - 1)}>
              ‹
            </Button>
            page {p + 1} / {pages}
            <Button size="sm" variant="outline" aria-label="Next page" disabled={p >= pages - 1} onClick={() => setPage(p + 1)}>
              ›
            </Button>
          </span>
        </div>
      )}
    </div>
  );
}
