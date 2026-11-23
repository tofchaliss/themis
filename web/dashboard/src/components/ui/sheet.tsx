// A side drawer on the native <dialog> element (shadcn/ui's Sheet look, without Radix Dialog).
// showModal() puts it in the top layer and makes the page behind it inert, Escape and the
// backdrop close it, and the browser returns focus to the row that opened it. Radix Dialog was
// not used because its scroll lock injects a <style> element, which the D9 CSP
// (style-src 'self') rightly refuses.
import { useEffect, useRef, type ReactNode } from "react";
import { X } from "lucide-react";
import { cn } from "@/lib/utils";

export function Sheet({
  open,
  onClose,
  labelledBy,
  className,
  children,
}: {
  open: boolean;
  onClose: () => void;
  labelledBy: string;
  className?: string;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      aria-labelledby={labelledBy}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onKeyDown={(e) => {
        if (e.key === "Escape") onClose();
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      className={cn(
        "fixed inset-y-0 right-0 left-auto m-0 h-full max-h-none w-full max-w-[640px] border-0 border-l border-line bg-card p-0 text-ink shadow-card backdrop:bg-black/30",
        className,
      )}
    >
      {open && (
        <div className="relative flex h-full flex-col">
          {children}
          <button
            type="button"
            onClick={onClose}
            className="absolute top-3.5 right-3.5 rounded-md p-1 text-ink-2 hover:bg-hover hover:text-ink"
            aria-label="Close"
          >
            <X className="size-4" />
          </button>
        </div>
      )}
    </dialog>
  );
}
