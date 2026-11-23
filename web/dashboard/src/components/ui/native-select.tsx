// A native <select> in the Themis tokens. Native on purpose: it is keyboard- and screen-reader
// correct for free, and it injects no style element (the new GUI's CSP is style-src 'self').
import * as React from "react";
import { cn } from "@/lib/utils";

export function Select({ className, ...props }: React.ComponentProps<"select">) {
  return (
    <select
      className={cn(
        "h-8 w-full rounded-lg border border-line bg-card px-2 text-[13px] text-ink focus-visible:outline-2 focus-visible:outline-accent disabled:opacity-50",
        className,
      )}
      {...props}
    />
  );
}
