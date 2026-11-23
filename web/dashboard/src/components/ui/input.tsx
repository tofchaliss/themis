// shadcn/ui Input, adapted to the Themis tokens.
import * as React from "react";
import { cn } from "@/lib/utils";

export function Input({ className, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      className={cn(
        "h-8 rounded-lg border border-line bg-card px-2.5 text-[13px] text-ink placeholder:text-muted focus-visible:outline-2 focus-visible:outline-accent",
        className,
      )}
      {...props}
    />
  );
}
