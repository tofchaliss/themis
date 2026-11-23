// shadcn/ui Badge, with the Themis status tones. Colour never carries alone: every badge
// has a text label (EDR-GUI-02 D7).
import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-px text-[11.5px] font-medium",
  {
    variants: {
      tone: {
        neutral: "border-line text-ink-2",
        accent: "border-transparent bg-accent-soft text-accent",
        crit: "border-transparent bg-crit/15 text-crit",
        serious: "border-transparent bg-serious/15 text-serious",
        warn: "border-transparent bg-warn/20 text-ink",
        good: "border-transparent bg-good/15 text-good",
        elevated: "border-transparent bg-elevated/15 text-elevated",
        info: "border-transparent bg-info/15 text-ink-2",
        ai: "border-transparent bg-ai-bg text-ai-ink",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export type BadgeProps = React.ComponentProps<"span"> & VariantProps<typeof badgeVariants>;

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
