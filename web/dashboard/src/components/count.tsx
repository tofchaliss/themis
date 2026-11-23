// One number with its label, for the small summary cards. The note is on hover.
import { cn } from "@/lib/utils";

export function Count({ value, label, note, tone }: { value: number | string; label: string; note?: string; tone?: string }) {
  return (
    <div title={note} className="min-w-[72px]">
      <div className={cn("text-xl leading-tight font-semibold tabular-nums", tone)}>{value}</div>
      <div className="text-xs text-ink-2">{label}</div>
    </div>
  );
}
