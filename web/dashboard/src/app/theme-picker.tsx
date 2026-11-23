import { Moon, MonitorDot, Sun } from "lucide-react";
import { THEMES, type ThemeId } from "@/lib/theme";
import { cn } from "@/lib/utils";

const ICON = { enterprise: Sun, midnight: Moon, "ops-night": MonitorDot } as const;

/** EDR-GUI-02 D7: the three shades as one segmented control in the top bar. */
export function ThemePicker({ value, onChange }: { value: ThemeId; onChange: (t: ThemeId) => void }) {
  return (
    <div role="radiogroup" aria-label="Shade" className="flex gap-0.5 rounded-lg border border-line p-0.5">
      {THEMES.map((t) => {
        const Icon = ICON[t.id];
        const on = t.id === value;
        return (
          <button
            key={t.id}
            type="button"
            role="radio"
            aria-checked={on}
            onClick={() => onChange(t.id)}
            className={cn(
              "flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium text-ink-2 hover:text-ink",
              on && "bg-accent text-on-accent hover:text-on-accent",
            )}
          >
            <Icon className="size-3.5" aria-hidden />
            {t.label}
          </button>
        );
      })}
    </div>
  );
}
