import { LogOut } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { WhoAmI } from "@/lib/api";
import type { ThemeId } from "@/lib/theme";
import { initials } from "@/lib/utils";
import { ThemePicker } from "./theme-picker";

export type Crumb = { label: string; href?: string };

export function TopBar({
  crumbs,
  who,
  theme,
  onTheme,
  defaultPassword,
}: {
  crumbs: Crumb[];
  who: WhoAmI | undefined;
  theme: ThemeId;
  onTheme: (t: ThemeId) => void;
  defaultPassword: boolean;
}) {
  const user = who?.user ?? "operator";
  // Scopes exist only on an authenticated session; that is when sign-out means something.
  const signedIn = Array.isArray(who?.scopes);
  return (
    <header className="flex h-[52px] shrink-0 items-center justify-between gap-4 border-b border-line bg-card px-[22px]">
      <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-2 text-ink-2">
        {crumbs.map((c, i) => (
          <span key={`${c.label}-${i}`} className="flex items-center gap-2">
            {i > 0 && <span className="text-muted">/</span>}
            {c.href && i < crumbs.length - 1 ? (
              <a href={c.href} className="hover:text-ink">
                {c.label}
              </a>
            ) : (
              <span aria-current={i === crumbs.length - 1 ? "page" : undefined} className={i === crumbs.length - 1 ? "font-semibold text-ink" : ""}>
                {c.label}
              </span>
            )}
          </span>
        ))}
      </nav>
      <div className="flex items-center gap-2.5">
        {defaultPassword && (
          // Plain and persistent, not a toast: it has to still be there next time somebody looks.
          <a
            href="/#/admin"
            className="rounded-lg border border-warn/60 bg-warn/15 px-2.5 py-1 text-xs font-medium text-ink"
            title="The dashboard's admin account still uses the password it shipped with"
          >
            Default password in use — change it
          </a>
        )}
        <ThemePicker value={theme} onChange={onTheme} />
        <span
          className="flex items-center gap-2 text-ink-2"
          title={signedIn ? `Signed in as ${user} (${who?.scopes?.join(", ") || "no scopes"})` : "Auth is off: the name comes from THEMIS_DASHBOARD_USER"}
        >
          <i className="grid size-7 place-items-center rounded-full bg-accent-soft text-[11px] font-semibold text-accent not-italic">
            {initials(user)}
          </i>
          <span>{user}</span>
          {who && !who.can_write && <span className="text-xs text-muted">(read only)</span>}
        </span>
        {signedIn && (
          <form method="post" action="/logout">
            <Button type="submit" variant="ghost" size="sm" title="End this session">
              <LogOut />
              Sign out
            </Button>
          </form>
        )}
      </div>
    </header>
  );
}
