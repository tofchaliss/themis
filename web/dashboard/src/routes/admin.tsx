// Admin (EDR-GUI-02 G5): the dashboard's own sign-in. Restricted to admin-scope sessions; the
// routes behind it refuse the request, not only the page.
import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorPanel } from "@/components/states";
import { useAdminStatus, useWhoAmI } from "@/lib/queries";

/** Its own fetch: on this route a 401 means "that is not your current password", and signing a
 * person out over a typo would be absurd. */
async function changePassword(body: { current: string; new: string; confirm: string }): Promise<string | null> {
  const r = await fetch("/api/dashboard/admin/password", {
    method: "POST",
    headers: { Accept: "application/json", "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (r.status === 204) return null;
  const j = (await r.json().catch(() => ({}))) as { detail?: string; title?: string };
  return j.detail || j.title || `status ${r.status}`;
}

export function Admin() {
  const qc = useQueryClient();
  const status = useAdminStatus();
  const who = useWhoAmI();
  const [f, setF] = useState({ current: "", next: "", confirm: "" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  if (status.isPending) return <Skeleton className="h-40" />;
  const s = status.data;
  const user = who.data?.user ?? "operator";
  if (s && "forbidden" in s)
    return (
      <Card>
        <CardHeader>
          <CardTitle>Admin</CardTitle>
          <CardDescription>
            This tab administers the dashboard itself and is for admin-scope operators. You are signed in as <span className="font-mono">{user}</span>{" "}
            without that scope, so there is nothing here for you; the routes behind it refuse the request too.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  if (!s) return <ErrorPanel error={new Error("The dashboard could not read its own admin status. Reload; if it persists, check the dashboard's log.")} />;
  if (!s.auth_enabled)
    return (
      <Card>
        <CardHeader>
          <CardTitle>Sign-in</CardTitle>
          <CardDescription>
            Authentication is off on this dashboard, so there is no login and no password to change. Every visitor reaches the GUI and acts as{" "}
            <span className="font-mono">{user}</span>. To require sign-in, set <span className="font-mono">THEMIS_AUTH_DATABASE_DSN</span> on the
            dashboard and restart it; this tab then gains the change-password form.
          </CardDescription>
        </CardHeader>
      </Card>
    );

  async function submit(e: FormEvent) {
    e.preventDefault();
    // The browser checks the obvious two so a typo costs no round trip; the server checks again.
    if (!f.next) return setMsg({ ok: false, text: "The new password cannot be empty." });
    if (f.next !== f.confirm) return setMsg({ ok: false, text: "The new password and its confirmation differ." });
    setBusy(true);
    setMsg(null);
    try {
      const err = await changePassword({ current: f.current, new: f.next, confirm: f.confirm });
      if (err) setMsg({ ok: false, text: err });
      else {
        setF({ current: "", next: "", confirm: "" });
        setMsg({ ok: true, text: "Password changed. Any other browser signed in as this user is signed out. Use the new password next time." });
        await qc.invalidateQueries({ queryKey: ["admin-status"] });
      }
    } catch (x) {
      setMsg({ ok: false, text: x instanceof Error ? x.message : "The request failed." });
    }
    setBusy(false);
  }

  return (
    <div className="flex flex-col gap-4">
      {s.is_default_password && (
        <div role="alert" className="rounded-lg border border-warn/50 bg-warn/15 p-3">
          <b>The default password is still in use.</b> The admin account holds the password it shipped with. Change it below.
        </div>
      )}
      <Card>
        <CardHeader>
          <CardTitle>Change the dashboard password</CardTitle>
          <CardDescription>
            The password for signing in to this GUI, stored only as a bcrypt hash. Changing it signs out every other browser signed in as the same
            user; this one stays signed in. Operators who sign in with their own API key change nothing here; they rotate the key with authadmin.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form className="grid max-w-md gap-3" onSubmit={submit} autoComplete="off">
            {(
              [
                ["current", "Current password", "current-password"],
                ["next", "New password", "new-password"],
                ["confirm", "Confirm new password", "new-password"],
              ] as const
            ).map(([k, label, ac]) => (
              <label key={k} className="flex flex-col gap-1 text-xs font-medium text-ink-2">
                {label}
                <Input type="password" autoComplete={ac} value={f[k]} onChange={(e) => setF({ ...f, [k]: e.target.value })} />
              </label>
            ))}
            <div>
              <Button type="submit" disabled={busy}>
                Change password
              </Button>
            </div>
          </form>
          {msg && (
            <div role={msg.ok ? "status" : "alert"} className={msg.ok ? "mt-3 rounded-lg border border-good/40 bg-good/10 p-3" : "mt-3 rounded-lg border border-crit/40 bg-crit/10 p-3"}>
              {msg.text}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
