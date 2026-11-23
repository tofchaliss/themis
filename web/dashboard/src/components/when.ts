/** "5 min ago", "3 h ago", "2 d ago"; "never" for no time. */
export function ago(iso?: string | null): string {
  if (!iso) return "never";
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (Number.isNaN(s)) return "—";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

/** "2026-11-23 14:05" in the viewer's own time zone. */
export function when(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
