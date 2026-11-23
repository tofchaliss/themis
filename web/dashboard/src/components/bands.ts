// Knowledge's exploitability bands, in fixed order with fixed status colours (EDR-GUI-01:
// status is never themed). "critical" means CVSS >= 9 AND KEV-listed.
export const BANDS = [
  { id: "critical", label: "critical", color: "var(--st-crit)" },
  { id: "high+", label: "high+", color: "var(--st-serious)" },
  { id: "high", label: "high", color: "var(--st-warn)" },
  { id: "elevated", label: "elevated", color: "var(--st-elevated)" },
  { id: "informational", label: "informational", color: "var(--st-info)" },
] as const;

export type Slice = { id: string; label: string; color: string; n: number };

export function bandSlices(bands: (string | undefined)[]): Slice[] {
  const out: Slice[] = BANDS.map((b) => ({ ...b, n: bands.filter((x) => x === b.id).length }));
  const known = new Set<string>(BANDS.map((b) => b.id));
  const unbanded = bands.filter((x) => !x || !known.has(x)).length;
  if (unbanded) out.push({ id: "unbanded", label: "unbanded", color: "var(--muted)", n: unbanded });
  return out.filter((s) => s.n > 0);
}
