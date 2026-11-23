// One donut, band order fixed, fixed status colours, always-on legend with counts — identity
// never rides on hue alone; the centre carries the total.
import type { Slice } from "./bands";

export function Donut({
  slices,
  total,
  label = "findings by exploitability band",
  compact = false,
}: {
  slices: Slice[];
  total: number;
  label?: string;
  compact?: boolean;
}) {
  const R = 74;
  const r = 46;
  const c = 84;
  const pt = (a: number, rad: number) => `${(c + rad * Math.cos(a)).toFixed(2)} ${(c + rad * Math.sin(a)).toFixed(2)}`;
  const arcs = slices.reduce<{ a0: number; paths: { d: string; s: Slice }[] }>(
    (acc, s) => {
      const a1 = acc.a0 + (s.n / total) * Math.PI * 2;
      const large = a1 - acc.a0 > Math.PI ? 1 : 0;
      const s0 = acc.a0 + 0.008;
      const s1 = Math.max(s0 + 0.001, a1 - 0.008);
      const d = `M ${pt(s0, R)} A ${R} ${R} 0 ${large} 1 ${pt(s1, R)} L ${pt(s1, r)} A ${r} ${r} 0 ${large} 0 ${pt(s0, r)} Z`;
      return { a0: a1, paths: [...acc.paths, { d, s }] };
    },
    { a0: -Math.PI / 2, paths: [] },
  ).paths;
  return (
    <div className={compact ? "flex items-center gap-3" : "flex flex-wrap items-center gap-6"}>
      <svg
        viewBox="0 0 168 168"
        className={compact ? "size-20 shrink-0" : "size-40 shrink-0"}
        role="img"
        aria-label={`${total} ${label}: ${slices.map((s) => `${s.label} ${s.n}`).join(", ")}`}
      >
        {arcs.map(({ d, s }) => (
          <path key={s.id} d={d} fill={s.color}>
            <title>{`${s.label}: ${s.n}`}</title>
          </path>
        ))}
        <text x="84" y="82" textAnchor="middle" className="fill-ink text-[22px] font-semibold">
          {total}
        </text>
        <text x="84" y="98" textAnchor="middle" className="fill-ink-2 text-[11px]">
          findings
        </text>
      </svg>
      <ul className={compact ? "flex min-w-[120px] flex-col gap-0.5 text-xs" : "flex min-w-[160px] flex-col gap-1.5"}>
        {slices.map((s) => (
          <li key={s.id} className="flex items-center justify-between gap-4">
            <span className="flex items-center gap-2">
              <span className={compact ? "size-2 rounded-full" : "size-2.5 rounded-full"} style={{ background: s.color }} aria-hidden />
              {s.label}
            </span>
            <span className="font-semibold tabular-nums">{s.n}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
