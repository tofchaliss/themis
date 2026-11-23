// A plain list of posture rows (one per CVE) for screens other than the release page, such as a
// comparison bucket. The same columns as the release list, without its releases dropdown; a row
// click or Enter opens the read-only drawer.
import { BandBadge, ExpertSeverity, FixCell, OriginalSeverity, PackageCell, SlaCell, StanceBadge, packageSummary, priorityTitle } from "@/components/finding-bits";
import type { PostureEntry } from "@/lib/queries";

export function FindingTable({ rows, onOpen }: { rows: PostureEntry[]; onOpen: (p: PostureEntry) => void }) {
  return (
    <table className="w-full min-w-[860px] text-left">
      <thead className="border-y border-line text-xs text-ink-2">
        <tr>
          <th className="py-2 pr-3 pl-4 font-medium">CVE</th>
          <th className="py-2 pr-3 font-medium">Original severity</th>
          <th className="py-2 pr-3 font-medium">Expert severity</th>
          <th className="py-2 pr-3 font-medium">Package</th>
          <th className="py-2 pr-3 font-medium">Decision</th>
          <th className="py-2 pr-3 font-medium">Fix</th>
          <th className="py-2 pr-3 font-medium">Next SLA</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((p) => (
          <tr
            key={p.finding_id ?? p.cve}
            className="cursor-pointer border-b border-line hover:bg-hover"
            onClick={() => onOpen(p)}
            onKeyDown={(e) => e.key === "Enter" && onOpen(p)}
            tabIndex={0}
            title={priorityTitle(p)}
            aria-label={`${p.cve}, ${packageSummary(p.components).name}`}
          >
            <td className="py-2 pr-3 pl-4 font-mono text-xs font-medium">
              {p.cve}
              <span className="ml-1.5 font-sans">
                <BandBadge band={p.band} />
              </span>
            </td>
            <td className="py-2 pr-3">
              <OriginalSeverity entry={p} />
            </td>
            <td className="py-2 pr-3">
              <ExpertSeverity entry={p} />
            </td>
            <td className="py-2 pr-3">
              <PackageCell components={p.components} />
            </td>
            <td className="py-2 pr-3">
              <StanceBadge stance={p.stance} decided={p.has_position} />
            </td>
            <td className="py-2 pr-3">
              <FixCell entry={p} />
            </td>
            <td className="py-2 pr-3">
              <SlaCell sla={p.sla} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
