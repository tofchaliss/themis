import { describe, expect, it } from "vitest";
import { fireEvent, screen, within } from "@testing-library/react";
import { Scan } from "./scan";
import { mockFetch, renderWithQuery, type Reply } from "@/test/helpers";

const report = {
  findings: [
    { cve: "CVE-2026-0002", severity: "HIGH", cvss_score: 7.5, component: { name: "zlib", version: "1.2" }, fixed: ["1.3"] },
    { cve: "CVE-2026-0001", severity: "critical", component: { name: "openssl" } },
    { cve: "CVE-2026-0009", severity: "low", component: { name: "curl", version: "8" } },
  ],
};
const posture = [
  { finding_id: "f1", cve: "CVE-2026-0001", band: "critical", residual_priority: 19, has_position: false, expert_score: 9.1, expert_severity: "critical", score_state: "scored" },
  { finding_id: "f2", cve: "CVE-2026-0002", band: "elevated", residual_priority: 3, has_position: true, stance: "not_affected" },
];
const base: Record<string, Reply> = {
  "GET /api/evidence/evidence/e1": [200, { id: "e1", kind: "scanner-report", provenance_source: "trivy", filed_at: "2026-11-20T10:00:00Z" }],
  "GET /api/evidence/evidence/e1/document": [200, { kind: "scanner-report", document: JSON.stringify(report) }],
  "GET /api/governance/releases/r1/posture": [200, posture],
};

describe("Scan report", () => {
  it("shows every claim beside its Finding, most urgent first, and opens the drawer", async () => {
    mockFetch(base);
    renderWithQuery(<Scan evidenceId="e1" releaseId="r1" version="1.4.0" />);
    const rows = await screen.findAllByRole("row", { name: /claim$/ });
    expect(rows.map((r) => r.getAttribute("aria-label"))).toEqual(["CVE-2026-0001 claim", "CVE-2026-0002 claim", "CVE-2026-0009 claim"]);
    expect(screen.getByText("trivy")).toBeInTheDocument();
    expect(screen.getByText("filed 2026-11-20")).toBeInTheDocument();
    expect(within(rows[1] as HTMLElement).getByText("high 7.5")).toBeInTheDocument();
    expect(within(rows[1] as HTMLElement).getByText("zlib@1.2")).toBeInTheDocument();
    expect(within(rows[1] as HTMLElement).getByText("1.3")).toBeInTheDocument();
    expect(within(rows[0] as HTMLElement).getByText("9.1")).toBeInTheDocument();
    expect(within(rows[2] as HTMLElement).getByText(/no Finding/)).toBeInTheDocument();
    expect(screen.getByText("Matched").previousElementSibling).toHaveTextContent("2");
    expect(screen.getByText("No Finding").previousElementSibling).toHaveTextContent("1");
    expect(screen.getByRole("link", { name: /back to the release/i })).toHaveAttribute("href", "#/release/r1?v=1.4.0");
    fireEvent.keyDown(rows[1] as HTMLElement, { key: "Enter" });
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
  });

  it("says when the document is missing, not a report, or empty", async () => {
    mockFetch({ ...base, "GET /api/evidence/evidence/e1/document": [404] });
    const a = renderWithQuery(<Scan evidenceId="e1" releaseId="r1" version="" />);
    expect(await screen.findByText(/was not found/)).toBeInTheDocument();
    a.unmount();
    mockFetch({ ...base, "GET /api/evidence/evidence/e1/document": [200, { kind: "sbom", document: "{not json" }] });
    const b = renderWithQuery(<Scan evidenceId="e1" releaseId="r1" version="" />);
    expect(await screen.findByText(/not a curated scanner report/)).toBeInTheDocument();
    b.unmount();
    mockFetch({ ...base, "GET /api/evidence/evidence/e1/document": [200, { kind: "scanner-report", document: '{"findings":[]}' }] });
    const c = renderWithQuery(<Scan evidenceId="e1" releaseId="r1" version="" />);
    expect(await screen.findByText("Empty report")).toBeInTheDocument();
    c.unmount();
    mockFetch({ ...base, "GET /api/governance/releases/r1/posture": [502] });
    renderWithQuery(<Scan evidenceId="e1" releaseId="r1" version="" />);
    expect(await screen.findByText(/governance node did not answer/i)).toBeInTheDocument();
  });
});
