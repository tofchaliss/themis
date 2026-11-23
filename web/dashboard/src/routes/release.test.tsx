import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { Release } from "./release";
import { mockFetch, renderWithQuery, type Reply } from "@/test/helpers";

const sla = (state: string, days_left: number) => ({
  state,
  bucket: "high",
  bucket_changed: false,
  period_start: "2026-11-01T00:00:00Z",
  due: "2026-12-01T00:00:00Z",
  days_left,
  kev_due_applied: state === "breached",
  age_days: 22,
  days_under_acceptance: 0,
});

const posture = [
  {
    finding_id: "f-low",
    faultline_id: "fl-low",
    cve: "CVE-2026-0002",
    band: "elevated",
    base_score: 5.1,
    residual_priority: 1,
    effective_priority: 1,
    has_position: true,
    stance: "not_affected",
    components: [{ name: "zlib", claim_class: "carrier", verdict_state: "cleared_vendor_fix" }],
    fixes: [],
    sla: sla("met", 0),
    original_score: 5.3,
    original_severity: "medium",
    score_state: "no_open_occurrences",
  },
  {
    finding_id: "f-top",
    faultline_id: "fl-top",
    cve: "CVE-2026-0001",
    band: "critical",
    base_score: 9.8,
    residual_priority: 19.6,
    effective_priority: 19.6,
    has_position: false,
    stance: "",
    components: [
      { name: "python3-pyyaml", claim_class: "scope" },
      { name: "openssl", claim_class: "carrier" },
    ],
    fixes: [{ package: "openssl", version: "3.0.7-27" }, { version: "3.0.8" }],
    sla: sla("breached", -3),
    disposition_stale: { since: "2026-11-20T00:00:00Z", reason: "entered KEV" },
    original_score: 9.8,
    original_severity: "critical",
    expert_score: 6.4,
    expert_severity: "medium",
    expert_status: "provisional",
    score_state: "scored",
  },
];

const base: Record<string, Reply> = {
  "GET /api/governance/releases/r1/posture": [200, posture],
  "GET /api/registry/releases/r1": [200, { id: "r1", project_id: "j1", version: "1.4.0" }],
  "GET /api/registry/projects/j1": [200, { id: "j1", name: "project-a" }],
};

describe("Release posture", () => {
  it("shows the summary card and one row per CVE, most urgent first, with both severities and without the dropped columns", async () => {
    mockFetch(base);
    renderWithQuery(<Release id="r1" version="" />);
    expect(await screen.findByRole("heading", { name: "project-a v1.4.0" })).toBeInTheDocument();
    const rows = await screen.findAllByRole("row", { name: /CVE-2026-000/ });
    expect(rows.map((r) => r.getAttribute("aria-label"))).toEqual(["CVE-2026-0001, openssl", "CVE-2026-0002, zlib"]);
    expect(rows[0]).toHaveAttribute("title", "priority 19.6 after decisions (19.6 before), base 9.8");
    const top = rows[0] as HTMLElement;
    // The band beside the CVE and the original severity are both "critical" here.
    expect(within(top).getAllByText("critical")).toHaveLength(2);
    expect(within(top).getByText("open")).toBeInTheDocument();
    expect(within(top).getByText("re-surfaced")).toBeInTheDocument();
    expect(within(top).getByText("breached 3d ago")).toBeInTheDocument();
    expect(within(top).getByText("KEV date")).toBeInTheDocument();
    expect(within(top).getByText("3.0.7-27")).toBeInTheDocument();
    expect(within(top).getAllByText("+1")).toHaveLength(2);
    expect(within(rows[1] as HTMLElement).getByText("none attributed")).toBeInTheDocument();
    expect(within(rows[1] as HTMLElement).getByText("not affected")).toBeInTheDocument();
    for (const gone of ["Blast", "Base", "Band", "Score", "Severity"]) expect(screen.queryByRole("columnheader", { name: gone })).toBeNull();
    expect(screen.getByRole("columnheader", { name: "Original severity" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Expert severity" })).toBeInTheDocument();
    expect(within(top).getByText("9.8")).toBeInTheDocument();
    expect(within(top).getByText("6.4")).toBeInTheDocument();
    expect(within(top).getByText("prov.")).toBeInTheDocument();
    expect(within(rows[1] as HTMLElement).getByText("5.3")).toBeInTheDocument();
    expect(within(rows[1] as HTMLElement).getByText("cleared")).toBeInTheDocument();
    expect(screen.getByText("SLA breached", { selector: "div" }).previousElementSibling).toHaveTextContent("1");
    expect(screen.getByRole("img", { name: /exploitability band: critical 1, elevated 1/ })).toBeInTheDocument();
    expect(screen.getByRole("img", { name: /expert severity: medium 1, not assessed 1/ })).toBeInTheDocument();
  });

  it("filters by open, SLA breached and text", async () => {
    mockFetch(base);
    renderWithQuery(<Release id="r1" version="1.4.0" />);
    await screen.findAllByRole("row", { name: /CVE-2026-000/ });
    fireEvent.click(screen.getByRole("radio", { name: "Open" }));
    expect(screen.getAllByRole("row", { name: /CVE-2026-000/ })).toHaveLength(1);
    fireEvent.click(screen.getByRole("radio", { name: /SLA breached/ }));
    expect(screen.getAllByRole("row", { name: /CVE-2026-000/ })).toHaveLength(1);
    fireEvent.click(screen.getByRole("radio", { name: /All/ }));
    fireEvent.change(screen.getByLabelText("Filter by CVE or package"), { target: { value: "zlib" } });
    expect(screen.getAllByRole("row", { name: /CVE-2026-000/ })).toHaveLength(1);
    fireEvent.change(screen.getByLabelText("Filter by CVE or package"), { target: { value: "nothing-here" } });
    expect(screen.getByText("Nothing matches")).toBeInTheDocument();
  });

  it("opens the releases dropdown under a CVE without opening the drawer", async () => {
    const calls = mockFetch({
      ...base,
      "GET /api/governance/faultlines/fl-top/findings": [
        200,
        [
          { ...posture[1], release_id: "r1" },
          { finding_id: "f2", release_id: "r2", faultline_id: "fl-top", has_position: true, stance: "affected", decided_by_kind: "human", decided_at: "2026-11-02T10:00:00Z", components: [{ name: "openssl" }], fixes: [] },
          { finding_id: "f4", release_id: "r4", faultline_id: "fl-top", has_position: true, stance: "not_affected", decided_by_kind: "policy", decided_at: "2026-11-03T10:00:00Z" },
          { finding_id: "f3", release_id: "r3", faultline_id: "fl-top", has_position: false },
        ],
      ],
      "GET /api/registry/releases/r2": [200, { id: "r2", project_id: "j1", version: "2.0.0" }],
      "GET /api/registry/releases/r4": [200, { id: "r4", project_id: "j1", version: "2.1.0" }],
      "GET /api/registry/releases/r3": [502],
    });
    renderWithQuery(<Release id="r1" version="1.4.0" />);
    fireEvent.click(await screen.findByRole("button", { name: "Show releases with CVE-2026-0001" }));
    expect(await screen.findByRole("link", { name: "project-a v2.0.0" })).toHaveAttribute("href", "#/release/r2?v=2.0.0");
    expect(screen.getByText("this release")).toBeInTheDocument();
    expect(screen.getByText("affected")).toBeInTheDocument();
    expect(screen.getByText("MANUAL")).toBeInTheDocument();
    expect(screen.getByText("AUTO")).toBeInTheDocument();
    expect(screen.getByText("2026-11-02")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "release vr3" })).toBeInTheDocument();
    // One project read for the two releases of project-a (r1's comes from the page itself).
    expect(calls.filter((c) => c.url === "/api/registry/projects/j1").length).toBeLessThanOrEqual(2);
    expect(screen.queryByRole("dialog")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Hide releases with CVE-2026-0001" }));
    expect(screen.queryByRole("link", { name: "project-a v2.0.0" })).toBeNull();
  });

  it("says so when Governance lists no release, and shows its error", async () => {
    mockFetch({ ...base, "GET /api/governance/faultlines/fl-top/findings": [200, []], "GET /api/governance/faultlines/fl-low/findings": [502] });
    renderWithQuery(<Release id="r1" version="1.4.0" />);
    fireEvent.click(await screen.findByRole("button", { name: "Show releases with CVE-2026-0001" }));
    expect(await screen.findByText("Governance lists no releases for this CVE.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Show releases with CVE-2026-0002" }));
    expect(await screen.findByText(/governance node did not answer/i)).toBeInTheDocument();
  });

  it("opens the read-only drawer on a row click and on Enter", async () => {
    mockFetch({
      ...base,
      "GET /api/governance/findings/f-low/assessment": [
        200,
        {
          knowledge: { summary: "A zlib flaw.", severity: "medium", cvss_score: 5.1, kev: true, exploit_public: true, epss: 0.123, fixes: [{ package: "zlib", version: "1.3" }] },
          finding: {
            components: [
              { name: "zlib", version: "1.2", claim_class: "carrier", verdict_state: "cleared_vendor_fix", verdict_grade: "inferred", verdict_reason: "rpm build carries the fix" },
              { name: "zlib-devel", claim_class: "scope" },
            ],
            current_position: {
              stance: "not_affected",
              actor_kind: "human",
              actor_id: "alice",
              established_at: "2026-11-02T10:00:00Z",
              treatment: "upgrade",
              scope: "project",
              rationale: "Not reachable.",
              review_by: "2027-01-01T00:00:00Z",
            },
            proposals: [
              { id: "p1", stance: "not_affected", proposer_kind: "ai", proposer_id: "gw", raised_at: "2026-11-01T00:00:00Z", status: "accepted", evidence_trust: "inferred", rationale: "AI says so" },
              { id: "p2", stance: "affected", proposer_kind: "system", status: "rejected" },
            ],
          },
          vendor_statements: [{ package: "zlib", status: "not_affected", applicability: "applicable", justification: "component_not_present" }],
        },
      ],
    });
    renderWithQuery(<Release id="r1" version="1.4.0" />);
    const rows = await screen.findAllByRole("row", { name: /CVE-2026-000/ });
    fireEvent.click(rows[1] as HTMLElement);
    const dialog = await screen.findByRole("dialog");
    expect(await within(dialog).findByText("A zlib flaw.")).toBeInTheDocument();
    expect(within(dialog).getByText("medium · CVSS 5.1")).toBeInTheDocument();
    expect(within(dialog).getByText("EPSS 12.3%")).toBeInTheDocument();
    expect(within(dialog).getByText("MANUAL")).toBeInTheDocument();
    expect(within(dialog).getByText("decided for the project")).toBeInTheDocument();
    expect(within(dialog).getByText("Not reachable.")).toBeInTheDocument();
    expect(within(dialog).getByText("cleared, inferred")).toBeInTheDocument();
    expect(within(dialog).getByText("rpm build carries the fix")).toBeInTheDocument();
    expect(within(dialog).getByText("applicable")).toBeInTheDocument();
    expect(within(dialog).getByText("AI says so")).toBeInTheDocument();
    expect(within(dialog).getByRole("link", { name: "Decide…" })).toHaveAttribute("href", "#/decide/f-low?rel=r1&v=1.4.0");
    fireEvent.keyDown(dialog, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());

    mockFetch({ ...base, "GET /api/governance/findings/f-top/assessment": [200, { knowledge: {}, finding: { components: [], proposals: [] } }] });
    fireEvent.keyDown(rows[0] as HTMLElement, { key: "Enter" });
    const d2 = await screen.findByRole("dialog");
    expect(await within(d2).findByText("none recorded", { selector: "span" })).toBeInTheDocument();
    expect(within(d2).getByText("none for these components")).toBeInTheDocument();
    expect(within(d2).getByText("since 2026-11-20")).toBeInTheDocument();
    expect(within(d2).getAllByText("none").length).toBeGreaterThan(0);
  });

  it("names a node that did not answer, in the page and in the drawer", async () => {
    mockFetch({ ...base, "GET /api/governance/findings/f-top/assessment": [502] });
    renderWithQuery(<Release id="r1" version="1.4.0" />);
    fireEvent.click((await screen.findAllByRole("row", { name: /CVE-2026-000/ }))[0] as HTMLElement);
    expect(await within(await screen.findByRole("dialog")).findByText(/governance node did not answer/i)).toBeInTheDocument();
  });

  it("shows the posture error and the empty release", async () => {
    mockFetch({ "GET /api/governance/releases/r9/posture": [502] });
    renderWithQuery(<Release id="r9" version="9" />);
    expect(await screen.findByText(/governance node did not answer/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "v9" })).toBeInTheDocument();

    mockFetch({ "GET /api/governance/releases/r8/posture": [200, []] });
    renderWithQuery(<Release id="r8" version="" />);
    expect(await screen.findByText("No findings")).toBeInTheDocument();
  });
});
