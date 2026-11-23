import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { WhatsNew, bySeverity } from "./whats-new";
import { mockFetch, renderWithQuery } from "@/test/helpers";

const recent = Array.from({ length: 12 }, (_, i) => ({
  created_at: new Date(Date.now() - i * 86_400_000).toISOString(),
  card: { id: `fl${i}`, cve: `CVE-2026-${1000 + i}`, stage: "Created", view: { severity: i === 0 ? "critical" : "low", cvss_score: 9.8, kev: i === 0, exploit_public: i === 0, epss: 0.5, summary: "x".repeat(i === 0 ? 300 : 10), fixed_versions: i === 0 ? ["1", "2", "3", "4"] : [] } },
}));

describe("What's new", () => {
  it("lists the newest cards ten a page, and narrows them by tag", async () => {
    mockFetch({
      "GET /api/knowledge/faultlines/recent?limit=100": [200, recent],
      "GET /api/registry/tagged-releases?tag=team%3Apay": [200, [{ id: "r1" }]],
      "GET /api/governance/faultlines/fl0/blast-radius": [200, ["r1"]],
      "GET /api/governance/faultlines/fl1/blast-radius": [502],
    });
    renderWithQuery(<WhatsNew />);
    expect(await screen.findByRole("link", { name: "CVE-2026-1000" })).toHaveAttribute("href", "#/cve/CVE-2026-1000");
    expect(screen.getByText("today")).toBeInTheDocument();
    expect(screen.getByText("+1")).toBeInTheDocument();
    expect(screen.getByText("1–10 of 12")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    expect(screen.getByRole("link", { name: "CVE-2026-1011" })).toBeInTheDocument();
    fireEvent.keyDown(screen.getByTitle("← → move between pages"), { key: "ArrowLeft" });
    expect(screen.getByRole("link", { name: "CVE-2026-1000" })).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Only CVEs on releases tagged"), { target: { value: "Team:Pay" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(await screen.findByText(/1 of the newest 12 cards are on releases tagged team:pay/)).toBeInTheDocument();
  });

  it("finds a CVE by id", async () => {
    mockFetch({ "GET /api/knowledge/faultlines/recent?limit=100": [200, []] });
    renderWithQuery(<WhatsNew />);
    expect(await screen.findByText("No cards yet")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Find a CVE"), { target: { value: " cve-2026-1234 " } });
    fireEvent.click(screen.getByRole("button", { name: "Find" }));
    expect(window.location.hash).toBe("#/cve/CVE-2026-1234");
  });

  it("loads what NVD published, worst first, and gathers one", async () => {
    const calls = mockFetch({
      "GET /api/knowledge/faultlines/recent?limit=100": [200, []],
      "GET /api/knowledge/faultlines/published-recently?days=14": [
        200,
        [
          { cve: "CVE-B", published: "2026-11-20T00:00:00Z", severity: "low", carded: false },
          { cve: "CVE-A", published: "2026-11-21T00:00:00Z", severity: "critical", cvss_score: 9.1, carded: true },
        ],
      ],
      "POST /api/knowledge/faultlines/gather": [201, {}],
    });
    renderWithQuery(<WhatsNew />);
    fireEvent.change(screen.getByLabelText("Days"), { target: { value: "14" } });
    fireEvent.click(screen.getByRole("button", { name: "Load from NVD" }));
    expect(await screen.findByText(/2 published in the last 14 days, worst first; 1 already carded/)).toBeInTheDocument();
    const rows = screen.getAllByRole("row").slice(-2);
    expect(within(rows[0] as HTMLElement).getByRole("link", { name: "CVE-A" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Gather CVE-B" }));
    await waitFor(() => expect(screen.getAllByText("carded")).toHaveLength(2));
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ cve: "CVE-B" });
  });

  it("shows a failed load and a failed gather", async () => {
    mockFetch({
      "GET /api/knowledge/faultlines/recent?limit=100": [502],
      "GET /api/knowledge/faultlines/published-recently?days=7": [200, [{ cve: "CVE-C", published: "", carded: false }]],
      "POST /api/knowledge/faultlines/gather": [500, { detail: "nope" }],
    });
    renderWithQuery(<WhatsNew />);
    expect(await screen.findByText(/knowledge node did not answer/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Load from NVD" }));
    fireEvent.click(await screen.findByRole("button", { name: "Gather CVE-C" }));
    expect(await screen.findByText("gather failed: nope")).toBeInTheDocument();
  });

  it("orders by severity, then score, then newest", () => {
    const r = (severity: string, cvss_score: number, published: string) => ({ cve: "", carded: false, severity, cvss_score, published });
    expect([r("low", 1, "a"), r("high", 5, "a"), r("high", 7, "a"), r("", 0, "b"), r("", 0, "c")].sort(bySeverity).map((x) => `${x.severity}${x.cvss_score}${x.published}`)).toEqual([
      "high7a",
      "high5a",
      "low1a",
      "0c",
      "0b",
    ]);
  });
});
