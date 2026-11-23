import { describe, expect, it } from "vitest";
import { fireEvent, screen, within } from "@testing-library/react";
import { Compare } from "./compare";
import { mockFetch, renderWithQuery, type Reply } from "@/test/helpers";

const base: Record<string, Reply> = {
  "GET /api/registry/products": [200, [{ id: "p1", name: "product-a" }]],
  "GET /api/registry/products/p1/projects": [200, [{ id: "j1", name: "project-a" }]],
  "GET /api/registry/projects/j1/releases": [
    200,
    [
      { id: "r1", version: "1.0" },
      { id: "r2", version: "2.0" },
    ],
  ],
};
const row = (cve: string, rel: string, extra = {}) => ({ finding_id: `f-${cve}`, release_id: rel, cve, band: "high", components: [{ name: "zlib" }], ...extra });

const pick = async () => {
  await screen.findByRole("option", { name: "product-a" });
  fireEvent.change(screen.getByLabelText("Product"), { target: { value: "p1" } });
  await screen.findByRole("option", { name: "project-a" });
  fireEvent.change(screen.getByLabelText("Project"), { target: { value: "j1" } });
  await screen.findAllByRole("option", { name: "v2.0" });
  fireEvent.change(screen.getByLabelText("Baseline release"), { target: { value: "r1" } });
  fireEvent.change(screen.getByLabelText("Candidate release"), { target: { value: "r2" } });
};

describe("Compare releases", () => {
  it("shows the three buckets, opens the drawer, and narrates on request", async () => {
    mockFetch({
      ...base,
      "GET /api/governance/releases/r1/compare/r2": [
        200,
        { fixed: [row("CVE-1", "r1")], new: [], persisting: [row("CVE-2", "r2", { has_position: true, stance: "affected" })] },
      ],
      "POST /api/intelligence/capabilities/compare_releases/invoke": [200, { information: "One fixed. [UNVERIFIED MENTIONS: CVE-9]", decided_by: "model", precedents_used: 1 }],
    });
    renderWithQuery(<Compare />);
    await pick();
    fireEvent.click(screen.getByRole("button", { name: "Compare" }));
    expect(await screen.findByText("Fixed in v2.0")).toBeInTheDocument();
    expect(screen.getByText("Nothing new")).toBeInTheDocument();
    expect(screen.getByText("Decided", { selector: "div" }).previousElementSibling).toHaveTextContent("1");
    fireEvent.click(screen.getByRole("row", { name: /CVE-1/ }));
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    fireEvent.click(screen.getByRole("button", { name: "Narrate this comparison" }));
    expect(await screen.findByText(/One fixed\./)).toBeInTheDocument();
    expect(screen.getByText("[UNVERIFIED MENTIONS: CVE-9]").tagName).toBe("MARK");
    expect(screen.getByText("1 precedent used")).toBeInTheDocument();
    expect(within(screen.getByRole("row", { name: /CVE-2/ })).getByText("affected")).toBeInTheDocument();
  });

  it("shows a refusal with versions, not ids, and a no-answer by its reason", async () => {
    mockFetch({ ...base, "GET /api/governance/releases/r1/compare/r2": [422, { title: "no evidence", detail: "release r2 has no SBOM" }] });
    const a = renderWithQuery(<Compare />);
    await pick();
    fireEvent.click(screen.getByRole("button", { name: "Compare" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("no evidence: release v2.0 has no SBOM");
    a.unmount();

    mockFetch({
      ...base,
      "GET /api/governance/releases/r1/compare/r2": [200, { fixed: [], new: [row("CVE-3", "r2")], persisting: [] }],
      "POST /api/intelligence/capabilities/compare_releases/invoke": [204],
    });
    renderWithQuery(<Compare />);
    await pick();
    fireEvent.click(screen.getByRole("button", { name: "Compare" }));
    expect(await screen.findByText("Nothing fixed")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Narrate this comparison" }));
    expect(await screen.findByText("no answer")).toBeInTheDocument();
  });
});
