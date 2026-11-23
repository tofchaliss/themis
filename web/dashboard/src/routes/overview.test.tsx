import { describe, expect, it } from "vitest";
import { fireEvent, screen } from "@testing-library/react";
import { Overview } from "./overview";
import { mockFetch, renderWithQuery } from "@/test/helpers";

describe("Overview", () => {
  it("shows the tiles and the estate risk from every release's posture", async () => {
    mockFetch({
      "GET /api/registry/products": [200, [{ id: "p1", name: "example-product" }]],
      "GET /api/registry/products/p1/projects": [200, [{ id: "j1", name: "project-a" }]],
      "GET /api/registry/projects/j1/releases": [200, [{ id: "r1", version: "1.4.0" }, { id: "r2", version: "1.3.0" }]],
      "GET /api/governance/releases/r1/posture": [200, [{ band: "critical" }, { band: "high" }]],
      "GET /api/governance/releases/r2/posture": [200, [{ band: "high" }]],
      "GET /api/knowledge/feeds": [200, { signals_stale: true, feeds: [{ status: "healthy" }, { status: "stale" }], degraded_feeds: ["alpine"] }],
    });
    renderWithQuery(<Overview />);
    expect(await screen.findByRole("img", { name: /^3 findings by exploitability band/ })).toBeInTheDocument();
    expect(screen.getByText("1/2")).toBeInTheDocument();
    expect(screen.getByText("STALE")).toBeInTheDocument();
    expect(screen.getByText("a critical feed has gone quiet")).toBeInTheDocument();
    expect(screen.getByText("critical")).toBeInTheDocument();
  });

  it("says so when there are no findings yet", async () => {
    mockFetch({ "GET /api/registry/products": [200, []], "GET /api/knowledge/feeds": [200, { feeds: [] }] });
    renderWithQuery(<Overview />);
    expect(await screen.findByText("No findings anywhere yet")).toBeInTheDocument();
    expect(screen.getByText("OK")).toBeInTheDocument();
  });

  it("names the node that did not answer", async () => {
    mockFetch({ "GET /api/registry/products": [502], "GET /api/knowledge/feeds": [502] });
    renderWithQuery(<Overview />);
    expect(await screen.findByRole("alert")).toHaveTextContent("The registry node did not answer");
  });

  it("checks the CVE id before opening it", async () => {
    mockFetch({ "GET /api/registry/products": [200, []], "GET /api/knowledge/feeds": [200, {}] });
    renderWithQuery(<Overview />);
    const box = screen.getByLabelText("Find a CVE");
    fireEvent.change(box, { target: { value: "not-a-cve" } });
    fireEvent.click(screen.getByRole("button", { name: /find/i }));
    expect(screen.getByText("That is not a CVE id.")).toBeInTheDocument();
    expect(box).toHaveAttribute("aria-invalid", "true");
  });
});
