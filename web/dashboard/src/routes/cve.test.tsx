import { describe, expect, it } from "vitest";
import { screen } from "@testing-library/react";
import { Cve } from "./cve";
import { mockFetch, renderWithQuery } from "@/test/helpers";

const card = {
  id: "fl1",
  cve: "CVE-2026-0001",
  stage: "Correlated",
  proposals: [{}, {}],
  view: {
    summary: "A flaw.",
    summary_source: "nvd",
    severity: "high",
    cvss_score: 7.5,
    cvss_vector: "CVSS:3.1/AV:N",
    severity_source: "nvd",
    kev: true,
    epss: 0.02,
    affected_range_statements: [{ ecosystem: "npm", package: "a", range: "<2" }],
    fixed_versions: ["2.0"],
  },
};
const ratings = {
  cve: "CVE-2026-0001",
  observations: [],
  ratings: [
    { id: "x1", observation_id: "o", source: "nvd", feed: "nvd-api", assessor: "nvd", nvd_type: "Primary", cvss_version: "3.1", vector: "AV:N", status: "active", recorded_at: "", validation: { calculator_version: "1", result: "valid", base_score: 7.5 }, identity: { key: "k1" } },
    { id: "x2", observation_id: "o", source: "osv", feed: "osv", publisher: "github", assessor: "nvd", cvss_version: "3.1", vector: "AV:N", status: "superseded", recorded_at: "", identity: { key: "k1" } },
    { id: "x3", observation_id: "o", source: "redhat", feed: "csaf", assessor: "redhat", cvss_version: "4.0", vector: "AV:L", status: "active", recorded_at: "", validation: { calculator_version: "1", result: "unsupported_cvss_version" } },
  ],
};

describe("CVE card", () => {
  it("shows the card, the ratings and the releases by name", async () => {
    mockFetch({
      "GET /api/knowledge/faultlines?cve=CVE-2026-0001": [200, card],
      "GET /api/knowledge/faultlines/fl1/releases": [200, ["r1", "r9"]],
      "GET /api/knowledge/faultlines/fl1/ratings": [200, ratings],
      "GET /api/registry/releases/r1": [200, { id: "r1", project_id: "j1", version: "1.4.0" }],
      "GET /api/registry/projects/j1": [200, { id: "j1", name: "project-a", product_id: "p1" }],
      "GET /api/registry/products/p1": [200, { id: "p1", name: "product-a" }],
    });
    renderWithQuery(<Cve cve="CVE-2026-0001" />);
    expect(await screen.findByText(/A flaw\./)).toBeInTheDocument();
    expect(screen.getByText("KEV")).toBeInTheDocument();
    expect(screen.getByText("EPSS 2.0%")).toBeInTheDocument();
    expect(screen.getByText("npm a <2")).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: "product-a / project-a / v1.4.0" })).toHaveAttribute("href", "#/release/r1?v=1.4.0");
    expect(screen.getByRole("link", { name: "r9" })).toBeInTheDocument();
    expect(await screen.findByText("github via osv")).toBeInTheDocument();
    expect(screen.getByText("unsupported cvss version")).toBeInTheDocument();
    expect(screen.getByText("superseded")).toBeInTheDocument();
  });

  it("says when there is no card, when nothing is filed, and when ratings cannot be read", async () => {
    mockFetch({ "GET /api/knowledge/faultlines?cve=CVE-2026-0002": [404] });
    const a = renderWithQuery(<Cve cve="CVE-2026-0002" />);
    expect(await screen.findByText("No card for CVE-2026-0002")).toBeInTheDocument();
    a.unmount();
    mockFetch({
      "GET /api/knowledge/faultlines?cve=CVE-2026-0003": [200, { id: "fl3", cve: "CVE-2026-0003" }],
      "GET /api/knowledge/faultlines/fl3/releases": [200, []],
      "GET /api/knowledge/faultlines/fl3/ratings": [502],
    });
    const b = renderWithQuery(<Cve cve="CVE-2026-0003" />);
    expect(await screen.findByText("no release in the estate")).toBeInTheDocument();
    expect(await screen.findByText(/unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/No stored summary yet/)).toBeInTheDocument();
    expect(screen.getByText("none recorded")).toBeInTheDocument();
    b.unmount();
    mockFetch({ "GET /api/knowledge/faultlines?cve=CVE-2026-0004": [502] });
    renderWithQuery(<Cve cve="CVE-2026-0004" />);
    expect(await screen.findByText(/knowledge node did not answer/i)).toBeInTheDocument();
  });
});
