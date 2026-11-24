import { describe, expect, it } from "vitest";
import { fireEvent, screen, within } from "@testing-library/react";
import { PSIRTCard, sourcesBehind } from "./psirt-card";
import { mockFetch, renderWithQuery } from "@/test/helpers";

const URL7 = "GET /api/knowledge/psirt/alerts?days=7&min_severity=high";

const hit = {
  cve: "CVE-2026-1001",
  published: "2026-11-23T10:00:00Z",
  modified: "2026-11-23T18:00:00Z",
  summary: "heap overflow in the parser",
  original_score: 9.8,
  original_severity: "critical",
  score_source: "nvd",
  cwes: ["CWE-787"],
  issue_type: "Memory safety",
  matches: [
    {
      product_id: "p1",
      product_name: "example-product",
      component: "libexample",
      matched_on: "libexample",
    },
    {
      product_id: "p2",
      product_name: "other-product",
      component: "libexample-devel",
      matched_on: "themis",
    },
  ],
  carded: true,
};
const otherHit = {
  cve: "CVE-2026-1003",
  published: "2026-11-22T10:00:00Z",
  original_score: 7.5,
  original_severity: "high",
  score_source: "cve.org",
  matches: [
    {
      product_id: "p2",
      product_name: "other-product",
      component: "libother",
      matched_on: "libother",
    },
  ],
  carded: false,
};
const worldOnly = {
  cve: "CVE-2026-1002",
  published: "2026-11-22T10:00:00Z",
  original_score: 8.1,
  original_severity: "high",
  score_source: "cve.org",
  matches: [],
  carded: false,
};

const healthy = {
  feeds: [
    { source: "nvd", status: "healthy" },
    { source: "osv/alpine", status: "informational" },
  ],
};
const behind = {
  feeds: [
    { source: "nvd", status: "stale" },
    { source: "redhat", status: "degraded" },
    { source: "epss", status: "healthy" },
  ],
};

describe("sourcesBehind", () => {
  it("counts stale and degraded sources, never informational ones", () => {
    expect(sourcesBehind(behind)).toEqual(["nvd", "redhat"]);
    expect(sourcesBehind(healthy)).toEqual([]);
    expect(sourcesBehind(null)).toEqual([]);
    expect(sourcesBehind({ feeds: [{ status: "stale" }] })).toEqual(["unnamed source"]);
  });
});

describe("PSIRTCard", () => {
  it("lists the product hits with original score, issue type and component, and the world on its own tab", async () => {
    mockFetch({
      [URL7]: [
        200,
        {
          alerts: [hit, worldOnly, otherHit],
          estate_unavailable: false,
          lookups_skipped: 0,
          issue_type_table: "1",
        },
      ],
    });
    renderWithQuery(<PSIRTCard feeds={healthy} feedsError={false} />);
    expect(await screen.findByText("CVE-2026-1001")).toHaveAttribute("href", "https://nvd.nist.gov/vuln/detail/CVE-2026-1001");
    expect(screen.getByText("Memory safety")).toBeInTheDocument();
    expect(screen.getByText("CWE-787")).toBeInTheDocument();
    expect(screen.getByText("libexample")).toBeInTheDocument();
    expect(screen.getByText("Themis")).toBeInTheDocument();
    expect(screen.getByText(/^updated /)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "in Themis" })).toHaveAttribute("href", "#/cve/CVE-2026-1001");
    expect(screen.getByText("Sources: all current.")).toBeInTheDocument();
    expect(screen.queryByText("CVE-2026-1002")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Our products (2)" })).toBeInTheDocument();

    // The product picker narrows the rows and the components shown.
    fireEvent.change(screen.getByLabelText("Product"), {
      target: { value: "p1" },
    });
    expect(screen.queryByText("CVE-2026-1003")).not.toBeInTheDocument();
    expect(screen.queryByText("libexample-devel")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "All world (3)" }));
    const row = screen.getByText("CVE-2026-1002").closest("tr") as HTMLElement;
    expect(within(row).getByText("not known")).toBeInTheDocument();
    expect(within(row).getByText("not yet")).toBeInTheDocument();
    expect(within(row).getByText("not stated")).toBeInTheDocument();
    expect(screen.queryByLabelText("Product")).not.toBeInTheDocument();
  });

  it("asks again for another window and floor", async () => {
    const calls = mockFetch({
      [URL7]: [
        200,
        {
          alerts: [],
          estate_unavailable: false,
          lookups_skipped: 0,
          issue_type_table: "1",
        },
      ],
      "GET /api/knowledge/psirt/alerts?days=30&min_severity=critical": [
        200,
        {
          alerts: [],
          estate_unavailable: false,
          lookups_skipped: 0,
          issue_type_table: "1",
        },
      ],
      "GET /api/knowledge/psirt/alerts?days=1&min_severity=critical": [
        200,
        {
          alerts: [],
          estate_unavailable: false,
          lookups_skipped: 0,
          issue_type_table: "1",
        },
      ],
    });
    renderWithQuery(<PSIRTCard feeds={healthy} feedsError={false} />);
    expect(await screen.findByText(/No critical or high CVE in the last 7 days names one of our components/)).toBeInTheDocument();
    expect(screen.getByText("All world lists 0 CVEs from the same window.")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Severity"), {
      target: { value: "critical" },
    });
    fireEvent.click(screen.getByRole("button", { name: "30 days" }));
    expect(await screen.findByText(/No critical CVE in the last 30 days/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "1 day" }));
    fireEvent.click(screen.getByRole("button", { name: /All world/ }));
    expect(await screen.findByText("No critical CVE published in the last day")).toBeInTheDocument();
    expect(calls.map((c) => c.url)).toContain("/api/knowledge/psirt/alerts?days=30&min_severity=critical");
  });

  it("never reads all clear when sources are behind", async () => {
    mockFetch({
      [URL7]: [
        200,
        {
          alerts: [],
          estate_unavailable: false,
          lookups_skipped: 0,
          issue_type_table: "1",
        },
      ],
    });
    renderWithQuery(<PSIRTCard feeds={behind} feedsError={false} />);
    expect(await screen.findByText("No new issues, but 2 sources are behind")).toBeInTheDocument();
    expect(screen.getByText("2 sources are behind: nvd, redhat.")).toBeInTheDocument();
  });

  it("names one source behind, and an unreadable source health", async () => {
    mockFetch({
      [URL7]: [
        200,
        {
          alerts: [worldOnly],
          estate_unavailable: false,
          lookups_skipped: 0,
          issue_type_table: "1",
        },
      ],
    });
    const { unmount } = renderWithQuery(<PSIRTCard feeds={{ feeds: [{ source: "nvd", status: "stale" }] }} feedsError={false} />);
    expect(await screen.findByText("No new issues, but 1 source is behind")).toBeInTheDocument();
    expect(screen.getByText("1 source is behind: nvd.")).toBeInTheDocument();
    unmount();
    renderWithQuery(<PSIRTCard feeds={undefined} feedsError />);
    expect(await screen.findByText("No new issues, but some sources are behind")).toBeInTheDocument();
    expect(screen.getByText(/Source health could not be read/)).toBeInTheDocument();
  });

  it("says the inventory was not read instead of no product hit", async () => {
    mockFetch({
      [URL7]: [
        200,
        {
          alerts: [worldOnly],
          estate_unavailable: true,
          lookups_skipped: 3,
          older_not_read: 7,
          issue_type_table: "1",
        },
      ],
    });
    renderWithQuery(<PSIRTCard feeds={healthy} feedsError={false} />);
    expect(await screen.findByText("Products could not be checked")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("The product inventory could not be read");
    expect(screen.getByText(/3 new records were not checked at CVE.org/)).toBeInTheDocument();
    expect(screen.getByText(/7 older CVEs in this window were not read/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /All world/ }));
    expect(screen.getByText("inventory not read")).toBeInTheDocument();
  });

  it("says so on a node without the alert read, and names a failed one", async () => {
    mockFetch({});
    const { unmount } = renderWithQuery(<PSIRTCard feeds={null} feedsError={false} />);
    expect(await screen.findByText("The alert is not available")).toBeInTheDocument();
    unmount();
    mockFetch({
      [URL7]: [502, { title: "bad gateway", detail: "nvd unreachable" }],
    });
    renderWithQuery(<PSIRTCard feeds={null} feedsError={false} />);
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});
