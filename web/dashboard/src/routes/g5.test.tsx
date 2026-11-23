import { describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { Reports } from "./reports";
import { Feeds } from "./feeds";
import { Admin } from "./admin";
import { Watches, WatchView, watchCsv } from "./watches";
import { mockFetch, renderWithQuery } from "@/test/helpers";

const mean = (mean_days: number, count: number) => ({ mean_days, count });
const metrics = (scope: string, open: number) => ({
  scope,
  open,
  open_by_age: { "0-7": { critical: 2 }, "over-90": { low: 1 } },
  sla_applicable: open ? 4 : 0,
  within_sla: 3,
  breached_now: 1,
  within_sla_share: 0.75,
  time_to_decision: mean(2.5, 4),
  time_to_remediation: mean(0, 0),
  time_to_resolution: mean(10, 1),
});

describe("Reports", () => {
  it("shows the estate and each product, and filters by tag", async () => {
    mockFetch({
      "GET /api/governance/metrics/remediation": [200, { generated_at: "", estate: metrics("", 5), products: [metrics("product-a", 0)], products_unavailable: true, unattributed: 2 }],
      "GET /api/governance/metrics/remediation?tag=env%3Aprod": [404],
    });
    renderWithQuery(<Reports />);
    expect(await screen.findByText("Estate")).toBeInTheDocument();
    expect(screen.getByText("product-a")).toBeInTheDocument();
    expect(screen.getAllByText("2.5 d").length).toBeGreaterThan(0);
    expect(screen.getAllByText("no sample").length).toBeGreaterThan(0);
    expect(screen.getByText(/Per-product figures are unavailable/)).toBeInTheDocument();
    expect(screen.getByText(/2 finding\(s\) sit on releases/)).toBeInTheDocument();
    expect(screen.getByText("Within SLA", { selector: "div" }).previousElementSibling).toHaveTextContent("75%");
    fireEvent.change(screen.getByLabelText("Only releases tagged"), { target: { value: "Env:Prod" } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(await screen.findByText("No metrics")).toBeInTheDocument();
    expect(screen.getByText(/covers only releases tagged env:prod/)).toBeInTheDocument();
  });

  it("names a node that did not answer", async () => {
    mockFetch({ "GET /api/governance/metrics/remediation": [502] });
    renderWithQuery(<Reports />);
    expect(await screen.findByText(/governance node did not answer/i)).toBeInTheDocument();
  });
});

describe("Feeds", () => {
  it("shows the feeds, the stale warning and the webhooks", async () => {
    mockFetch({
      "GET /api/knowledge/feeds": [200, { signals_stale: true, feeds: [{ source: "nvd", tier: 1, status: "stale", consecutive_failures: 3, last_success_at: null }, { source: "osv", tier: 2, status: "healthy" }] }],
      "GET /api/communication/webhook-health": [200, [{ destination: "teams-sec", state: "inactive_tmp", consecutive_failures: 2, paused_until: "2026-11-23T10:00:00Z", last_error: "timeout" }]],
    });
    renderWithQuery(<Feeds />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Signals are STALE");
    expect(screen.getAllByText("never").length).toBeGreaterThan(0);
    expect(await screen.findByText("teams-sec")).toBeInTheDocument();
    expect(screen.getByText("timeout")).toBeInTheDocument();
  });

  it("says when nothing is recorded, and hides webhooks on an older node", async () => {
    mockFetch({ "GET /api/knowledge/feeds": [200, { feeds: [] }], "GET /api/communication/webhook-health": [200, []] });
    const a = renderWithQuery(<Feeds />);
    expect(await screen.findByText("No feed activity recorded")).toBeInTheDocument();
    expect(await screen.findByText("No webhook sent yet")).toBeInTheDocument();
    a.unmount();
    mockFetch({ "GET /api/knowledge/feeds": [502] });
    renderWithQuery(<Feeds />);
    expect(await screen.findByText(/knowledge node did not answer/i)).toBeInTheDocument();
  });
});

describe("Admin", () => {
  it("changes the password, checks the two fields first, and shows a refusal", async () => {
    const calls = mockFetch({
      "GET /whoami": [200, { user: "admin", scopes: ["admin"] }],
      "GET /api/dashboard/admin/status": [200, { auth_enabled: true, is_default_password: true }],
      "POST /api/dashboard/admin/password": (b) => ((b as { current: string }).current === "old" ? [204] : [401, { detail: "that is not your current password" }]),
    });
    renderWithQuery(<Admin />);
    expect(await screen.findByText(/default password is still in use/)).toBeInTheDocument();
    const submit = screen.getByRole("button", { name: "Change password" });
    fireEvent.click(submit);
    expect(await screen.findByText("The new password cannot be empty.")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: "a" } });
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "b" } });
    fireEvent.click(submit);
    expect(await screen.findByText(/confirmation differ/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: "a" } });
    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "wrong" } });
    fireEvent.click(submit);
    expect(await screen.findByText("that is not your current password")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "old" } });
    fireEvent.click(submit);
    expect(await screen.findByText(/Password changed/)).toBeInTheDocument();
    expect(calls.filter((c) => c.url === "/api/dashboard/admin/password")).toHaveLength(2);
  });

  it("explains a session without admin, auth switched off, and an unreadable status", async () => {
    mockFetch({ "GET /whoami": [200, { user: "viewer" }], "GET /api/dashboard/admin/status": [403] });
    const a = renderWithQuery(<Admin />);
    expect(await screen.findByText(/without that scope/)).toBeInTheDocument();
    a.unmount();
    mockFetch({ "GET /whoami": [200, { user: "operator" }], "GET /api/dashboard/admin/status": [200, { auth_enabled: false }] });
    const b = renderWithQuery(<Admin />);
    expect(await screen.findByText(/Authentication is off/)).toBeInTheDocument();
    b.unmount();
    mockFetch({ "GET /whoami": [200, { user: "operator" }], "GET /api/dashboard/admin/status": [500] });
    renderWithQuery(<Admin />);
    expect(await screen.findByText(/could not read its own admin status/)).toBeInTheDocument();
  });
});

const status = {
  watch: { id: "w1", name: "wave 11", created_by: "alice", created_at: new Date().toISOString(), identifiers: ["CVE-1", "RHSA-1"], resolved_cves: ["CVE-1"], notify: false },
  generated_at: "2026-11-23T10:00:00Z",
  note: "Computed from what Themis knows.",
  identifiers: [
    { id: "CVE-1", kind: "cve", cves: ["CVE-1"], resolved: true },
    { id: "RHSA-1", kind: "advisory", cves: [], resolved: false },
  ],
  rows: [
    { release_id: "r1", product_name: "product-a", project_name: "project-a", version: "1.0", cve: "CVE-1", state: "open_fix_available", packages: ["openssl"], fixes: ["3.0.7"], last_evidence_kind: "sbom", last_evidence_at: "2026-11-20T10:00:00Z" },
    { release_id: "r2", product_id: "p2", project_id: "j2", cve: "CVE-1", state: "fixed", stance: "affected", packages: [], fixes: [] },
    { product_name: "product-b", cve: "CVE-1", state: "unknown", packages: [], fixes: [] },
  ],
  counts: { open_fix_available: 1, fixed: 1, unknown: 1 },
};

describe("Watches", () => {
  it("lists watches and creates one", async () => {
    const calls = mockFetch({
      "GET /whoami": [200, { user: "alice" }],
      "GET /api/governance/watches": [200, [status.watch]],
      "POST /api/governance/watches": [201, { watch: { ...status.watch, id: "w9" }, added: 2, rejected: [] }],
    });
    renderWithQuery(<Watches />);
    expect(await screen.findByRole("link", { name: "wave 11" })).toHaveAttribute("href", "#/watches/w1");
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "wave 12" } });
    fireEvent.change(screen.getByLabelText("Identifiers"), { target: { value: "CVE-2 RHSA-2" } });
    await waitFor(() => expect(screen.getByText("alice")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Create watch" }));
    await waitFor(() => expect(window.location.hash).toBe("#/watches/w9"));
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ name: "wave 12", identifiers: "CVE-2 RHSA-2", created_by: "alice" });
  });

  it("says when the node does not serve watches, and when there are none", async () => {
    mockFetch({ "GET /api/governance/watches": [503, { detail: "older build" }] });
    const a = renderWithQuery(<Watches />);
    expect(await screen.findByText("older build")).toBeInTheDocument();
    a.unmount();
    mockFetch({ "GET /api/governance/watches": [200, []], "POST /api/governance/watches": [400, { detail: "name is required" }] });
    renderWithQuery(<Watches />);
    expect(await screen.findByText("No watch yet")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "x" } });
    fireEvent.change(screen.getByLabelText("Identifiers"), { target: { value: "y" } });
    fireEvent.click(screen.getByRole("button", { name: "Create watch" }));
    expect(await screen.findByText(/name is required/)).toBeInTheDocument();
  });

  it("shows one watch, filters by state, adds ids, exports and deletes", async () => {
    const calls = mockFetch({
      "GET /api/governance/watches/w1/status": [200, status],
      "POST /api/governance/watches/w1/identifiers": [200, { added: 1, rejected: ["junk"] }],
      "DELETE /api/governance/watches/w1": [204],
    });
    const url = vi.fn(() => "blob:x");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: url, revokeObjectURL: vi.fn() }));
    renderWithQuery(<WatchView id="w1" />);
    expect(await screen.findByText("wave 11")).toBeInTheDocument();
    expect(screen.getByText(/RHSA-1/)).toBeInTheDocument();
    expect(screen.getByText(/An advisory resolves/)).toBeInTheDocument();
    expect(screen.getByText("project-a 1.0")).toBeInTheDocument();
    expect(screen.getByText("j2")).toBeInTheDocument();
    expect(screen.getByText("none filed")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("radio", { name: "fixed 1" }));
    const table = screen.getAllByRole("table")[0] as HTMLElement;
    expect(within(table).getAllByRole("row")).toHaveLength(2);
    fireEvent.click(screen.getByRole("radio", { name: "accepted 0" }));
    expect(screen.getByText("Nothing in this state")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Export CSV" }));
    expect(url).toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("More identifiers"), { target: { value: "CVE-3 junk" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    expect(await screen.findByText("1 identifier(s) added, not understood: junk")).toBeInTheDocument();
    vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValueOnce(true);
    fireEvent.click(screen.getByRole("button", { name: "Delete watch" }));
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Delete watch" }));
    await waitFor(() => expect(window.location.hash).toBe("#/watches"));
  });

  it("says when a watch is gone, and writes CSV with quotes escaped", async () => {
    mockFetch({ "GET /api/governance/watches/w2/status": [404] });
    renderWithQuery(<WatchView id="w2" />);
    expect(await screen.findByText("No such watch")).toBeInTheDocument();
    expect(watchCsv([{ cve: 'C"1', state: "fixed", packages: ["a", "b"], fixes: [] }]).split("\n")[1]).toBe('"","","","","C""1","fixed","","a b","","","",""');
  });
});
