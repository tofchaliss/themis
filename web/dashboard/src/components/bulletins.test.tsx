import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { canEditBulletins } from "./bulletins";
import { PSIRTCard } from "./psirt-card";
import { mockFetch, renderWithQuery, type Routes } from "@/test/helpers";

const ALERTS = "GET /api/knowledge/psirt/alerts?days=7&min_severity=high";
const LIST = "GET /api/knowledge/psirt/bulletins";

const vuln = {
  id: "b1",
  bulletin_id: "BUL-0001",
  title: "Heap overflow in the parser",
  bulletin_url: "https://example.com/b/1",
  alert_url: "https://example.com/a/1",
  note: "patched in 2.1",
  cve: "CVE-2026-1001",
  report_date: "2026-11-20",
  type: "Vulnerability",
  created_at: "2026-11-20T09:00:00Z",
  created_by: "key:k1",
  updated_at: "2026-11-21T09:00:00Z",
  updated_by: "key:k1",
};
const risk = { ...vuln, id: "b2", bulletin_id: "BUL-0002", title: "Signing key exposed", bulletin_url: "", alert_url: "", note: "", cve: "", type: "Risk" };

const withBulletin = {
  cve: "CVE-2026-1001",
  published: "2026-11-23T10:00:00Z",
  modified: "2026-11-23T18:00:00Z",
  original_score: 9.8,
  original_severity: "critical",
  score_source: "nvd",
  issue_type: "Memory safety",
  matches: [{ product_id: "p1", product_name: "example-product", component: "libexample", matched_on: "libexample" }],
  carded: false,
  bulletin: { id: "b1", bulletin_id: "BUL-0001", title: "Heap overflow in the parser", bulletin_url: "https://example.com/b/1" },
};
const without = { ...withBulletin, cve: "CVE-2026-1003", issue_type: undefined, bulletin: undefined };
const unlinked = { ...withBulletin, cve: "CVE-2026-1004", bulletin: { id: "b9", bulletin_id: "BUL-0009", title: "No page yet", bulletin_url: "" } };

const page = (alerts: unknown[]) => ({ alerts, estate_unavailable: false, lookups_skipped: 0, older_not_read: 0, issue_type_table: "1" });
const admin = { user: "alice", scopes: ["admin"], can_write: true };
const reader = { user: "bob", scopes: ["read"], can_write: false };

function open(routes: Routes) {
  const calls = mockFetch(routes);
  renderWithQuery(<PSIRTCard feeds={{ feeds: [] }} feedsError={false} />);
  return calls;
}

describe("canEditBulletins", () => {
  it("needs the admin scope when scopes are stated, and write access when auth is off", () => {
    expect(canEditBulletins(undefined)).toBe(false);
    expect(canEditBulletins(admin)).toBe(true);
    expect(canEditBulletins(reader)).toBe(false);
    expect(canEditBulletins({ user: "p", scopes: ["product:p1"], can_write: true })).toBe(false);
    expect(canEditBulletins({ user: "dev", can_write: true })).toBe(true);
  });
});

describe("the bulletin register", () => {
  it("lists bulletins newest first with links, the derived type and the live CVE facts", async () => {
    open({ [ALERTS]: [200, page([withBulletin])], [LIST]: [200, [vuln, risk]], "GET /whoami": [200, reader] });
    fireEvent.click(await screen.findByRole("button", { name: "Bulletins (2)" }));
    const row = screen.getByText("BUL-0001").closest("tr") as HTMLElement;
    expect(within(row).getByRole("link", { name: "Bulletin" })).toHaveAttribute("href", "https://example.com/b/1");
    expect(within(row).getByRole("link", { name: "TSN / Alert" })).toHaveAttribute("href", "https://example.com/a/1");
    expect(within(row).getByRole("link", { name: "CVE record" })).toHaveAttribute("href", "https://nvd.nist.gov/vuln/detail/CVE-2026-1001");
    expect(within(row).getByText("patched in 2.1")).toBeInTheDocument();
    expect(within(row).getByText("Memory safety")).toBeInTheDocument();
    expect(within(row).getByText(/^CVE updated /)).toBeInTheDocument();
    expect(within(row).getByText("Vulnerability")).toBeInTheDocument();
    const riskRow = screen.getByText("BUL-0002").closest("tr") as HTMLElement;
    expect(within(riskRow).getByText("Risk")).toBeInTheDocument();
    expect(within(riskRow).getByText("no link")).toBeInTheDocument();
    expect(within(riskRow).getByText("not stated")).toBeInTheDocument();
    // A reader sees no way to change the register.
    expect(screen.queryByRole("button", { name: "Add a bulletin" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Edit bulletin/ })).not.toBeInTheDocument();
  });

  it("shows the bulletin on the alert row, and Add only to an admin", async () => {
    open({ [ALERTS]: [200, page([withBulletin, without, unlinked])], [LIST]: [200, [vuln]], "GET /whoami": [200, reader] });
    expect(await screen.findByRole("link", { name: "BUL-0001" })).toHaveAttribute("href", "https://example.com/b/1");
    expect(screen.getByText("BUL-0009").tagName).toBe("SPAN");
    expect(within(screen.getByText("CVE-2026-1003").closest("tr") as HTMLElement).getByText("none")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Add a bulletin for/ })).not.toBeInTheDocument();
  });

  it("lets an admin add a bulletin for a CVE from the alert row", async () => {
    const calls = open({
      [ALERTS]: [200, page([without])],
      [LIST]: [200, []],
      "GET /whoami": [200, admin],
      "POST /api/knowledge/psirt/bulletins": [201, vuln],
    });
    fireEvent.click(await screen.findByRole("button", { name: "Add a bulletin for CVE-2026-1003" }));
    expect(screen.getByLabelText(/^CVE/)).toHaveValue("CVE-2026-1003");
    fireEvent.change(screen.getByLabelText("Bulletin ID"), { target: { value: "BUL-0003" } });
    fireEvent.change(screen.getByLabelText("Title"), { target: { value: "A flaw" } });
    fireEvent.change(screen.getByLabelText("Bulletin link"), { target: { value: "https://example.com/b/3" } });
    fireEvent.change(screen.getByLabelText("Note"), { target: { value: "watch" } });
    fireEvent.click(screen.getByRole("button", { name: "Add bulletin" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Add bulletin" })).not.toBeInTheDocument());
    const sent = calls.find((c) => c.method === "POST");
    expect(sent?.body).toEqual({ bulletin_id: "BUL-0003", title: "A flaw", cve: "CVE-2026-1003", bulletin_url: "https://example.com/b/3", alert_url: "", note: "watch" });
  });

  it("lets an admin edit and remove, and names a refusal", async () => {
    const calls = open({
      [ALERTS]: [200, page([])],
      [LIST]: [200, [vuln]],
      "GET /whoami": [200, admin],
      "PUT /api/knowledge/psirt/bulletins/b1": [409, { title: "bulletin conflict", detail: "another bulletin already has this bulletin ID or CVE" }],
      "DELETE /api/knowledge/psirt/bulletins/b1": [204],
    });
    fireEvent.click(await screen.findByRole("button", { name: "Bulletins (1)" }));
    fireEvent.click(screen.getByRole("button", { name: "Edit bulletin BUL-0001" }));
    expect(screen.getByLabelText("Title")).toHaveValue("Heap overflow in the parser");
    fireEvent.change(screen.getByLabelText(/^Report date/), { target: { value: "2026-11-22" } });
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("another bulletin already has this bulletin ID or CVE");
    expect((calls.find((c) => c.method === "PUT")?.body as { report_date: string }).report_date).toBe("2026-11-22");

    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    fireEvent.click(screen.getByRole("button", { name: "Yes, remove it" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Save" })).not.toBeInTheDocument());
    expect(calls.some((c) => c.method === "DELETE" && c.url === "/api/knowledge/psirt/bulletins/b1")).toBe(true);

    // Add a bulletin opens an empty form; Cancel closes it without a call.
    fireEvent.click(screen.getByRole("button", { name: "Add a bulletin" }));
    expect(screen.getByLabelText("Bulletin ID")).toHaveValue("");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByLabelText("Bulletin ID")).not.toBeInTheDocument();
  });

  it("says so when the register is empty", async () => {
    open({ [ALERTS]: [200, page([])], [LIST]: [200, []], "GET /whoami": [200, admin] });
    fireEvent.click(await screen.findByRole("button", { name: "Bulletins (0)" }));
    expect(screen.getByText("No bulletin yet")).toBeInTheDocument();
    expect(screen.getByText("Add the first one with Add a bulletin.")).toBeInTheDocument();
  });

  it("names a node without the register and offers no Add there", async () => {
    open({ [ALERTS]: [200, page([without])], "GET /whoami": [200, admin] });
    fireEvent.click(await screen.findByRole("button", { name: "Bulletins" }));
    expect(await screen.findByText("The bulletin register is not available")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add a bulletin" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /^All world/ }));
    expect(screen.queryByRole("button", { name: /^Add a bulletin for/ })).not.toBeInTheDocument();
  });

  it("names a failing register", async () => {
    open({ [ALERTS]: [200, page([])], [LIST]: [500, { detail: "db down" }], "GET /whoami": [200, reader] });
    fireEvent.click(await screen.findByRole("button", { name: "Bulletins" }));
    expect(await screen.findByText(/db down/)).toBeInTheDocument();
  });

  it("tells a reader who adds bulletins", async () => {
    open({ [ALERTS]: [200, page([])], [LIST]: [200, []], "GET /whoami": [200, reader] });
    fireEvent.click(await screen.findByRole("button", { name: "Bulletins (0)" }));
    expect(screen.getByText("An admin adds bulletins here.")).toBeInTheDocument();
  });
});
