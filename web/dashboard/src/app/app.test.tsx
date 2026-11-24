import { describe, expect, it } from "vitest";
import { act, fireEvent, screen, waitFor } from "@testing-library/react";
import { App } from "./app";
import { mockFetch, renderWithQuery } from "@/test/helpers";

const base = {
  "GET /api/registry/products": [200, []] as [number, unknown],
  "GET /api/knowledge/feeds": [200, { feeds: [], degraded_feeds: [] }] as [number, unknown],
};

describe("App shell", () => {
  it("shows the signed-in user, sign out and the admin chrome for an admin", async () => {
    mockFetch({
      ...base,
      "GET /whoami": [200, { user: "jane.doe", scopes: ["admin"], can_write: true }],
      "GET /api/dashboard/admin/status": [200, { auth_enabled: true, is_default_password: true }],
    });
    renderWithQuery(<App />);
    expect(await screen.findByText("jane.doe")).toBeInTheDocument();
    expect(screen.getByText("JD")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign out/i })).toBeInTheDocument();
    expect(await screen.findByText(/default password in use/i)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /admin/i })).toHaveAttribute("href", "#/admin");
    expect(screen.getByRole("link", { name: /^old gui$/i })).toHaveAttribute("href", "/old/");
  });

  it("hides sign out and admin when auth is on and the user is read-only", async () => {
    mockFetch({
      ...base,
      "GET /whoami": [200, { user: "viewer", scopes: ["read"], can_write: false }],
      "GET /api/dashboard/admin/status": [403],
    });
    renderWithQuery(<App />);
    expect(await screen.findByText("(read only)")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /admin/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/default password/i)).not.toBeInTheDocument();
  });

  it("shows Admin to everyone when auth is off, with no sign out", async () => {
    mockFetch({
      ...base,
      "GET /whoami": [200, { user: "operator", can_write: true }],
      "GET /api/dashboard/admin/status": [200, { auth_enabled: false }],
    });
    renderWithQuery(<App />);
    expect(await screen.findByRole("link", { name: /admin/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /sign out/i })).not.toBeInTheDocument();
  });

  it("switches and remembers the shade", async () => {
    mockFetch({ ...base, "GET /whoami": [200, { user: "operator", can_write: true }], "GET /api/dashboard/admin/status": [200, { auth_enabled: false }] });
    renderWithQuery(<App />);
    fireEvent.click(screen.getByRole("radio", { name: /ops night/i }));
    await waitFor(() => expect(document.documentElement.dataset.theme).toBe("ops-night"));
    expect(localStorage.getItem("themis-theme")).toBe("ops-night");
    expect(screen.getByRole("radio", { name: /ops night/i })).toHaveAttribute("aria-checked", "true");
  });

  it("marks screens that still open in the classic GUI", () => {
    mockFetch({ ...base, "GET /whoami": [200, { user: "operator", can_write: true }] });
    renderWithQuery(<App />);
    expect(screen.getByRole("link", { name: "Estate" })).toHaveAttribute("href", "#/estate");
    expect(screen.getByRole("link", { name: "SBOM manager" })).toHaveAttribute("href", "#/sbom");
    expect(screen.getByRole("link", { name: "Compare" })).toHaveAttribute("href", "#/compare");
    expect(screen.getByRole("link", { name: "Reports" })).toHaveAttribute("href", "#/reports");
    expect(screen.queryByRole("link", { name: /opens the old gui/i })).toBeNull();
  });

  it("routes by hash and hands unbuilt screens to the classic GUI", async () => {
    mockFetch({ ...base, "GET /whoami": [200, { user: "operator", can_write: true }] });
    renderWithQuery(<App />);
    expect(await screen.findByText("PSIRT early alert")).toBeInTheDocument();
    act(() => {
      window.location.hash = "#/estate";
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    });
    expect(await screen.findByText("Filter by tag")).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toHaveTextContent("Overview/Estate");
    act(() => {
      window.location.hash = "#/sbom";
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    });
    expect(await screen.findByText("Upload evidence")).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Breadcrumb" })).toHaveTextContent("Overview/SBOM manager");
    act(() => {
      window.location.hash = "#/scan/e1?rel=r1&v=1.0";
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    });
    expect(await screen.findByRole("navigation", { name: "Breadcrumb" })).toHaveTextContent("Overview/Estate/Release v1.0/Scan report");
    for (const [hash, crumbs] of [
      ["#/compare", "Overview/Compare releases"],
      ["#/new", "Overview/What's new"],
      ["#/cve/CVE-2026-0001", "Overview/What's new/CVE-2026-0001"],
      ["#/reports", "Overview/Reports"],
      ["#/feeds", "Overview/Feed health"],
      ["#/admin", "Overview/Admin"],
      ["#/watches", "Overview/Watches"],
      ["#/watches/w1", "Overview/Watches/Watch"],
    ]) {
      act(() => {
        window.location.hash = hash as string;
        window.dispatchEvent(new HashChangeEvent("hashchange"));
      });
      expect(await screen.findByRole("navigation", { name: "Breadcrumb" })).toHaveTextContent(crumbs as string);
    }
    act(() => {
      window.location.hash = "#/nowhere";
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    });
    expect(await screen.findByText(/opening this screen in the old gui/i)).toBeInTheDocument();
  });
});
