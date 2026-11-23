import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { Sbom } from "./sbom";
import { mockFetch, renderWithQuery, type Reply } from "@/test/helpers";

const base: Record<string, Reply> = {
  "GET /api/registry/products": [200, [{ id: "p1", name: "product-a" }]],
  "GET /api/registry/products/p1/projects": [200, [{ id: "j1", name: "project-a" }]],
  "GET /api/registry/projects/j1/releases": [200, [{ id: "r1", version: "1.4.0" }]],
  "GET /api/evidence/evidence?release=r1": [
    200,
    [
      { id: "e1", kind: "sbom", fingerprint: "abcdef0123456789abcdef", filed_at: new Date(Date.now() - 120_000).toISOString() },
      { id: "e2", kind: "scanner-report", provenance_source: "trivy", fingerprint: "ff", filed_at: new Date(Date.now() - 7_200_000).toISOString() },
      { id: "e3", kind: "vex", fingerprint: "aa", filed_at: new Date(Date.now() - 3 * 86_400_000).toISOString() },
    ],
  ],
};

const file = (name: string, text = "{}") => new File([text], name, { type: "application/json" });
const pick = async () => {
  await screen.findByRole("option", { name: "product-a" });
  fireEvent.change(screen.getByLabelText("Product"), { target: { value: "p1" } });
  await screen.findByRole("option", { name: "project-a" });
  fireEvent.change(screen.getByLabelText("Project"), { target: { value: "j1" } });
  await screen.findByRole("option", { name: "v1.4.0" });
  fireEvent.change(screen.getByLabelText("Release"), { target: { value: "r1" } });
};

afterEach(() => vi.useRealTimers());

describe("SBOM manager", () => {
  it("lists a release's evidence once it is picked", async () => {
    mockFetch(base);
    renderWithQuery(<Sbom />);
    expect(await screen.findByText("Pick a release")).toBeInTheDocument();
    await pick();
    expect(await screen.findByText("e2")).toBeInTheDocument();
    expect(screen.getByText("trivy")).toBeInTheDocument();
    expect(screen.getByText("2 min ago")).toBeInTheDocument();
    expect(screen.getByText("2 h ago")).toBeInTheDocument();
    expect(screen.getByText("3 d ago")).toBeInTheDocument();
    expect(screen.getByText("product-a / project-a / v1.4.0")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /open this release/i })).toHaveAttribute("href", "#/release/r1");
  });

  it("uploads through the intake door and shows the receipt as a pair of counts", async () => {
    const calls = mockFetch({
      ...base,
      "POST /api/evidence/intake?release_id=r1&observed_at=2026-11-20T00%3A00%3A00Z": [
        201,
        { intake_id: "i1", status: "filed", detected_kind: "scanner-report", detected_format: "nessus-csv", findings_total: 12, findings_skipped: 2, evidence_id: "ev-1", created: true, status_url: "" },
      ],
    });
    renderWithQuery(<Sbom />);
    await pick();
    const upload = screen.getByRole("button", { name: "Upload" });
    expect(upload).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Document"), { target: { files: [file("scan.csv", "a,b")] } });
    expect(screen.getByText(/sent as text\/csv/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Scan date/), { target: { value: "2026-11-20" } });
    fireEvent.click(upload);
    expect(await screen.findByRole("status")).toHaveTextContent("12 findings considered, 2 skipped");
    expect(calls.find((c) => c.method === "POST")?.url).toContain("observed_at=");
  });

  it("names a refusal by its reason and says what it means", async () => {
    mockFetch({
      ...base,
      "POST /api/evidence/intake?release_id=r1": [422, { title: "refused", status: 422, reason: "no_inventory_for_release", detail: "file the SBOM first" }],
    });
    renderWithQuery(<Sbom />);
    await pick();
    fireEvent.change(screen.getByLabelText("Document"), { target: { files: [file("report.json")] } });
    fireEvent.click(screen.getByRole("button", { name: "Upload" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("no_inventory_for_release");
    expect(alert).toHaveTextContent("upload the SBOM first");
    expect(alert).toHaveTextContent("file the SBOM first");
  });

  it("registers a new product, project and release on upload, and refuses a name that exists", async () => {
    const calls = mockFetch({
      ...base,
      "POST /api/registry/products": [201, { id: "p2" }],
      "POST /api/registry/projects": [201, { id: "j2" }],
      "POST /api/registry/releases": [201, { id: "r2" }],
      "POST /api/evidence/evidence": [201, { id: "vex-1", created: true }],
    });
    renderWithQuery(<Sbom />);
    await screen.findByRole("option", { name: "product-a" });
    fireEvent.change(screen.getByLabelText("Product"), { target: { value: "__new__" } });
    expect(screen.getByText("A new release starts empty")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Kind"), { target: { value: "vex" } });
    fireEvent.change(screen.getByLabelText("Document"), { target: { files: [file("vex.json", '{"a":1}')] } });
    const upload = screen.getByRole("button", { name: "Upload" });
    fireEvent.change(screen.getByLabelText("New product name"), { target: { value: "product-a" } });
    fireEvent.change(screen.getByLabelText("New project name"), { target: { value: "project-b" } });
    fireEvent.change(screen.getByLabelText("New release version"), { target: { value: "2.0.0" } });
    fireEvent.click(upload);
    expect(await screen.findByRole("alert")).toHaveTextContent("already exists");

    fireEvent.change(screen.getByLabelText("New product name"), { target: { value: "product-b" } });
    fireEvent.click(upload);
    expect(await screen.findByRole("status")).toHaveTextContent("VEX filed");
    expect(calls.find((c) => c.url === "/api/registry/projects")?.body).toEqual({ product_id: "p2", name: "project-b" });
    expect(calls.find((c) => c.url === "/api/registry/releases")?.body).toEqual({ project_id: "j2", version: "2.0.0" });
    expect(calls.find((c) => c.url === "/api/evidence/evidence")?.body).toEqual({ kind: "vex", subject_release_id: "r2", document: '{"a":1}' });
  });

  it("follows a receipt that is still working, and says when intake is busy", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mockFetch({
      ...base,
      "POST /api/evidence/intake?release_id=r1": [202, { intake_id: "i9", status: "accepted", retry_after_seconds: 1, status_url: "" }],
      "GET /api/evidence/intake/i9": [200, { intake_id: "i9", status: "filed", detected_kind: "sbom", detected_format: "cyclonedx", components: 40, components_unmanaged: 2, components_skipped: 1, created: false, status_url: "" }],
    });
    const first = renderWithQuery(<Sbom />);
    await pick();
    fireEvent.change(screen.getByLabelText("Document"), { target: { files: [file("big.json")] } });
    fireEvent.click(screen.getByRole("button", { name: "Upload" }));
    expect(await screen.findByText("Accepted, still working")).toBeInTheDocument();
    await vi.advanceTimersByTimeAsync(1500);
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("40 components (2 hand-installed), 1 packages skipped"));
    expect(screen.getByRole("status")).toHaveTextContent("Already filed");
    first.unmount();

    mockFetch({ ...base, "POST /api/evidence/intake?release_id=r1": [503, {}] });
    renderWithQuery(<Sbom />);
    await pick();
    fireEvent.change(screen.getByLabelText("Document"), { target: { files: [file("x.json")] } });
    fireEvent.click(screen.getByRole("button", { name: "Upload" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Intake is busy");
  });

  it("names a node that did not answer", async () => {
    mockFetch({ "GET /api/registry/products": [502] });
    renderWithQuery(<Sbom />);
    expect(await screen.findByText(/registry node did not answer/i)).toBeInTheDocument();
  });
});
