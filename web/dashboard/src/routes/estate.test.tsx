import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { Estate } from "./estate";
import { mockFetch, renderWithQuery } from "@/test/helpers";

const estate = {
  "GET /whoami": [200, { user: "operator", can_write: true }] as [number, unknown],
  "GET /api/registry/products": [200, [{ id: "p1-aaaaaaaa", name: "example-product", tags: ["team:sec"] }]] as [number, unknown],
  "GET /api/registry/products/p1-aaaaaaaa/projects": [200, [{ id: "j1-bbbbbbbb", name: "project-a" }]] as [number, unknown],
  "GET /api/registry/projects/j1-bbbbbbbb/releases": [200, [{ id: "r1-cccccccc", version: "1.4.0", tags: [] }]] as [number, unknown],
  "GET /api/registry/products/p1-aaaaaaaa/tags": [200, { tags: ["team:sec"], effective: ["team:sec"] }] as [number, unknown],
  "GET /api/registry/projects/j1-bbbbbbbb/tags": [200, { tags: [], effective: ["team:sec"] }] as [number, unknown],
  "GET /api/registry/releases/r1-cccccccc/tags": [200, { tags: [], effective: ["team:sec"] }] as [number, unknown],
};

describe("Estate", () => {
  it("walks products → projects → releases and links the posture", async () => {
    mockFetch(estate);
    renderWithQuery(<Estate />);
    fireEvent.click(await screen.findByRole("button", { name: /example-product/ }));
    fireEvent.click(await screen.findByRole("button", { name: /project-a/ }));
    const rel = await screen.findByRole("link", { name: /v1\.4\.0/ });
    expect(rel).toHaveAttribute("href", "#/release/r1-cccccccc?v=1.4.0");
    expect(screen.getByText(/Tags — project project-a/)).toBeInTheDocument();
    expect(await screen.findByText(/team:sec\)/)).toBeInTheDocument();
  });

  it("saves tags through the Registry and shows the answer", async () => {
    const calls = mockFetch({
      ...estate,
      "PUT /api/registry/releases/r1-cccccccc/tags": (b) => [200, { tags: (b as { tags: string[] }).tags, effective: ["env:prod", "team:sec"] }],
    });
    renderWithQuery(<Estate />);
    fireEvent.click(await screen.findByRole("button", { name: /example-product/ }));
    fireEvent.click(await screen.findByRole("button", { name: /project-a/ }));
    fireEvent.click(await screen.findByRole("button", { name: "tags, build profile…" }));
    const input = await screen.findByLabelText("Tags");
    fireEvent.change(input, { target: { value: "env:prod, " } });
    fireEvent.click(screen.getByRole("button", { name: "Save tags" }));
    expect(await screen.findByText("saved")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ tags: ["env:prod"] });
  });

  it("shows the Registry's refusal", async () => {
    mockFetch({ ...estate, "PUT /api/registry/products/p1-aaaaaaaa/tags": [400, { detail: "tag must be lower-case" }] });
    renderWithQuery(<Estate />);
    fireEvent.click(await screen.findByRole("button", { name: /example-product/ }));
    await screen.findByDisplayValue("team:sec");
    fireEvent.click(screen.getByRole("button", { name: "Save tags" }));
    expect(await screen.findByText("not saved: tag must be lower-case")).toBeInTheDocument();
  });

  it("disables saving for a read-only key", async () => {
    mockFetch({ ...estate, "GET /whoami": [200, { user: "viewer", can_write: false, scopes: ["read"] }] });
    renderWithQuery(<Estate />);
    fireEvent.click(await screen.findByRole("button", { name: /example-product/ }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Save tags" })).toBeDisabled());
  });

  it("renames a project for an admin and shows the new name", async () => {
    const calls = mockFetch({
      ...estate,
      "GET /whoami": [200, { user: "operator", can_write: true, scopes: ["admin"] }],
      "PATCH /api/registry/projects/j1-bbbbbbbb": (b) => [200, { id: "j1-bbbbbbbb", product_id: "p1-aaaaaaaa", name: (b as { name: string }).name.trim() }],
    });
    renderWithQuery(<Estate />);
    fireEvent.click(await screen.findByRole("button", { name: /example-product/ }));
    fireEvent.click(await screen.findByRole("button", { name: /project-a/ }));
    const input = await screen.findByLabelText("New project name");
    const btn = screen.getByRole("button", { name: "Rename" });
    expect(btn).toBeDisabled();
    fireEvent.change(input, { target: { value: " project-b " } });
    fireEvent.click(btn);
    expect(await screen.findByText("renamed")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ name: "project-b" });
    expect(await screen.findByText(/Rename project project-b/)).toBeInTheDocument();
  });

  it("shows the Registry's rename refusal", async () => {
    mockFetch({
      ...estate,
      "PATCH /api/registry/projects/j1-bbbbbbbb": [409, { detail: "another project of this product already has this name" }],
    });
    renderWithQuery(<Estate />);
    fireEvent.click(await screen.findByRole("button", { name: /example-product/ }));
    fireEvent.click(await screen.findByRole("button", { name: /project-a/ }));
    fireEvent.change(await screen.findByLabelText("New project name"), { target: { value: "project-b" } });
    fireEvent.click(screen.getByRole("button", { name: "Rename" }));
    expect(await screen.findByText(/not renamed: another project/)).toBeInTheDocument();
  });

  it("disables renaming for a key that is not admin", async () => {
    mockFetch({ ...estate, "GET /whoami": [200, { user: "ci", can_write: true, scopes: ["product:p1-aaaaaaaa"] }] });
    renderWithQuery(<Estate />);
    fireEvent.click(await screen.findByRole("button", { name: /example-product/ }));
    fireEvent.click(await screen.findByRole("button", { name: /project-a/ }));
    fireEvent.change(await screen.findByLabelText("New project name"), { target: { value: "project-b" } });
    await waitFor(() => expect(screen.getByRole("button", { name: "Rename" })).toBeDisabled());
  });

  it("filters by tag and explains an empty result", async () => {
    mockFetch({ ...estate, "GET /api/registry/products?tag=env%3Aprod": [200, []] });
    renderWithQuery(<Estate />);
    await screen.findByRole("button", { name: /example-product/ });
    fireEvent.change(screen.getByLabelText("Filter by tag"), { target: { value: " ENV:prod " } });
    fireEvent.click(screen.getByRole("button", { name: "Apply" }));
    expect(await screen.findByText("No product carries env:prod")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(await screen.findByRole("button", { name: /example-product/ })).toBeInTheDocument();
  });

  it("explains an empty estate and empty children", async () => {
    mockFetch({ ...estate, "GET /api/registry/products": [200, []] });
    renderWithQuery(<Estate />);
    expect(await screen.findByText("No products yet")).toBeInTheDocument();
  });

  it("names a node that did not answer", async () => {
    mockFetch({ ...estate, "GET /api/registry/products": [502] });
    renderWithQuery(<Estate />);
    expect(await screen.findByRole("alert")).toHaveTextContent("registry node did not answer");
  });

  it("explains empty projects and releases", async () => {
    mockFetch({
      ...estate,
      "GET /api/registry/products/p1-aaaaaaaa/projects": [200, [{ id: "j1-bbbbbbbb", name: "project-a" }]],
      "GET /api/registry/projects/j1-bbbbbbbb/releases": [200, []],
    });
    renderWithQuery(<Estate />);
    fireEvent.click(await screen.findByRole("button", { name: /example-product/ }));
    fireEvent.click(await screen.findByRole("button", { name: /project-a/ }));
    expect(await screen.findByText("No releases")).toBeInTheDocument();
  });
});
