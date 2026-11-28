import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { BuildProfileEditor, parseProfile } from "./build-profile";
import { mockFetch, renderWithQuery, type Reply } from "@/test/helpers";

const at = "2026-11-28T12:00:00Z";
const saved = { level: "project", entity_id: "j1", revision: 1, removed: false, actor: "operator", recorded_at: at, sha256: "0123456789abcdef", profile: { job: "team/build-image" } };
const removed = { level: "project", entity_id: "j1", revision: 2, removed: true, actor: "operator", recorded_at: at };
const base = "/api/registry/projects/j1/build-profile";
const editor = (canWrite = true) => <BuildProfileEditor kind="project" id="j1" name="project-a" actor="alice" canWrite={canWrite} />;

afterEach(() => vi.restoreAllMocks());

describe("parseProfile", () => {
  it("takes one JSON object and nothing else", () => {
    expect(parseProfile('{"a":1}')).toEqual({ profile: { a: 1 } });
    for (const bad of ["nope", "[1]", "null", '"x"']) expect(parseProfile(bad)).toHaveProperty("error");
  });
});

describe("BuildProfileEditor", () => {
  it("shows the stored profile and its history, and states the no-secrets rule", async () => {
    mockFetch({ [`GET ${base}`]: [200, { current: saved, history: [saved] }] });
    renderWithQuery(editor());
    expect(await screen.findByText(/Stored here: revision 1, saved by operator/)).toBeInTheDocument();
    expect(screen.getByLabelText("Build profile")).toHaveValue(JSON.stringify(saved.profile, null, 2));
    expect(screen.getByText("No secrets here.")).toBeInTheDocument();
    expect(screen.getByText("0123456789ab")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove profile" })).toBeEnabled();
  });

  it("refuses text that is not one JSON object without calling the Registry", async () => {
    const calls = mockFetch({ [`GET ${base}`]: [200, { history: [] }] });
    renderWithQuery(editor());
    const input = await screen.findByLabelText("Build profile");
    expect(screen.getByText("No profile is stored on this project.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove profile" })).toBeNull();
    fireEvent.change(input, { target: { value: "[1]" } });
    fireEvent.click(screen.getByRole("button", { name: "Save profile" }));
    expect(await screen.findByText("not saved: the profile must be one JSON object, in { }")).toBeInTheDocument();
    fireEvent.change(input, { target: { value: "{" } });
    fireEvent.click(screen.getByRole("button", { name: "Save profile" }));
    expect(await screen.findByText("not saved: this is not valid JSON")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
  });

  it("saves with the signed-in user as actor", async () => {
    let stored: Reply = [200, { history: [] }];
    const calls = mockFetch({
      [`GET ${base}`]: () => stored,
      [`PUT ${base}`]: () => {
        stored = [200, { current: saved, history: [saved] }];
        return [200, saved];
      },
    });
    renderWithQuery(editor());
    fireEvent.change(await screen.findByLabelText("Build profile"), { target: { value: '{"job":"team/build-image"}' } });
    fireEvent.click(screen.getByRole("button", { name: "Save profile" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("saved"));
    expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ profile: { job: "team/build-image" }, actor: "alice" });
    expect(await screen.findByText(/Stored here: revision 1/)).toBeInTheDocument();
  });

  it("shows the Registry's refusal as it came", async () => {
    mockFetch({ [`GET ${base}`]: [200, { history: [] }], [`PUT ${base}`]: [400, { detail: 'the key "api_token" is named like a secret' }] });
    renderWithQuery(editor());
    fireEvent.change(await screen.findByLabelText("Build profile"), { target: { value: '{"api_token":"x"}' } });
    fireEvent.click(screen.getByRole("button", { name: "Save profile" }));
    expect(await screen.findByText('not saved: the key "api_token" is named like a secret')).toBeInTheDocument();
  });

  it("removes only after a yes, with the actor in the query", async () => {
    let stored: Reply = [200, { current: saved, history: [saved] }];
    const calls = mockFetch({
      [`GET ${base}`]: () => stored,
      [`DELETE ${base}?actor=alice`]: () => {
        stored = [200, { history: [removed, saved] }];
        return [200, removed];
      },
    });
    const ask = vi.spyOn(window, "confirm").mockReturnValue(false);
    renderWithQuery(editor());
    fireEvent.click(await screen.findByRole("button", { name: "Remove profile" }));
    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
    ask.mockReturnValue(true);
    fireEvent.click(screen.getByRole("button", { name: "Remove profile" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("removed"));
    expect(await screen.findByText("No profile is stored on this project.")).toBeInTheDocument();
    expect(screen.getAllByRole("row")).toHaveLength(3);
  });

  it("says when a removal is refused", async () => {
    mockFetch({ [`GET ${base}`]: [200, { current: saved, history: [saved] }], [`DELETE ${base}?actor=alice`]: [403, { detail: "not your product" }] });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderWithQuery(editor());
    fireEvent.click(await screen.findByRole("button", { name: "Remove profile" }));
    expect(await screen.findByText("not removed: not your product")).toBeInTheDocument();
  });

  it("disables writing for a read-only key", async () => {
    mockFetch({ [`GET ${base}`]: [200, { current: saved, history: [saved] }] });
    renderWithQuery(editor(false));
    expect(await screen.findByRole("button", { name: "Save profile" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Remove profile" })).toBeDisabled();
  });

  it("says which profile is in force for a release", async () => {
    const rel = "/api/registry/releases/r1/build-profile";
    mockFetch({
      [`GET ${rel}`]: [200, { history: [] }],
      [`GET ${rel}/resolved`]: [200, { release_id: "r1", project_id: "j1", found: true, scope: "project", record: saved }],
    });
    renderWithQuery(<BuildProfileEditor kind="release" id="r1" name="v1.4.0" actor="alice" canWrite />);
    expect(await screen.findByText(/In force for this release: the project's profile, revision 1\./)).toBeInTheDocument();
  });

  it("says when no profile is in force for a release", async () => {
    const rel = "/api/registry/releases/r1/build-profile";
    mockFetch({ [`GET ${rel}`]: [200, { history: [] }], [`GET ${rel}/resolved`]: [200, { release_id: "r1", project_id: "j1", found: false }] });
    renderWithQuery(<BuildProfileEditor kind="release" id="r1" name="v1.4.0" actor="alice" canWrite />);
    expect(await screen.findByText(/a rebuild can only be recommended/)).toBeInTheDocument();
  });

  it("explains an older Registry and a failed read", async () => {
    mockFetch({});
    const { unmount } = renderWithQuery(editor());
    expect(await screen.findByText(/This Registry has no build profiles yet/)).toBeInTheDocument();
    unmount();
    mockFetch({ [`GET ${base}`]: [500, { detail: "boom" }] });
    renderWithQuery(editor());
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});
