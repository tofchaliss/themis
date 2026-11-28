import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { RebuildRecommendationCard, answerText } from "./rebuild-recommendation";
import { mockFetch, renderWithQuery, type Reply } from "@/test/helpers";

const at = "2026-11-28T12:00:00Z";
const target = (cve: string, n: number) => ({ finding_id: `f${n}`, cve, purl: `pkg:rpm/redhat/pkg${n}@1` });
const decision = { decision_id: "dec-1", outcome: "recommend", decided_at: at, recommend_reason: "mode_ask", targeted: [target("CVE-2026-1", 1), target("CVE-2026-1", 2), target("CVE-2026-2", 3)] };
const standing = { decision, state: "standing", state_at: at, expires_at: "2026-12-05T12:00:00Z", can_approve: true };
const read = "GET /api/governance/releases/r1/rebuild-recommendation";
const post = "POST /api/governance/rebuild-recommendations/dec-1/approve";
const card = (canWrite = true) => <RebuildRecommendationCard releaseId="r1" actor="alice" canWrite={canWrite} />;

afterEach(() => vi.restoreAllMocks());

describe("answerText", () => {
  it("says in plain words what each answer means", () => {
    const a = { decision_id: "d", release_id: "r", state: "standing" } as const;
    expect(answerText({ ...a, result: "approved" })).toMatch(/Rebuild requested/);
    expect(answerText({ ...a, result: "not_standing", standing_decision_id: "d2" })).toMatch(/newer recommendation/);
    expect(answerText({ ...a, result: "not_standing" })).toMatch(/can no longer be approved/);
    expect(answerText({ ...a, result: "expired" })).toMatch(/expired/);
    expect(answerText({ ...a, result: "withdrawn", effective_mode: "auto" })).toMatch(/now "auto"/);
    expect(answerText({ ...a, result: "withdrawn" })).toMatch(/now "unknown"/);
    expect(answerText({ ...a, result: "no_build_profile" })).toMatch(/no build profile/);
  });
});

describe("RebuildRecommendationCard", () => {
  it("shows nothing for a release with no recommendation", async () => {
    const calls = mockFetch({});
    const { container } = renderWithQuery(card());
    await waitFor(() => expect(calls.length).toBe(1));
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the standing recommendation and starts the rebuild after a yes, as the signed-in user", async () => {
    let stored: Reply = [200, standing];
    const calls = mockFetch({
      [read]: () => stored,
      [post]: () => {
        stored = [200, { ...standing, state: "approved", can_approve: false, approval: { actor: "alice", key_name: "deciders", approved_at: at }, cycle_closed: false }];
        return [200, { result: "approved", decision_id: "dec-1", release_id: "r1", state: "approved" }];
      },
    });
    renderWithQuery(card());
    expect(await screen.findByText(/3 component\(s\) with a known fix, 2 CVE\(s\): CVE-2026-1, CVE-2026-2\./)).toBeInTheDocument();
    expect(screen.getByText("waiting for a person")).toBeInTheDocument();
    expect(screen.getByText(/and then expires/)).toBeInTheDocument();
    const confirm = vi.spyOn(window, "confirm").mockReturnValueOnce(false).mockReturnValue(true);
    fireEvent.click(screen.getByRole("button", { name: "Start rebuild" }));
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Start rebuild" }));
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Rebuild requested"));
    expect(confirm).toHaveBeenCalledTimes(2);
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ actor_id: "alice" });
    expect(await screen.findByText(/Started by alice/)).toBeInTheDocument();
    expect(screen.getByText(/\(key deciders\)\. The rebuild cycle is open\./)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start rebuild" })).toBeNull();
  });

  it("shows a refusal with its reason and reads the recommendation again", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    mockFetch({ [read]: [200, standing], [post]: [409, { result: "withdrawn", decision_id: "dec-1", release_id: "r1", state: "withdrawn", effective_mode: "off" }] });
    renderWithQuery(card());
    fireEvent.click(await screen.findByRole("button", { name: "Start rebuild" }));
    expect(await screen.findByText(/Not started: the rebuild mode of this release is now "off"/)).toBeInTheDocument();
  });

  it("shows the node's own words when the call fails", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    let reply: Reply = [503, { detail: "the rebuild mode of this release could not be read" }];
    mockFetch({ [read]: [200, standing], [post]: () => reply });
    renderWithQuery(card());
    fireEvent.click(await screen.findByRole("button", { name: "Start rebuild" }));
    expect(await screen.findByText("Not started: the rebuild mode of this release could not be read")).toBeInTheDocument();
    reply = [500, { title: "rebuild approval failed" }];
    fireEvent.click(screen.getByRole("button", { name: "Start rebuild" }));
    expect(await screen.findByText("Not started: rebuild approval failed")).toBeInTheDocument();
    reply = [500];
    fireEvent.click(screen.getByRole("button", { name: "Start rebuild" }));
    expect(await screen.findByText("Not started: 500")).toBeInTheDocument();
  });

  it("offers no start without a build profile, and none to a read-only key", async () => {
    const many = Array.from({ length: 10 }, (_, i) => target(`CVE-2026-${i}`, i));
    mockFetch({ [read]: [200, { ...standing, can_approve: false, decision: { ...decision, recommend_reason: "no_build_profile", supersedes: "dec-0", targeted: many } }] });
    const first = renderWithQuery(card());
    expect(await screen.findByText(/Add a build profile on the project/)).toBeInTheDocument();
    expect(screen.getByText(/It replaced an earlier recommendation/)).toBeInTheDocument();
    expect(screen.getByText(/and 2 more/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Start rebuild" })).toBeNull();
    first.unmount();
    mockFetch({ [read]: [200, standing] });
    renderWithQuery(card(false));
    expect(await screen.findByRole("button", { name: "Start rebuild" })).toBeDisabled();
  });

  it("shows a closed cycle, and a read that failed", async () => {
    mockFetch({ [read]: [200, { ...standing, state: "approved", can_approve: false, approval: { actor: "pat", key_name: "", approved_at: at }, cycle_closed: true }] });
    const first = renderWithQuery(card());
    expect(await screen.findByText(/Started by pat.*The rebuild cycle has closed\./)).toBeInTheDocument();
    first.unmount();
    mockFetch({ [read]: [500, { detail: "down" }] });
    renderWithQuery(card());
    expect(await screen.findByText(/down/)).toBeInTheDocument();
  });
});
