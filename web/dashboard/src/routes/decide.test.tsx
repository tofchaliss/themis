import { describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { Decide } from "./decide";
import { mockFetch, renderWithQuery, type Reply } from "@/test/helpers";

const assessment = {
  knowledge: { summary: "A flaw in openssl.", severity: "high", cvss_score: 7.5, kev: true, exploit_public: true, epss: 0.05, fixes: [{ package: "openssl", version: "3.0.7" }, { version: "3.1" }] },
  finding: {
    id: "f1",
    release_id: "r1",
    faultline_id: "fl1",
    cve: "CVE-2026-0001",
    components: [{ name: "openssl", claim_class: "carrier" }],
    current_position: { version: 2, stance: "affected" },
    proposals: [
      { id: "p-ai", stance: "not_affected", proposer_kind: "ai", status: "proposed", evidence_trust: "inferred", rationale: "Not reachable." },
      { id: "p-old", stance: "affected", proposer_kind: "human", status: "accepted" },
    ],
  },
  vendor_statements: [{ package: "openssl", status: "fixed", applicability: "applicable" }],
};

const base: Record<string, Reply> = {
  "GET /whoami": [200, { user: "alice", scopes: ["admin"], can_write: true }],
  "GET /api/governance/findings/f1/assessment": [200, assessment],
  "GET /api/governance/faultlines/fl1/findings": [
    200,
    [
      { finding_id: "f1", release_id: "r1", faultline_id: "fl1", has_position: true, stance: "affected" },
      { finding_id: "f2", release_id: "r2", faultline_id: "fl1", has_position: false },
    ],
  ],
  "GET /api/registry/releases/r1": [200, { id: "r1", project_id: "j1", version: "1.4.0" }],
  "GET /api/registry/releases/r2": [200, { id: "r2", project_id: "j1", version: "1.5.0" }],
  "GET /api/registry/projects/j1": [200, { id: "j1", name: "project-a" }],
};

// The pick list of a copy: one open release, one of another version, one decided, one on a
// different component.
const PICK = "GET /api/governance/findings/f1/scope-targets?scope=product&all=true";
const targets = [
  { finding_id: "t1", project_id: "j1", project_name: "project-a", version: "1.5.0", level: "artifact" },
  { finding_id: "t2", project_id: "j1", project_name: "project-a", version: "1.6.0", level: "component" },
  { finding_id: "t3", project_id: "j2", project_name: "project-b", version: "2.0", level: "artifact", decision: { stance: "affected", decided_by_id: "bob", decided_by_kind: "human" } },
  { finding_id: "t4", project_id: "j2", project_name: "project-b", version: "2.1", level: "vulnerability" },
];

const render = () => renderWithQuery(<Decide findingId="f1" releaseId="r1" version="1.4.0" />);

describe("Decision page", () => {
  it("shows the facts, the waiting proposals and the other releases", async () => {
    mockFetch(base);
    render();
    expect(await screen.findByRole("heading", { name: /Decide CVE-2026-0001/ })).toBeInTheDocument();
    expect(screen.getByText(/Current decision: affected \(version 2\)/)).toBeInTheDocument();
    expect(screen.getByText("A flaw in openssl.")).toBeInTheDocument();
    expect(screen.getByText("high · CVSS 7.5")).toBeInTheDocument();
    expect(screen.getByText("EPSS 5.0%")).toBeInTheDocument();
    expect(screen.getByText("openssl → 3.0.7, 3.1")).toBeInTheDocument();
    // Once in the AI box, once under Proposals waiting.
    expect(screen.getAllByText("Not reachable.")).toHaveLength(2);
    expect(screen.getByText("AI")).toBeInTheDocument();
    // Nothing is asked on opening, and the form is not filled.
    expect(screen.getByRole("button", { name: "Use this in the form" })).toBeInTheDocument();
    expect(screen.getByLabelText(/Rationale/)).toHaveValue("");
    expect(await screen.findByText("project-a v1.5.0")).toBeInTheDocument();
    expect(screen.queryByText("project-a v1.4.0")).toBeNull();
    expect(screen.getByRole("link", { name: /back to the release/i })).toHaveAttribute("href", "#/release/r1?v=1.4.0");
  });

  it("requires a decision, a rationale and, for an accepted risk, an owner", async () => {
    mockFetch(base);
    render();
    const record = await screen.findByRole("button", { name: "Record decision" });
    fireEvent.click(record);
    expect(await screen.findByRole("alert")).toHaveTextContent("Choose a decision.");
    fireEvent.click(screen.getByLabelText(/Accepted risk/));
    fireEvent.click(record);
    expect(screen.getByRole("alert")).toHaveTextContent("Write the rationale");
    fireEvent.change(screen.getByLabelText(/Rationale/), { target: { value: "We carry it." } });
    fireEvent.click(record);
    expect(screen.getByRole("alert")).toHaveTextContent("Name the accountable owner");
  });

  it("records a decision as raise then accept, with review date and acceptance terms", async () => {
    const calls = mockFetch({
      ...base,
      "POST /api/governance/findings/f1/proposals": [201, { proposal_id: "p-new" }],
      "POST /api/governance/findings/f1/proposals/p-new/accept": [204],
    });
    render();
    fireEvent.click(await screen.findByLabelText(/Accepted risk/));
    fireEvent.change(screen.getByLabelText(/Rationale/), { target: { value: "  We carry it.  " } });
    fireEvent.change(screen.getByLabelText(/Review by/), { target: { value: "2027-01-31" } });
    fireEvent.change(screen.getByLabelText(/Owner/), { target: { value: "team-sec" } });
    fireEvent.change(screen.getByLabelText(/Disposition/), { target: { value: "mitigate_later" } });
    fireEvent.change(screen.getByLabelText(/Proof/), { target: { value: "https://example.com/doc" } });
    fireEvent.click(screen.getByRole("button", { name: "Record decision" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Recorded: accepted risk, decided by alice.");
    const raise = calls.find((c) => c.method === "POST" && c.url.endsWith("/proposals"));
    expect(raise?.body).toEqual({ stance: "accepted_risk", rationale: "We carry it.", proposer_kind: "human", proposer_id: "alice" });
    const acc = calls.find((c) => c.url.endsWith("/p-new/accept"));
    expect(acc?.body).toEqual({
      actor_id: "alice",
      actor_kind: "human",
      review_by: "2027-01-31T00:00:00.000Z",
      owner: "team-sec",
      treatment: "mitigate_later",
      proof: "https://example.com/doc",
    });
    // The list of releases is not read unless the person opens it.
    expect(calls.some((c) => c.url.includes("scope-targets"))).toBe(false);
  });

  it("copies the decision to the ticked releases, and asks before replacing a decision", async () => {
    const calls = mockFetch({
      ...base,
      [PICK]: [200, { targets }],
      "POST /api/governance/findings/f1/proposals": [201, { proposal_id: "p-new" }],
      "POST /api/governance/findings/f1/proposals/p-new/accept": [204],
    });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    render();
    fireEvent.click(await screen.findByLabelText(/^Affected/));
    fireEvent.change(screen.getByLabelText(/Rationale/), { target: { value: "Reachable." } });
    fireEvent.click(screen.getByRole("button", { name: "Choose releases to copy to" }));
    fireEvent.click(await screen.findByLabelText("project-a 1.5.0"));
    fireEvent.click(screen.getByLabelText("project-b 2.0"));
    expect(screen.getByRole("note")).toHaveTextContent("Also copies to 2 findings in 2 projects, once, in your name. 1 of them has a decision that will be replaced");
    // A proposal is never copied.
    fireEvent.click(screen.getByRole("button", { name: "Only propose" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("A proposal is not copied");
    // The person says no to the replacement: nothing is sent.
    fireEvent.click(screen.getByRole("button", { name: "Record decision" }));
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("1 of the ticked releases already has a decision"));
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    // The person says yes: the picks go with the decision.
    confirm.mockReturnValue(true);
    fireEvent.click(screen.getByRole("button", { name: "Record decision" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Recorded: affected, decided by alice; copying to 2 more findings, they follow within a minute.");
    expect(calls.find((c) => c.url.endsWith("/p-new/accept"))?.body).toEqual({ actor_id: "alice", actor_kind: "human", copy_to: ["t1", "t3"] });
    confirm.mockRestore();
  });

  it("copies without asking when nothing is replaced, also when a waiting proposal is accepted", async () => {
    const calls = mockFetch({ ...base, [PICK]: [200, { targets }], "POST /api/governance/findings/f1/proposals/p-ai/accept": [204] });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Choose releases to copy to" }));
    fireEvent.click(await screen.findByLabelText("project-a 1.5.0"));
    fireEvent.click(screen.getByRole("button", { name: "Accept" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Recorded: not affected, decided by alice; copying to 1 more finding, they follow within a minute.");
    expect(calls.find((c) => c.url.endsWith("/p-ai/accept"))?.body).toEqual({ actor_id: "alice", actor_kind: "human", copy_to: ["t1"] });
    // No replacement, so the confirm was only the "leave the page" guard's, never called here.
    expect(confirm).not.toHaveBeenCalled();
    confirm.mockRestore();
  });

  it("does not accept a waiting proposal when the person refuses the replacement", async () => {
    const calls = mockFetch({ ...base, [PICK]: [200, { targets }] });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Choose releases to copy to" }));
    fireEvent.click(await screen.findByLabelText("project-b 2.0"));
    fireEvent.click(screen.getByRole("button", { name: "Accept" }));
    expect(confirm).toHaveBeenCalled();
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    confirm.mockRestore();
  });

  it("only proposes when asked, and shows a refusal", async () => {
    const calls = mockFetch({ ...base, "POST /api/governance/findings/f1/proposals": [201, { proposal_id: "p-new" }] });
    const first = render();
    fireEvent.click(await screen.findByLabelText(/^Affected/));
    fireEvent.change(screen.getByLabelText(/Rationale/), { target: { value: "Reachable." } });
    fireEvent.click(screen.getByRole("button", { name: "Only propose" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Proposal raised");
    expect(calls.some((c) => c.url.includes("/accept"))).toBe(false);
    first.unmount();

    mockFetch({ ...base, "POST /api/governance/findings/f1/proposals": [201, {}] });
    render();
    fireEvent.click(await screen.findByLabelText(/^Affected/));
    fireEvent.change(screen.getByLabelText(/Rationale/), { target: { value: "x" } });
    fireEvent.click(screen.getByRole("button", { name: "Record decision" }));
    expect(await screen.findByText(/returned no id/)).toBeInTheDocument();
  });

  it("accepts or rejects a waiting proposal, and names a refusal", async () => {
    const calls = mockFetch({
      ...base,
      "POST /api/governance/findings/f1/proposals/p-ai/accept": [204],
      "POST /api/governance/findings/f1/proposals/p-ai/reject": [403, { detail: "read-only key" }],
    });
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Accept" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Recorded: not affected, decided by alice.");
    expect(calls.find((c) => c.url.endsWith("/p-ai/accept"))?.body).toEqual({ actor_id: "alice", actor_kind: "human" });
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("read-only key");
  });

  it("asks before leaving with unsaved changes", async () => {
    mockFetch(base);
    render();
    fireEvent.change(await screen.findByLabelText(/Rationale/), { target: { value: "draft" } });
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    const back = screen.getByRole("link", { name: /back to the release/i });
    const ev = new MouseEvent("click", { bubbles: true, cancelable: true });
    back.dispatchEvent(ev);
    expect(confirm).toHaveBeenCalled();
    expect(ev.defaultPrevented).toBe(true);
    const unload = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(unload);
    expect(unload.defaultPrevented).toBe(true);
  });

  it("is read only for a read-only key, and names a missing finding or node", async () => {
    mockFetch({ ...base, "GET /whoami": [200, { user: "viewer", scopes: ["read"], can_write: false }] });
    const a = render();
    expect(await screen.findByText(/Your key is read-only/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Accept" })).toBeNull();
    a.unmount();

    mockFetch({ "GET /api/governance/findings/f1/assessment": [404] });
    const b = render();
    expect(await screen.findByText("Governance has no such finding.")).toBeInTheDocument();
    b.unmount();

    mockFetch({ "GET /api/governance/findings/f1/assessment": [502] });
    render();
    expect(await screen.findByText(/governance node did not answer/i)).toBeInTheDocument();
  });

  it("shows when the other releases cannot be read, and when there are none", async () => {
    mockFetch({ ...base, "GET /api/governance/faultlines/fl1/findings": [502] });
    const first = render();
    expect(await screen.findByText(/governance node did not answer/i)).toBeInTheDocument();
    first.unmount();
    mockFetch({ ...base, "GET /api/governance/faultlines/fl1/findings": [200, []] });
    renderWithQuery(<Decide findingId="f1" releaseId="" version="" />);
    expect(await screen.findByRole("link", { name: /back to the release/i })).toHaveAttribute("href", "#/release/r1");
    expect(await screen.findByText("none", { selector: "li" })).toBeInTheDocument();
  });
});

const RECOMMEND = "POST /api/governance/findings/f1/recommend";
const ASSESS = "GET /api/governance/findings/f1/assessment";
const aiProposal = { id: "p-ai", stance: "not_affected", proposer_kind: "ai", status: "proposed", evidence_trust: "inferred", rationale: "Not reachable." };
const undecided = (proposals: unknown[]) => ({ ...assessment, finding: { ...assessment.finding, current_position: undefined, proposals } });

/** An undecided finding with no AI proposal; the proposal appears once the AI was asked. */
function fresh(reply: Reply, extra: Record<string, Reply> = {}) {
  let asked = false;
  return mockFetch({
    ...base,
    [ASSESS]: () => [200, undecided(asked ? [aiProposal] : [])],
    [RECOMMEND]: () => {
      asked = true;
      return reply;
    },
    ...extra,
  });
}

describe("Decision page: the AI recommendation", () => {
  it("asks the AI only on the button, then fills the form on request and records it as is", async () => {
    const calls = fresh([201, { proposal_id: "p-ai" }], { "POST /api/governance/findings/f1/proposals/p-ai/accept": [204] });
    render();
    expect(await screen.findByText(/Not asked for this finding/)).toBeInTheDocument();
    expect(calls.some((c) => c.url.endsWith("/recommend"))).toBe(false);

    fireEvent.click(screen.getByRole("button", { name: "Ask the AI" }));
    const use = await screen.findByRole("button", { name: "Use this in the form" });
    expect(calls.filter((c) => c.url.endsWith("/recommend"))).toHaveLength(1);
    // The answer is shown, and the form is still the person's.
    expect(screen.getByLabelText(/Rationale/)).toHaveValue("");

    // An empty form takes the answer without a question.
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    fireEvent.click(use);
    expect(confirm).not.toHaveBeenCalled();
    expect(screen.getByLabelText(/Not affected/)).toBeChecked();
    expect(screen.getByLabelText(/Rationale/)).toHaveValue("Not reachable.");
    expect(screen.getByText(/In the form below/)).toBeInTheDocument();
    expect(screen.getByText(/Recording it as is accepts the AI's proposal in your name \(alice\)/)).toBeInTheDocument();

    // An untouched AI fill is not an unsaved change.
    screen.getByRole("link", { name: /back to the release/i }).dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    expect(confirm).not.toHaveBeenCalled();
    confirm.mockRestore();

    fireEvent.click(screen.getByRole("button", { name: "Record decision" }));
    expect(await screen.findByText(/Recorded: not affected, as the AI proposed, decided by alice\./)).toBeInTheDocument();
    expect(calls.find((c) => c.url.endsWith("/p-ai/accept"))?.body).toEqual({ actor_id: "alice", actor_kind: "human" });
    expect(calls.some((c) => c.method === "POST" && c.url.endsWith("/proposals"))).toBe(false);
  });

  it("asks before the AI's answer replaces what the person typed", async () => {
    const calls = fresh([201, { proposal_id: "p-ai" }], {
      "POST /api/governance/findings/f1/proposals": [201, { proposal_id: "p-new" }],
      "POST /api/governance/findings/f1/proposals/p-new/accept": [204],
    });
    // Hold the AI's answer: the form stays usable while it works.
    const inner = globalThis.fetch;
    let release = () => {};
    const held = new Promise<void>((ok) => (release = ok));
    vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("/recommend")) await held;
      return inner(input, init);
    });
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Ask the AI" }));
    expect(await screen.findByRole("status", { name: "Asking the AI" })).toBeInTheDocument();
    expect(screen.getByText("0 s")).toBeInTheDocument();
    expect(screen.getByLabelText(/Rationale/)).toBeEnabled();
    fireEvent.click(screen.getByLabelText(/^Affected/));
    fireEvent.change(screen.getByLabelText(/Rationale/), { target: { value: "mine" } });
    release();
    const use = await screen.findByRole("button", { name: "Use this in the form" });
    expect(screen.getByLabelText(/Rationale/)).toHaveValue("mine");

    // "No" keeps the person's values.
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    fireEvent.click(use);
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("Do you want to proceed?"));
    expect(screen.getByLabelText(/Rationale/)).toHaveValue("mine");

    // Recording now is the person's own proposal; the AI's is not accepted.
    confirm.mockRestore();
    fireEvent.click(screen.getByRole("button", { name: "Record decision" }));
    expect(await screen.findByText(/Recorded: affected, decided by alice\./)).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST" && c.url.endsWith("/proposals"))?.body).toEqual({
      stance: "affected",
      rationale: "mine",
      proposer_kind: "human",
      proposer_id: "alice",
    });
    expect(calls.some((c) => c.url.endsWith("/p-ai/accept"))).toBe(false);

    // "Yes" replaces them.
    vi.spyOn(window, "confirm").mockReturnValue(true);
    fireEvent.click(screen.getByRole("button", { name: "Use this in the form" }));
    expect(screen.getByLabelText(/Not affected/)).toBeChecked();
    expect(screen.getByLabelText(/Rationale/)).toHaveValue("Not reachable.");
    vi.restoreAllMocks();
  });

  it("names a no-answer and a failure, and asks again on request", async () => {
    const calls = fresh([204]);
    const first = render();
    fireEvent.click(await screen.findByRole("button", { name: "Ask the AI" }));
    expect(await screen.findByText("no answer")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Ask the AI again" }));
    await waitFor(() => expect(calls.filter((c) => c.url.endsWith("/recommend"))).toHaveLength(2));
    first.unmount();

    mockFetch({ ...base, [ASSESS]: [200, undecided([])], [RECOMMEND]: [500, { detail: "gateway broke" }] });
    const second = render();
    fireEvent.click(await screen.findByRole("button", { name: "Ask the AI" }));
    expect(await screen.findByText(/returned 500: gateway broke/)).toBeInTheDocument();
    second.unmount();

    mockFetch({ ...base, [ASSESS]: [200, undecided([])], [RECOMMEND]: [500] });
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Ask the AI" }));
    expect(await screen.findByText(/returned 500: no detail/)).toBeInTheDocument();
  });

  it("lets a read-only key ask the AI and read the answer, never use or record it", async () => {
    const calls = fresh([201, { proposal_id: "p-ai" }], { "GET /whoami": [200, { user: "viewer", scopes: ["read"], can_write: false }] });
    render();
    expect(await screen.findByText(/Your key is read-only/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Ask the AI" }));
    expect(await screen.findAllByText("Not reachable.")).toHaveLength(2);
    expect(calls.filter((c) => c.url.endsWith("/recommend"))).toHaveLength(1);
    expect(screen.queryByRole("button", { name: "Use this in the form" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Record decision" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Accept" })).toBeNull();
  });

  it("says so when the recorded proposal cannot be read back", async () => {
    mockFetch({ ...base, [ASSESS]: [200, undecided([])], [RECOMMEND]: [201, { proposal_id: "p-ai" }] });
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Ask the AI" }));
    expect(await screen.findByText(/could not read it back/)).toBeInTheDocument();
  });

  it("ignores a stance it does not know", async () => {
    mockFetch({ ...base, [ASSESS]: [200, undecided([{ ...aiProposal, stance: "fixed_elsewhere", rationale: undefined, id: "p-odd" }])] });
    render();
    fireEvent.click(await screen.findByRole("button", { name: "Use this in the form" }));
    expect(screen.getByLabelText(/Rationale/)).toHaveValue("");
    for (const r of screen.getAllByRole("radio")) expect(r).not.toBeChecked();
  });
});
