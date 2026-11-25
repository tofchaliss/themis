import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { SeverityCard, type SeverityTarget } from "./severity-card";
import { ExpertSeverity, countingSeverity } from "./finding-bits";
import { mockFetch, renderWithQuery, type Routes } from "@/test/helpers";
import { render } from "@testing-library/react";

const BASE = "/api/governance/findings/f1/severity";
const VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const original = { finding_id: "f1", cve: "CVE-2026-0001", original_score: 9.8, original_severity: "critical", original_vector: VECTOR, history: [] };
const owner = { kind: "level", level: "medium", score: 6.9, original_score: 9.8, reason: "only after login", set_by: "alice", set_at: "2026-11-25T10:00:00Z" };
const withOwner = { ...original, owner, history: [{ ...owner, level: "low", score: 3.9, ended_at: "2026-11-25T10:00:00Z", ended_by: "alice", end_cause: "replaced" }, owner] };
const targets: SeverityTarget[] = [
  { finding_id: "t1", release_id: "r1", project_id: "j1", project_name: "project-a", version: "1.5.0" },
  { finding_id: "t2", release_id: "r2", project_id: "j1", project_name: "project-a", version: "1.6.0", owner: { ...owner, level: "high", score: 7.5 } as SeverityTarget["owner"] },
  { finding_id: "t3", release_id: "r3", project_id: "j2" },
];

const show = (routes: Routes, canSet = true) => {
  const calls = mockFetch(routes);
  renderWithQuery(<SeverityCard findingId="f1" canSet={canSet} user="alice" />);
  return calls;
};

afterEach(() => vi.restoreAllMocks());

describe("severity card", () => {
  it("shows the original and says the original counts when nothing is set", async () => {
    show({ [`GET ${BASE}`]: [200, original] });
    expect(await screen.findByText("none, the original counts")).toBeInTheDocument();
    expect(screen.getByText("9.8")).toBeInTheDocument();
    expect(screen.getByText(VECTOR)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Set severity" })).toBeInTheDocument();
    expect(screen.queryByText(/History/)).not.toBeInTheDocument();
  });

  it("is read-only for a person who is not an admin", async () => {
    show({ [`GET ${BASE}`]: [200, withOwner] }, false);
    expect(await screen.findByText("Only an admin can set or remove the severity.")).toBeInTheDocument();
    expect(screen.getAllByText("Reason: only after login")).toHaveLength(3);
    expect(screen.getByText("counts for priority and deadline")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Change severity" })).not.toBeInTheDocument();
    expect(screen.getByText("History (2)")).toBeInTheDocument();
    expect(screen.getByText(/replaced by alice/)).toBeInTheDocument();
    expect(screen.getByText("in force")).toBeInTheDocument();
  });

  it("says so when the finding has no severity read, and shows a failed read", async () => {
    show({});
    expect(await screen.findByText("Severity is not available for this finding.")).toBeInTheDocument();
  });

  it("shows a failed read", async () => {
    show({ [`GET ${BASE}`]: [500, { detail: "boom" }] });
    expect(await screen.findByText(/boom/)).toBeInTheDocument();
  });

  it("sets a level with a preview, a reason and picked releases", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const calls = show({
      [`GET ${BASE}`]: [200, original],
      [`POST ${BASE}/preview`]: [200, { kind: "level", level: "medium", score: 6.9, original_score: 9.8 }],
      [`GET ${BASE}/targets`]: [200, { finding_id: "f1", count: 3, with_owner_severity: 1, targets }],
      [`PUT ${BASE}`]: [200, { applied: 3, replaced: 1, severity: { ...original, owner, history: [owner] } }],
    });
    fireEvent.click(await screen.findByRole("button", { name: "Set severity" }));
    expect(screen.getByText("The computed score shows here.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save severity" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Pick a level.");
    fireEvent.change(screen.getByLabelText("Level"), { target: { value: "medium" } });
    expect(await screen.findByText("Themis computes")).toBeInTheDocument();
    expect(screen.getByText("(original 9.8)")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save severity" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Write the reason");
    fireEvent.change(screen.getByLabelText(/Reason/), { target: { value: " only after login " } });

    // The pick list: read on open, a project tick, the whole product, and what gets replaced.
    fireEvent.click(screen.getByRole("button", { name: "Choose other releases" }));
    expect(await screen.findByText("3 releases in 2 projects have this CVE.")).toBeInTheDocument();
    expect(screen.getByRole("note")).toHaveTextContent("Nothing is ticked");
    fireEvent.click(screen.getByLabelText("Project project-a"));
    expect(screen.getByText("will be replaced")).toBeInTheDocument();
    expect(screen.getByRole("note")).toHaveTextContent("Also sets it on 2 findings in 1 project. 1 of them has an owner-set severity that will be replaced");
    fireEvent.click(screen.getByLabelText("project-a 1.5.0"));
    expect(screen.getByRole("note")).toHaveTextContent("Also sets it on 1 finding in 1 project.");
    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    fireEvent.click(screen.getByRole("button", { name: "Select all in product" }));
    expect(screen.getByLabelText("Project j2")).toBeChecked();
    expect(screen.getByText(/Each release gets its own score/)).toBeInTheDocument();

    // Replacing asks first; "no" sends nothing.
    confirm.mockReturnValueOnce(false);
    fireEvent.click(screen.getByRole("button", { name: "Save severity" }));
    expect(calls.some((c) => c.method === "PUT")).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Save severity" }));
    expect(await screen.findByRole("status", { name: "" })).toHaveTextContent("Saved: medium 6.9, set on 3 findings.");
    const put = calls.find((c) => c.method === "PUT");
    expect(put?.body).toEqual({ actor_id: "alice", reason: "only after login", level: "medium", apply_to: ["t1", "t2", "t3"] });
    expect(confirm).toHaveBeenLastCalledWith(expect.stringContaining("1 owner-set severity will be replaced"));
  });

  it("sets changed CVSS metrics and sends the vector", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const changed = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H";
    const calls = show({
      [`GET ${BASE}`]: [200, withOwner],
      [`POST ${BASE}/preview`]: [200, { kind: "vector", level: "high", score: 8.8, vector: changed }],
      [`PUT ${BASE}`]: [200, { applied: 1, replaced: 1, severity: { ...original, owner: { ...owner, kind: "vector", level: "high", score: 8.8, vector: changed }, history: [] } }],
    });
    fireEvent.click(await screen.findByRole("button", { name: "Change severity" }));
    fireEvent.click(screen.getByLabelText("Change CVSS metrics"));
    expect(screen.getByText("Nothing is changed yet.")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save severity" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Change at least one metric.");
    fireEvent.change(screen.getByLabelText("Privileges required"), { target: { value: "L" } });
    expect(screen.getByText("Changed: PR N → L")).toBeInTheDocument();
    expect(await screen.findByText("8.8")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Reason/), { target: { value: "needs a login" } });
    fireEvent.click(screen.getByRole("button", { name: "Save severity" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ actor_id: "alice", reason: "needs a login", vector: changed }));
    expect(await screen.findByText(/Saved: high 8.8, set on 1 finding\./)).toBeInTheDocument();
  });

  it("offers only a level when no vector is stored, and shows a refused save and a failed preview", async () => {
    show({
      [`GET ${BASE}`]: [200, { ...original, original_vector: undefined, original_score: undefined, original_severity: undefined }],
      [`POST ${BASE}/preview`]: [400, { detail: "bad level" }],
      [`PUT ${BASE}`]: [403, { detail: "admin only" }],
      [`GET ${BASE}/targets`]: [503, { detail: "no Registry seam" }],
    });
    fireEvent.click(await screen.findByRole("button", { name: "Set severity" }));
    expect(screen.getByLabelText("Change CVSS metrics")).toBeDisabled();
    expect(screen.getByText(/only a level can be set/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Level"), { target: { value: "low" } });
    expect(await screen.findByText(/The score could not be computed: bad level/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Choose other releases" }));
    expect(await screen.findByText(/The list of releases could not be read: .*no Registry seam/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText(/Reason/), { target: { value: "r" } });
    fireEvent.click(screen.getByRole("button", { name: "Save severity" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("admin only");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByRole("button", { name: "Set severity" })).toBeInTheDocument();
  });

  it("says when no other release has the CVE", async () => {
    show({ [`GET ${BASE}`]: [200, original], [`GET ${BASE}/targets`]: [200, { finding_id: "f1", count: 0, with_owner_severity: 0, targets: [] }] });
    fireEvent.click(await screen.findByRole("button", { name: "Set severity" }));
    fireEvent.click(screen.getByRole("button", { name: "Choose other releases" }));
    expect(await screen.findByText("No other release of this product has this CVE.")).toBeInTheDocument();
  });

  it("removes the owner-set severity after asking, and shows a refusal", async () => {
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    let status = 403;
    const calls = show({ [`GET ${BASE}`]: [200, withOwner], [`POST ${BASE}/remove`]: () => [status, status === 200 ? original : { detail: "admin only" }] });
    fireEvent.click(await screen.findByRole("button", { name: "Remove owner-set severity" }));
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    confirm.mockReturnValue(true);
    fireEvent.click(screen.getByRole("button", { name: "Remove owner-set severity" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("admin only");
    status = 200;
    fireEvent.click(screen.getByRole("button", { name: "Remove owner-set severity" }));
    expect(await screen.findByText("Removed. The original score counts again.")).toBeInTheDocument();
    expect(calls.find((c) => c.method === "POST")?.body).toEqual({ actor_id: "alice" });
  });
});

describe("the severity that counts in the lists", () => {
  it("is the owner-set one while it stands", () => {
    const entry = { expert_severity: "critical", expert_score: 9.8, owner_severity: owner } as Parameters<typeof countingSeverity>[0];
    expect(countingSeverity(entry)).toBe("medium");
    expect(countingSeverity({ expert_severity: "high" } as Parameters<typeof countingSeverity>[0])).toBe("high");
    render(<ExpertSeverity entry={entry} />);
    expect(screen.getByText("owner-set")).toBeInTheDocument();
    expect(screen.getByText("6.9")).toBeInTheDocument();
    expect(screen.getByTitle("Set by alice: only after login")).toBeInTheDocument();
  });
});
