import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { CopyPicker, copySummary, copyable, type CopyTarget } from "./copy-picker";
import { mockFetch } from "@/test/helpers";

const URL = "GET /api/governance/findings/f1/scope-targets?scope=product&all=true";
const targets: CopyTarget[] = [
  { finding_id: "t1", project_id: "j1", project_name: "project-a", version: "1.5.0", level: "artifact" },
  { finding_id: "t2", project_id: "j1", project_name: "project-a", version: "1.6.0", level: "component" },
  { finding_id: "t3", project_id: "j2", project_name: "project-b", version: "2.0", level: "artifact", decision: { stance: "affected", decided_by_kind: "human" } },
  { finding_id: "t4", project_id: "j2", project_name: "project-b", version: "2.1", level: "vulnerability" },
  { finding_id: "t5", project_id: "j3", release_id: "r9", level: "vulnerability" },
];

function Host({ onTargets }: { onTargets?: (t: CopyTarget[]) => void }) {
  const [picked, setPicked] = useState<string[]>([]);
  return (
    <>
      <CopyPicker findingId="f1" picked={picked} onChange={setPicked} onTargets={onTargets} />
      <output>{picked.join(",")}</output>
    </>
  );
}
const picked = () => document.querySelector("output")?.textContent;

describe("copy pick list", () => {
  it("counts what a pick copies and replaces", () => {
    expect(copySummary(targets, [])).toEqual({ findings: 0, projects: 0, replaced: 0 });
    expect(copySummary(targets, ["t1", "t2", "t3", "ghost"])).toEqual({ findings: 3, projects: 2, replaced: 1 });
    expect(copyable(targets[0]!)).toBe(true);
    expect(copyable(targets[3]!)).toBe(false);
  });

  it("reads the list only when opened, and ticks releases, projects and the whole product", async () => {
    const calls = mockFetch({ [URL]: [200, { targets }] });
    const onTargets = vi.fn();
    render(<Host onTargets={onTargets} />);
    expect(calls).toHaveLength(0);
    fireEvent.click(screen.getByRole("button", { name: "Choose releases to copy to" }));
    expect(screen.getByText(/Reading the releases/)).toBeInTheDocument();
    expect(await screen.findByText("3 releases can take a copy, in 2 projects.")).toBeInTheDocument();
    expect(onTargets).toHaveBeenCalledWith(targets);
    expect(screen.getByRole("note")).toHaveTextContent("Nothing is ticked: the decision stays on this release only.");
    // A different component is listed and cannot be ticked; a project of only such rows neither.
    expect(screen.getByLabelText("project-b 2.1")).toBeDisabled();
    expect(screen.getByLabelText("Project j3")).toBeDisabled();
    expect(screen.getAllByText("different component, cannot be copied to")).toHaveLength(2);
    expect(screen.getByText("same package, other version")).toBeInTheDocument();
    expect(screen.getByText("r9")).toBeInTheDocument();
    expect(screen.getByText("by human")).toBeInTheDocument();
    // One release, then its whole project.
    fireEvent.click(screen.getByLabelText("project-a 1.5.0"));
    expect(picked()).toBe("t1");
    expect(screen.getByRole("note")).toHaveTextContent("Also copies to 1 finding in 1 project, once, in your name.");
    expect(screen.getByLabelText("Project project-a")).not.toBeChecked();
    fireEvent.click(screen.getByLabelText("Project project-a"));
    expect(picked()).toBe("t1,t2");
    expect(screen.getByLabelText("Project project-a")).toBeChecked();
    // A decided release says what happens to its decision only once ticked.
    expect(screen.queryByText("will be replaced by this decision")).toBeNull();
    fireEvent.click(screen.getByLabelText("Project project-b"));
    expect(picked()).toBe("t1,t2,t3");
    expect(screen.getByText("will be replaced by this decision")).toBeInTheDocument();
    expect(screen.getByRole("note")).toHaveTextContent("3 findings in 2 projects, once, in your name. 1 of them has a decision that will be replaced; the old one stays in the history.");
    // Untick a project, clear, select all.
    fireEvent.click(screen.getByLabelText("Project project-a"));
    expect(picked()).toBe("t3");
    fireEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(picked()).toBe("");
    fireEvent.click(screen.getByRole("button", { name: "Select all in product" }));
    expect(picked()).toBe("t1,t2,t3");
    fireEvent.click(screen.getByLabelText("project-b 2.0"));
    expect(picked()).toBe("t1,t2");
  });

  it("says so when two picked releases have decisions", async () => {
    const two: CopyTarget[] = [
      { finding_id: "a", project_id: "j1", project_name: "project-a", version: "1", level: "artifact", decision: { stance: "affected", decided_by_id: "bob" } },
      { finding_id: "b", project_id: "j1", project_name: "project-a", version: "2", level: "artifact", decision: { stance: "mitigated", decided_by_id: "bob" } },
    ];
    mockFetch({ [URL]: [200, { targets: two }] });
    render(<Host />);
    fireEvent.click(screen.getByRole("button", { name: "Choose releases to copy to" }));
    fireEvent.click(await screen.findByRole("button", { name: "Select all in product" }));
    expect(screen.getByRole("note")).toHaveTextContent("2 of them have a decision that will be replaced");
    expect(screen.getAllByText("by bob")).toHaveLength(2);
  });

  it("says when there is nothing to copy to, and when the list cannot be read", async () => {
    mockFetch({ [URL]: [200, {}] });
    const first = render(<Host />);
    fireEvent.click(screen.getByRole("button", { name: "Choose releases to copy to" }));
    expect(await screen.findByText(/No other release of this product has this CVE/)).toBeInTheDocument();
    first.unmount();
    mockFetch({ [URL]: [503, { detail: "no Registry seam" }] });
    render(<Host />);
    fireEvent.click(screen.getByRole("button", { name: "Choose releases to copy to" }));
    expect(await screen.findByText(/could not be read: .*no Registry seam/)).toBeInTheDocument();
  });
});
