import { describe, expect, it } from "vitest";
import { changedMetrics, metricOf, withMetric } from "./cvss";

const V = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MPR:H/CR:H";

describe("cvss vector edits", () => {
  it("reads a metric", () => {
    expect(metricOf(V, "PR")).toBe("N");
    expect(metricOf(V, "CR")).toBe("H");
    expect(metricOf(V, "E")).toBe("");
    expect(metricOf("CVSS:3.1/AV", "AV")).toBe("");
  });
  it("changes a base metric and drops its modified twin", () => {
    expect(withMetric(V, "PR", "L")).toBe("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/CR:H");
    expect(withMetric(V, "A", "N")).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N/MPR:H/CR:H");
  });
  it("lists what changed", () => {
    expect(changedMetrics(V, V)).toEqual([]);
    expect(changedMetrics(V, withMetric(withMetric(V, "PR", "L"), "A", "N"))).toEqual(["PR N → L", "A H → N"]);
  });
});
