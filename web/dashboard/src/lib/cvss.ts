// The CVSS 3.x base metrics a person may change when setting a severity (EDR-SCORING-01
// section 7.1). The score is never computed here: Governance's calculator does that, and this
// file only edits the vector string the form sends.
export const BASE_METRICS = [
  { key: "AV", label: "Attack vector", values: [["N", "Network"], ["A", "Adjacent"], ["L", "Local"], ["P", "Physical"]] },
  { key: "AC", label: "Attack complexity", values: [["L", "Low"], ["H", "High"]] },
  { key: "PR", label: "Privileges required", values: [["N", "None"], ["L", "Low"], ["H", "High"]] },
  { key: "UI", label: "User interaction", values: [["N", "None"], ["R", "Required"]] },
  { key: "S", label: "Scope", values: [["U", "Unchanged"], ["C", "Changed"]] },
  { key: "C", label: "Confidentiality", values: [["H", "High"], ["L", "Low"], ["N", "None"]] },
  { key: "I", label: "Integrity", values: [["H", "High"], ["L", "Low"], ["N", "None"]] },
  { key: "A", label: "Availability", values: [["H", "High"], ["L", "Low"], ["N", "None"]] },
] as const;

/** One metric's value in a vector; "" when the vector does not carry it. */
export function metricOf(vector: string, key: string): string {
  for (const part of vector.split("/").slice(1)) {
    const [k, v] = part.split(":");
    if (k === key) return v ?? "";
  }
  return "";
}

/** The vector with one base metric changed. The matching "modified" metric (MAV for AV, and so
 * on) is dropped, because it would otherwise keep deciding the score in place of the change. */
export function withMetric(vector: string, key: string, value: string): string {
  const [head, ...parts] = vector.split("/");
  const out = parts.filter((p) => !p.startsWith(`M${key}:`)).map((p) => (p.startsWith(`${key}:`) ? `${key}:${value}` : p));
  return [head, ...out].join("/");
}

/** The base metrics that differ between two vectors, as "PR N → L". */
export function changedMetrics(from: string, to: string): string[] {
  return BASE_METRICS.filter((m) => metricOf(from, m.key) !== metricOf(to, m.key)).map(
    (m) => `${m.key} ${metricOf(from, m.key)} → ${metricOf(to, m.key)}`,
  );
}
