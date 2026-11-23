import { describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { Explanation, ScoreSection, SimilarDecisions } from "./drawer-extras";
import { CustomerVexCard, DocSheet, PublicationsCard, RemediationPlanCard } from "./release-extras";
import { mockFetch, renderWithQuery } from "@/test/helpers";

describe("drawer extras", () => {
  it("explains when the AI answers, names a decline, and hides when the plane is off", async () => {
    mockFetch({ "POST /api/intelligence/capabilities/explain_vulnerability/invoke": [200, { information: "It matters here." }] });
    const a = renderWithQuery(<Explanation findingId="f1" />);
    expect(await screen.findByText("It matters here.")).toBeInTheDocument();
    a.unmount();
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 204, headers: { "X-Themis-AI-Reason": "insufficient" } })));
    const b = renderWithQuery(<Explanation findingId="f2" />);
    expect(await screen.findByText("declined honestly")).toBeInTheDocument();
    b.unmount();
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 204, headers: { "X-Themis-AI-Reason": "disabled" } })));
    const c = renderWithQuery(<Explanation findingId="f3" />);
    await waitFor(() => expect(c.container).toBeEmptyDOMElement());
  });

  it("shows how the score was made, and says when there is none", async () => {
    mockFetch({
      "GET /api/governance/findings/f1/score": [
        200,
        {
          finding_id: "f1",
          cve: "CVE-1",
          rollup: {
            revision: 2,
            cause: "source_added",
            recorded_at: "2026-11-21T10:00:00Z",
            snapshot: {
              state: "scored",
              score: 7.7,
              band: "high",
              score_status: "provisional",
              contributors: ["pkg:a@1"],
              at_maximum: ["pkg:a@1"],
              scoring_coverage: { value: "partial", numerator: 1, denominator: 2 },
              assessment_finality: { value: "not_applicable" },
              unassessed: [{ purl: "pkg:b@1", reason: "no_vector" }],
            },
          },
          components: [
            {
              purl: "pkg:a@1",
              revision: 2,
              cause: "source_added",
              recorded_at: "2026-11-21T10:00:00Z",
              snapshot: {
                score_status: "provisional",
                eligible: true,
                open: true,
                outcome: "selected",
                conflict_conditions: ["independent_assessor_disagreement"],
                scores: { base: 9.8, temporal: 9.1, environmental: 7.7 },
                assessment_vector: "CVSS:3.1/AV:N",
                candidates: [{ assessor: "nvd", feed: "nvd-api", class: "nvd_analyst", cvss_version: "3.1", vector: "AV:N", scores: { environmental: 7.7 }, disposition: "reference" }, { disposition: "rejected" }],
              },
            },
            { purl: "pkg:c@1", revision: 1, cause: "component_added", recorded_at: "", snapshot: { score_status: "unavailable", eligible: false, open: false } },
          ],
          history: [
            { purl: "pkg:a@1", revision: 2, cause: "source_added", score_status: "provisional", score: 7.7, recorded_at: "2026-11-21T10:00:00Z" },
            { purl: "pkg:a@1", revision: 1, cause: "component_added", score_status: "final", score: 9.8, recorded_at: "2026-11-20T10:00:00Z" },
          ],
        },
      ],
      "GET /api/governance/findings/f2/score": [200, { finding_id: "f2", cve: "CVE-2", rollup: { revision: 1, cause: "x", recorded_at: "", snapshot: { state: "no_carrier" } }, components: [], history: [] }],
      "GET /api/governance/findings/f3/score": [404],
      "GET /api/governance/findings/f4/score": [500],
    });
    const a = renderWithQuery(<ScoreSection findingId="f1" />);
    expect(await screen.findByText(/highest Environmental score among 1 contributing component$/)).toBeInTheDocument();
    expect(screen.getAllByText("two assessors give different vectors")).toHaveLength(2);
    expect(screen.getByText("no source gave a CVSS vector")).toBeInTheDocument();
    expect(screen.getByText("scope, not counted")).toBeInTheDocument();
    expect(screen.getByText("Base 9.8 · Temporal 9.1 · Environmental 7.7", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("NVD")).toBeInTheDocument();
    expect(screen.getByText(/History \(2 revisions/)).toBeInTheDocument();
    a.unmount();
    const b = renderWithQuery(<ScoreSection findingId="f2" />);
    expect(await screen.findByText(/Only rebuild-set/)).toBeInTheDocument();
    b.unmount();
    const c = renderWithQuery(<ScoreSection findingId="f3" />);
    expect(await screen.findByText(/Not yet assessed/)).toBeInTheDocument();
    c.unmount();
    renderWithQuery(<ScoreSection findingId="f4" />);
    expect(await screen.findByText(/Score unavailable/)).toBeInTheDocument();
  });

  it("lists similar decisions, none, or unavailable", async () => {
    mockFetch({
      "GET /api/intelligence/findings/f1/similar?k=5": [200, { finding_id: "f1", precedents: [{ release_id: "r1234567890", stance: "not_affected", source_cve: "CVE-9", score: 0.91, rationale: "same loader" }, { release_id: "r2", stance: "affected" }] }],
      "GET /api/intelligence/findings/f2/similar?k=5": [200, { finding_id: "f2", precedents: [] }],
    });
    const a = renderWithQuery(<SimilarDecisions findingId="f1" />);
    expect(await screen.findByText("same loader")).toBeInTheDocument();
    expect(screen.getByText("0.91")).toBeInTheDocument();
    expect(screen.getByText("exact")).toBeInTheDocument();
    expect(screen.getByText("release r1234567")).toBeInTheDocument();
    a.unmount();
    const b = renderWithQuery(<SimilarDecisions findingId="f2" />);
    expect(await screen.findByText(/No precedent found/)).toBeInTheDocument();
    b.unmount();
    renderWithQuery(<SimilarDecisions findingId="f3" />);
    expect(await screen.findByText(/Precedent unavailable/)).toBeInTheDocument();
  });
});

describe("release extras", () => {
  it("drafts a remediation plan and shows a refusal", async () => {
    mockFetch({ "POST /api/intelligence/capabilities/plan_remediation/invoke": [200, { information: "Upgrade openssl." }] });
    const a = renderWithQuery(<RemediationPlanCard releaseId="r1" />);
    fireEvent.click(screen.getByRole("button", { name: "Draft a remediation plan" }));
    expect(await screen.findByText("Upgrade openssl.")).toBeInTheDocument();
    a.unmount();
    mockFetch({ "POST /api/intelligence/capabilities/plan_remediation/invoke": [500, { detail: "boom" }] });
    renderWithQuery(<RemediationPlanCard releaseId="r1" />);
    fireEvent.click(screen.getByRole("button", { name: "Draft a remediation plan" }));
    expect(await screen.findByText(/plan_remediation returned 500: boom/)).toBeInTheDocument();
  });

  it("previews, views and republishes the customer VEX", async () => {
    const onDoc = vi.fn();
    const calls = mockFetch({
      "GET /api/communication/releases/r1/rollup-status?audience=customer": [200, { found: true, publication_id: "pub1", statements: 4, as_of: "2026-11-20", stale: true, summary: "2 decisions changed" }],
      "POST /api/communication/previews": [200, { payload: "{}" }],
      "GET /api/communication/rollups/pub1": [200, { as_of: "2026-11-20", payload: "{\"a\":1}" }],
      "POST /api/communication/publications": [201, { publication_id: "pub2" }],
    });
    renderWithQuery(<CustomerVexCard releaseId="r1" canWrite onDoc={onDoc} />);
    expect(await screen.findByText("2 decisions changed")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() => expect(onDoc).toHaveBeenCalledWith(expect.objectContaining({ note: "preview, not recorded" })));
    fireEvent.click(screen.getByRole("button", { name: "View published" }));
    await waitFor(() => expect(onDoc).toHaveBeenCalledWith(expect.objectContaining({ payload: "{\"a\":1}" })));
    fireEvent.click(screen.getByRole("button", { name: /Republish/ }));
    await waitFor(() => expect(calls.some((c) => c.url === "/api/communication/publications")).toBe(true));
    expect(calls.find((c) => c.url === "/api/communication/publications")?.body).toEqual({ release_id: "r1", artifact_type: "vex", format: "openvex", audience: "customer" });
  });

  it("shows none published, a current document, an unreadable status, and a refused publish", async () => {
    mockFetch({ "GET /api/communication/releases/r1/rollup-status?audience=customer": [200, { found: false }], "POST /api/communication/publications": [403, { detail: "read-only key" }] });
    const a = renderWithQuery(<CustomerVexCard releaseId="r1" canWrite onDoc={vi.fn()} />);
    expect(await screen.findByText("none published yet")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Publish" }));
    expect(await screen.findByText("read-only key")).toBeInTheDocument();
    a.unmount();
    mockFetch({ "GET /api/communication/releases/r1/rollup-status?audience=customer": [200, { found: true, statements: 1, as_of: "x" }] });
    const b = renderWithQuery(<CustomerVexCard releaseId="r1" canWrite={false} onDoc={vi.fn()} />);
    expect(await screen.findByText("current")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^(Re)?publish/i })).toBeNull();
    expect(screen.getByRole("button", { name: "View published" })).toBeInTheDocument();
    b.unmount();
    mockFetch({ "GET /api/communication/releases/r1/rollup-status?audience=customer": [500] });
    renderWithQuery(<CustomerVexCard releaseId="r1" canWrite onDoc={vi.fn()} />);
    expect(await screen.findByText("status unavailable")).toBeInTheDocument();
  });

  it("lists publications and the queue, opens a document and previews a queued decision", async () => {
    const onDoc = vi.fn();
    mockFetch({
      "GET /api/communication/publications?release=r1": [200, [{ id: "p1", artifact_type: "vex", format: "csaf", cve: "CVE-1", stance: "not_affected", delivery_status: "delivered", superseded: true }]],
      "GET /api/communication/publishable-positions": [200, [{ finding_id: "f2", release_id: "r1", cve: "CVE-2", stance: "affected", version: 3, stale: true }, { finding_id: "f9", release_id: "r9", cve: "CVE-9" }]],
      "GET /api/communication/publications/p1": [200, { cve: "CVE-1", format: "csaf", stance: "not_affected", superseded: true, payload: "{}" }],
      "POST /api/communication/previews": [200, { payload: "x" }],
    });
    renderWithQuery(<PublicationsCard releaseId="r1" onDoc={onDoc} />);
    fireEvent.click(await screen.findByRole("row", { name: /csaf document for CVE-1/ }));
    await waitFor(() => expect(onDoc).toHaveBeenCalledWith(expect.objectContaining({ note: "superseded" })));
    expect(await screen.findByText("Publishable queue")).toBeInTheDocument();
    expect(screen.queryByText("CVE-9")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Preview CVE-2" }));
    await waitFor(() => expect(onDoc).toHaveBeenCalledWith(expect.objectContaining({ title: "CVE-2", payload: "x" })));
  });

  it("says nothing is published, and shows the document with a download", async () => {
    mockFetch({ "GET /api/communication/publications?release=r1": [200, []], "GET /api/communication/publishable-positions": [200, []] });
    renderWithQuery(<PublicationsCard releaseId="r1" onDoc={vi.fn()} />);
    expect(await screen.findByText("Nothing published for this release")).toBeInTheDocument();
    const url = vi.fn(() => "blob:x");
    vi.stubGlobal("URL", Object.assign(URL, { createObjectURL: url, revokeObjectURL: vi.fn() }));
    const onClose = vi.fn();
    renderWithQuery(<DocSheet doc={{ title: "CVE-1", format: "markdown", stance: "affected", note: "preview, not recorded", payload: "# not json" }} onClose={onClose} />);
    const d = await screen.findByRole("dialog");
    expect(within(d).getByText("# not json")).toBeInTheDocument();
    fireEvent.click(within(d).getByRole("button", { name: "Download" }));
    expect(url).toHaveBeenCalled();
    fireEvent.keyDown(d, { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
  });
});
