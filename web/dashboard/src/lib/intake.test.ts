import { describe, expect, it } from "vitest";
import { errorText, followReceipt, intakeContentType, reasonMeaning, receiptOutcome, register, sendVex, type IntakeReceipt } from "./intake";
import { NodeDownError } from "./api";
import { mockFetch } from "@/test/helpers";

const rec = (r: Partial<IntakeReceipt>): IntakeReceipt => ({ intake_id: "i1", status: "filed", status_url: "", ...r });
const now = () => Promise.resolve();

describe("intake", () => {
  it("picks the content type and reads a reason", () => {
    expect(intakeContentType("a.nessus")).toBe("application/xml");
    expect(intakeContentType("a.CSV")).toBe("text/csv");
    expect(intakeContentType("a.json")).toBe("application/json");
    expect(reasonMeaning("empty_report")).toMatch(/zero findings/);
    expect(reasonMeaning("brand_new")).toMatch(/does not know/);
    expect(errorText(new NodeDownError("evidence"))).toMatch(/evidence node/);
    expect(errorText("x")).toBe("The request failed.");
  });

  it("words a receipt: refused, failed without a reason, filed with an observation time", () => {
    expect(receiptOutcome(rec({ status: "rejected", reason: "empty_report", detail: "none" }))).toMatchObject({ tone: "err", title: "Intake refused", reason: "empty_report" });
    expect(receiptOutcome(rec({ status: "failed" }))).toMatchObject({ tone: "err", title: "Intake could not be carried out", detail: "intake failed" });
    expect(receiptOutcome(rec({ detected_kind: "scanner-report", converted_by: "nessus-csv@1", observed_at: "2026-11-20T00:00:00Z" })).detail).toBe(
      "scanner-report / ? · ? findings considered, 0 skipped · converted by nessus-csv@1 · observed 2026-11-20T00:00:00Z",
    );
  });

  it("follows a receipt until it ends, the node goes away, or it never finishes", async () => {
    mockFetch({ "GET /api/evidence/intake/i1": [200, rec({ status: "rejected", reason: "schema_invalid" })] });
    expect((await followReceipt(rec({ status: "accepted" }), now))?.status).toBe("rejected");
    mockFetch({ "GET /api/evidence/intake/i1": [404] });
    expect(await followReceipt(rec({ status: "accepted" }), now)).toBeNull();
    mockFetch({ "GET /api/evidence/intake/i1": [502] });
    expect(await followReceipt(rec({ status: "accepted" }), now)).toBeNull();
    mockFetch({ "GET /api/evidence/intake/i1": [200, rec({ status: "converting" })] });
    expect(await followReceipt(rec({ status: "accepted" }), now, 2)).toBeNull();
  });

  it("files a VEX, keeps a dedup, and shows a refusal", async () => {
    const f = new File(["{}"], "v.json");
    mockFetch({ "POST /api/evidence/evidence": [200, { id: "v1", created: false }] });
    expect((await sendVex(f, "r1")).title).toMatch(/Already filed/);
    mockFetch({ "POST /api/evidence/evidence": [400, { detail: "not a VEX" }] });
    expect(await sendVex(f, "r1")).toMatchObject({ tone: "err", title: "Refused (400)", detail: "not a VEX" });
  });

  it("refuses a registration the Registry refused or answered without an id", async () => {
    mockFetch({ "POST /api/registry/products": [409, { detail: "exists" }] });
    await expect(register("/products", {}, "product")).rejects.toThrow("Cannot register the product: exists");
    mockFetch({ "POST /api/registry/products": [201, {}] });
    await expect(register("/products", {}, "product")).rejects.toThrow(/returned no id/);
  });
});
