import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { AiOutcome, AiResultView, invokeCapability } from "./ai-bits";

describe("AI bits", () => {
  it("names every kind of no-answer, splits a flattened header, and shows the detail apart", () => {
    const { rerender } = render(<AiOutcome reason="insufficient" detail="too little" />);
    expect(screen.getByText("declined honestly")).toBeInTheDocument();
    expect(screen.getByText("too little")).toBeInTheDocument();
    rerender(<AiOutcome reason="provider_error: timeout after 60s" />);
    expect(screen.getByText("provider error")).toBeInTheDocument();
    expect(screen.getByText("timeout after 60s")).toBeInTheDocument();
    rerender(<AiOutcome reason="brand_new" />);
    expect(screen.getByText("brand_new")).toBeInTheDocument();
    rerender(<AiResultView r={{ kind: "missing" }} missing="older node" />);
    expect(screen.getByText("older node")).toBeInTheDocument();
  });

  it("reads the answer, the no-answer headers, a missing capability and a refusal", async () => {
    const reply = (status: number, body: string | null, headers: Record<string, string> = {}) =>
      vi.stubGlobal("fetch", vi.fn(async () => new Response(body, { status, headers })));
    reply(204, null, { "X-Themis-AI-Reason": "disabled", "X-Themis-AI-Detail": "off" });
    expect(await invokeCapability("x", { type: "release", ids: ["r"] })).toEqual({ kind: "none", reason: "disabled", detail: "off" });
    reply(404, "{}");
    expect(await invokeCapability("x", { type: "release", ids: ["r"] })).toEqual({ kind: "missing" });
    reply(500, JSON.stringify({ detail: "boom" }));
    await expect(invokeCapability("x", { type: "release", ids: ["r"] })).rejects.toThrow("x returned 500: boom");
  });
});
