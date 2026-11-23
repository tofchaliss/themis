import { describe, expect, it, vi } from "vitest";
import { apiGet, apiPut, ApiError, getAdminStatus, getWhoAmI, NodeDownError, session } from "./api";
import { mockFetch } from "@/test/helpers";

describe("apiGet", () => {
  it("reads JSON through the same-origin proxy", async () => {
    const calls = mockFetch({ "GET /api/registry/products": [200, [{ id: "p1" }]] });
    expect(await apiGet("registry", "/products")).toEqual([{ id: "p1" }]);
    expect(calls[0]?.url).toBe("/api/registry/products");
  });

  it("reads 404 and 204 as nothing there", async () => {
    mockFetch({ "GET /api/registry/a": [404], "GET /api/registry/b": [204] });
    expect(await apiGet("registry", "/a")).toBeNull();
    expect(await apiGet("registry", "/b")).toBeNull();
  });

  it("names the node that did not answer", async () => {
    mockFetch({ "GET /api/knowledge/feeds": [502] });
    const err = await apiGet("knowledge", "/feeds").catch((e) => e);
    expect(err).toBeInstanceOf(NodeDownError);
    expect((err as NodeDownError).node).toBe("knowledge");
  });

  it("sends the browser to sign in on 401", async () => {
    const gone = vi.spyOn(session, "gone").mockImplementation(() => {});
    mockFetch({ "GET /api/registry/products": [401] });
    await expect(apiGet("registry", "/products")).rejects.toBeInstanceOf(ApiError);
    expect(gone).toHaveBeenCalledOnce();
  });

  it("carries the problem detail of any other failure", async () => {
    mockFetch({ "GET /api/governance/x": [500, { detail: "boom" }] });
    await expect(apiGet("governance", "/x")).rejects.toThrow("governance /x: boom");
  });

  it("falls back to the status when the failure has no JSON body", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("plain", { status: 503 })));
    await expect(apiGet("governance", "/x")).rejects.toThrow("governance /x: 503");
  });
});

describe("apiPut", () => {
  it("sends JSON and reads the answer", async () => {
    const calls = mockFetch({ "PUT /api/registry/products/p1/tags": [200, { tags: ["a"], effective: ["a"] }] });
    expect(await apiPut("registry", "/products/p1/tags", { tags: ["a"] })).toEqual({ tags: ["a"], effective: ["a"] });
    expect(calls[0]?.body).toEqual({ tags: ["a"] });
  });

  it("throws the node's refusal", async () => {
    mockFetch({ "PUT /api/registry/products/p1/tags": [400, { title: "bad tag" }] });
    await expect(apiPut("registry", "/products/p1/tags", { tags: ["X"] })).rejects.toThrow("bad tag");
  });
});

describe("dashboard routes", () => {
  it("reads who is signed in, with safe defaults", async () => {
    mockFetch({ "GET /whoami": [200, { user: "", can_write: false, scopes: ["read"] }] });
    expect(await getWhoAmI()).toEqual({ user: "operator", can_write: false, scopes: ["read"] });
  });

  it("whoami 401 means the session is gone", async () => {
    const gone = vi.spyOn(session, "gone").mockImplementation(() => {});
    mockFetch({ "GET /whoami": [401] });
    await expect(getWhoAmI()).rejects.toBeInstanceOf(ApiError);
    expect(gone).toHaveBeenCalled();
  });

  it("tells 'not an admin' apart from 'unknown'", async () => {
    mockFetch({ "GET /api/dashboard/admin/status": [403] });
    expect(await getAdminStatus()).toEqual({ forbidden: true });
    mockFetch({ "GET /api/dashboard/admin/status": [200, { auth_enabled: true, is_default_password: true }] });
    expect(await getAdminStatus()).toEqual({ auth_enabled: true, is_default_password: true });
    mockFetch({ "GET /api/dashboard/admin/status": [500] });
    expect(await getAdminStatus()).toBeNull();
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new Error("offline"))));
    expect(await getAdminStatus()).toBeNull();
  });

  it("admin status 401 means the session is gone", async () => {
    const gone = vi.spyOn(session, "gone").mockImplementation(() => {});
    mockFetch({ "GET /api/dashboard/admin/status": [401] });
    expect(await getAdminStatus()).toBeNull();
    expect(gone).toHaveBeenCalled();
  });
});
