// A fake same-origin backend: route "METHOD path" → [status, body]. Unknown routes 404.
import type { ReactNode } from "react";
import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { vi } from "vitest";

export type Reply = [number, unknown?];
export type Routes = Record<string, Reply | ((body: unknown) => Reply)>;

export function mockFetch(routes: Routes) {
  const calls: { method: string; url: string; body: unknown }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const method = (init?.method ?? "GET").toUpperCase();
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, url, body });
    const r = routes[`${method} ${url}`];
    const [status, payload] = typeof r === "function" ? r(body) : (r ?? [404, { title: "not found" }]);
    return new Response(status === 204 ? null : JSON.stringify(payload ?? {}), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  });
  vi.stubGlobal("fetch", fn);
  return calls;
}

export function renderWithQuery(ui: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}
