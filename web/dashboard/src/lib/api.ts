// EDR-GUI-02 D5: every call goes through the dashboard's same-origin proxy (/api/<node>/…),
// with today's meanings kept exactly: 401 → the session is gone, go to /login; 502 → that
// node did not answer; 404 → nothing there; 204 → no body.

export type Node = "registry" | "evidence" | "knowledge" | "governance" | "communication" | "intelligence";

/** The node behind the proxy did not answer (the proxy said 502). */
export class NodeDownError extends Error {
  readonly node: Node;
  constructor(node: Node) {
    super(`The ${node} node did not answer`);
    this.name = "NodeDownError";
    this.node = node;
  }
}

/** Any other non-2xx answer, with the problem detail when the node sent one. */
export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/** Where a 401 sends the browser. Replaceable in tests. */
export const session = {
  gone: () => {
    window.location.href = "/login";
  },
};

async function problemDetail(r: Response): Promise<string> {
  try {
    const j = (await r.clone().json()) as { detail?: string; title?: string };
    return j.detail || j.title || `${r.status}`;
  } catch {
    return `${r.status}`;
  }
}

async function send(node: Node, path: string, init?: RequestInit): Promise<Response> {
  const r = await fetch(`/api/${node}${path}`, {
    ...init,
    headers: { Accept: "application/json", ...(init?.body ? { "Content-Type": "application/json" } : {}), ...init?.headers },
  });
  if (r.status === 401) {
    session.gone();
    throw new ApiError(401, "session expired");
  }
  if (r.status === 502) throw new NodeDownError(node);
  return r;
}

/** The raw answer for a caller that reads a non-2xx body itself (the intake receipt, whose
 * refusal is a closed reason plus a detail). 401 and 502 keep their shared meanings. */
export function apiRaw(node: Node, path: string, init?: RequestInit): Promise<Response> {
  return send(node, path, init);
}

/** GET a JSON document. 404 and 204 read as null ("nothing there"). */
export async function apiGet<T>(node: Node, path: string): Promise<T | null> {
  const r = await send(node, path);
  if (r.status === 404 || r.status === 204) return null;
  if (!r.ok) throw new ApiError(r.status, `${node} ${path}: ${await problemDetail(r)}`);
  return (await r.json()) as T;
}

/** PUT a JSON body and read the JSON answer; a non-2xx is an ApiError with its detail. */
export async function apiPut<T>(node: Node, path: string, body: unknown): Promise<T> {
  const r = await send(node, path, { method: "PUT", body: JSON.stringify(body) });
  if (!r.ok) throw new ApiError(r.status, await problemDetail(r));
  return (await r.json()) as T;
}

/** POST a JSON body. Returns the status and the parsed JSON (null when there is none); a
 * non-2xx is an ApiError carrying the node's problem detail. */
export async function apiPost<T>(node: Node, path: string, body?: unknown): Promise<{ status: number; data: T | null }> {
  const r = await send(node, path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok) throw new ApiError(r.status, await problemDetail(r));
  const text = r.status === 204 ? "" : await r.text();
  return { status: r.status, data: text ? (JSON.parse(text) as T) : null };
}

/** DELETE. A non-2xx is an ApiError carrying the node's problem detail. */
export async function apiDelete(node: Node, path: string): Promise<void> {
  const r = await send(node, path, { method: "DELETE" });
  if (!r.ok) throw new ApiError(r.status, await problemDetail(r));
}

/** The dashboard's own routes (not a node): /whoami and the admin status. */
export type WhoAmI = { user: string; scopes?: string[]; can_write: boolean };
export type AdminStatus = { auth_enabled: boolean; is_default_password?: boolean } | { forbidden: true } | null;

export async function getWhoAmI(): Promise<WhoAmI> {
  const r = await fetch("/whoami", { headers: { Accept: "application/json" } });
  if (r.status === 401) {
    session.gone();
    throw new ApiError(401, "session expired");
  }
  const j = (await r.json()) as Partial<WhoAmI>;
  return { user: j.user || "operator", scopes: j.scopes, can_write: j.can_write !== false };
}

/** 403 is a fact about the session (not an admin); a failure means "we do not know" (null). */
export async function getAdminStatus(): Promise<AdminStatus> {
  try {
    const r = await fetch("/api/dashboard/admin/status", { headers: { Accept: "application/json" } });
    if (r.status === 401) {
      session.gone();
      return null;
    }
    if (r.status === 403) return { forbidden: true };
    return r.ok ? ((await r.json()) as AdminStatus) : null;
  } catch {
    return null;
  }
}
