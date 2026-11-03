// Control-plane client for the Redstrike console.
//
// `scripts/console.py` serves a READ-ONLY viewer; `scripts/console_control.py` is an opt-in
// backend that exposes token-gated `/api/*` routes to LAUNCH and STEER an engagement. This
// module is the browser side of that contract. It:
//   * sends the bearer token in the Authorization header (never a cookie — a header can't be
//     attached by a CSRF'd cross-site page, which is exactly the backend's threat model),
//   * consumes the SSE run stream via `fetch` + ReadableStream (the native EventSource can't
//     carry an Authorization header, so it can't be used against a token-gated route),
//   * normalizes the raw `autorun.jsonl` events the backend tails into render-ready rows.
//
// Every request is relative / same-origin, so it resolves against whatever host serves the
// page: under the read-only `console.py` the `/api/*` routes 404 (surfaced as `kind:"offline"`)
// and the UI explains how to start the control plane; under `console_control.py` they work
// once a valid token is supplied.

export interface ControlStatus {
  ok: boolean;
  engagements: string[];
  runs: Record<string, number>; // engagement id -> live run pid
}

export interface PendingItem {
  fingerprint: string;
  tool_name: string;
  command?: string;
  summary?: string;
  deferred_at?: string;
}

export interface InitBody {
  client: string;
  domains: string[];
  authorized_by: string;
  confirm_authorization: boolean;
  cidrs?: string[];
  window_days?: number;
}

export interface RunBody {
  allow?: string[];
  max_turns?: number;
  max_budget?: number;
  resume?: boolean;
}

// Shape the CLI-wrapping routes (`init` / `run` / `approve` / `stop`) return.
export interface CliResult {
  ok: boolean;
  rc?: number;
  stdout?: string;
  stderr?: string;
  pid?: number;
  engagement?: string;
  error?: string;
  note?: string;
}

/* ---- errors ---- */
/* ---- LLM provider auth ---- */
export interface ProviderAuth {
  label: string;
  live: boolean;
  methods: string[];      // e.g. ["oauth_token","api_key"] or ["api_key"]
  connected: boolean;
  via: string | null;     // which method is active ("api_key" | "oauth_token" | "login")
  masked: string | null;  // last-4 hint — never the secret
  source: string | null;  // "ui" (set here) | "env" (present at startup)
  model?: string;         // providers with a model var
  models: string[];       // dropdown options
  can_login: boolean;     // a click-to-login flow exists
  login_running: boolean; // a login flow is in progress
}
export interface LoginStatus {
  ok: boolean;
  running: boolean;
  output: string;         // what the provider CLI printed (the URL/code to follow)
  connected: boolean;
}
export interface AuthSnapshot {
  providers: Record<string, ProviderAuth>;
  engine: string;
}
export interface SetAuthBody {
  method?: string;
  value?: string;
  model?: string;
  action?: "disconnect";
}

export type ControlErrorKind =
  | "offline"      // nothing answering the /api route (read-only console, or plane down)
  | "unauthorized" // 401 — token missing/rejected
  | "forbidden"    // 403 — host/origin not localhost
  | "conflict"     // 409 — a run is already in progress
  | "http"         // other non-2xx with a JSON {error}
  | "network";     // fetch threw (connection refused mid-session)

export class ControlError extends Error {
  kind: ControlErrorKind;
  status: number;
  body?: unknown;
  constructor(kind: ControlErrorKind, status: number, message: string, body?: unknown) {
    super(message);
    this.name = "ControlError";
    this.kind = kind;
    this.status = status;
    this.body = body;
  }
}

/* ---- request core ---- */
async function safeJson(res: Response): Promise<any> {
  try {
    return await res.json();
  } catch {
    return undefined;
  }
}

async function request<T>(path: string, token: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${token}`);
  if (init.body != null && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");

  let res: Response;
  try {
    res = await fetch(path, { ...init, headers, cache: "no-store" });
  } catch {
    // connection refused / DNS / network — the plane isn't reachable from this page
    throw new ControlError("network", 0, "control plane not reachable");
  }

  if (res.status === 401) throw new ControlError("unauthorized", 401, "token rejected");
  if (res.status === 403) throw new ControlError("forbidden", 403, "request host/origin not localhost");

  if (res.status === 404) {
    // The control plane answers unknown API routes with JSON {error}; the read-only console.py
    // falls through to a static 404 (non-JSON). Treat the latter as "plane not running".
    const body = await safeJson(res);
    if (body && typeof body === "object") throw new ControlError("http", 404, (body as any).error || "not found", body);
    throw new ControlError("offline", 404, "control plane not running");
  }

  const body = await safeJson(res);
  if (res.status === 409) throw new ControlError("conflict", 409, (body as any)?.error || "run already in progress", body);
  if (!res.ok) throw new ControlError("http", res.status, (body as any)?.error || `HTTP ${res.status}`, body);
  return body as T;
}

/* ---- endpoints ---- */
export const getStatus = (token: string) => request<ControlStatus>("/api/status", token);

export const initEngagement = (token: string, body: InitBody) =>
  request<CliResult>("/api/engagements", token, { method: "POST", body: JSON.stringify(body) });

export const runEngagement = (token: string, id: string, body: RunBody) =>
  request<CliResult>(`/api/engagements/${encodeURIComponent(id)}/run`, token, { method: "POST", body: JSON.stringify(body) });

export async function getApprovals(token: string, id: string): Promise<PendingItem[]> {
  // The backend returns the raw approvals_pending.json — a bare array when the file exists,
  // or {pending:[]} when it doesn't. Accept both shapes.
  const data = await request<any>(`/api/engagements/${encodeURIComponent(id)}/approvals`, token);
  if (Array.isArray(data)) return data as PendingItem[];
  if (data && Array.isArray(data.pending)) return data.pending as PendingItem[];
  return [];
}

export const approve = (token: string, id: string, body: { ids?: string[]; all?: boolean }) =>
  request<CliResult>(`/api/engagements/${encodeURIComponent(id)}/approve`, token, { method: "POST", body: JSON.stringify(body) });

export const stopRun = (token: string, id: string) =>
  request<CliResult>(`/api/engagements/${encodeURIComponent(id)}/stop`, token, { method: "POST", body: "{}" });

/* ---- LLM provider auth (set a key/token the launched runs inherit — no .env editing) ---- */
export const getAuth = (token: string) => request<AuthSnapshot>("/api/auth", token);

export const setProviderAuth = (token: string, provider: string, body: SetAuthBody) =>
  request<AuthSnapshot>(`/api/auth/${encodeURIComponent(provider)}`, token, { method: "POST", body: JSON.stringify(body) });

export const disconnectProvider = (token: string, provider: string) =>
  request<AuthSnapshot>(`/api/auth/${encodeURIComponent(provider)}`, token, { method: "POST", body: JSON.stringify({ action: "disconnect" }) });

export const setModel = (token: string, provider: string, model: string) =>
  request<AuthSnapshot>(`/api/auth/${encodeURIComponent(provider)}`, token, { method: "POST", body: JSON.stringify({ action: "set_model", model }) });

// click-to-login: start the provider CLI's own browser/OAuth flow, then poll for completion
export const startLogin = (token: string, provider: string) =>
  request<LoginStatus>(`/api/auth/${encodeURIComponent(provider)}/login`, token, { method: "POST", body: "{}" });

export const getLoginStatus = (token: string, provider: string) =>
  request<LoginStatus>(`/api/auth/${encodeURIComponent(provider)}/login`, token);

/* ---- SSE run stream (fetch-based; EventSource can't set Authorization) ---- */
export async function openRunStream(
  token: string,
  id: string,
  onLine: (line: string) => void,
  signal: AbortSignal,
): Promise<void> {
  let res: Response;
  try {
    res = await fetch(`/api/engagements/${encodeURIComponent(id)}/stream`, {
      headers: { Authorization: `Bearer ${token}`, Accept: "text/event-stream" },
      cache: "no-store",
      signal,
    });
  } catch (e) {
    if ((e as any)?.name === "AbortError") return;
    throw new ControlError("network", 0, "stream not reachable");
  }
  if (res.status === 401) throw new ControlError("unauthorized", 401, "token rejected");
  if (!res.ok || !res.body) throw new ControlError("http", res.status, `stream HTTP ${res.status}`);

  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  try {
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let nl: number;
      // SSE frames are separated by a blank line; each frame may carry "data:" and ":" lines.
      while ((nl = buf.indexOf("\n\n")) >= 0) {
        const frame = buf.slice(0, nl);
        buf = buf.slice(nl + 2);
        for (const ln of frame.split("\n")) {
          if (ln.startsWith("data:")) onLine(ln.slice(5).replace(/^ /, ""));
          // ": connected" / keepalive comment frames are ignored
        }
      }
    }
  } catch (e) {
    if ((e as any)?.name !== "AbortError") throw e;
  } finally {
    try {
      reader.cancel();
    } catch {
      /* already closed */
    }
  }
}

/* ---- autorun.jsonl event parsing ---- */
export type RunEventTone = "ok" | "warn" | "muted" | "cyan";
export type RunEventKind = "run" | "system" | "tool" | "result";
export interface RunEvent {
  key: string;
  kind: RunEventKind;
  text: string;
  detail?: string;
  tone?: RunEventTone;
  deferred?: number; // result events: how many actions were deferred for approval
}

let _seq = 0;
const nextKey = () => `ev-${Date.now().toString(36)}-${(_seq++).toString(36)}`;

const INPUT_KEYS = ["command", "url", "file_path", "pattern", "path", "description", "prompt"];
function shortInput(inp: Record<string, any>): string {
  for (const k of INPUT_KEYS) {
    if (inp && inp[k] != null) {
      const v = String(inp[k]).replace(/\s+/g, " ").trim();
      return v.length > 90 ? v.slice(0, 89) + "…" : v;
    }
  }
  return "";
}

/** Parse one line of the tailed autorun.jsonl into zero or more render-ready events.
 *  (An `assistant` line can carry several tool_use blocks → several events.) */
export function parseRunLine(line: string): RunEvent[] {
  const s = line.trim();
  if (!s) return [];
  if (s.startsWith("#")) {
    // run-boundary marker teed by autorun.py: "# --- redstrike autonomous run <iso> ---"
    const text = s.replace(/^#+\s*/, "").replace(/-{2,}/g, "").trim() || "run";
    return [{ key: nextKey(), kind: "run", text, tone: "muted" }];
  }
  let o: any;
  try {
    o = JSON.parse(s);
  } catch {
    return []; // chatty non-JSON line — skip, exactly like the CLI does
  }
  const t = o?.type;
  if (t === "system" && o.subtype === "init") {
    const skills = (o.slash_commands || []).filter((x: any) => String(x).toLowerCase().includes("redstrike")).length;
    const mcp = (o.mcp_servers || []).length;
    return [{
      key: nextKey(),
      kind: "system",
      tone: "cyan",
      text: `engine up · ${o.model ?? "model"}`,
      detail: `${skills} redstrike skills · mcp ${mcp}`,
    }];
  }
  if (t === "assistant") {
    const out: RunEvent[] = [];
    for (const b of o.message?.content || []) {
      if (b && b.type === "tool_use") {
        const si = shortInput(b.input || {});
        out.push({ key: nextKey(), kind: "tool", text: b.name || "tool", detail: si || undefined });
      }
    }
    return out;
  }
  if (t === "result") {
    const deferred = Array.isArray(o.deferred_tool_use) ? o.deferred_tool_use.length : o.deferred_tool_use ? 1 : 0;
    const denied = (o.permission_denials || []).length;
    const good = o.subtype === "success";
    const cost = typeof o.total_cost_usd === "number" ? `$${o.total_cost_usd.toFixed(4)}` : "$0";
    const detail = [
      o.stop_reason ? `stop: ${o.stop_reason}` : "",
      denied ? `${denied} denied` : "",
      deferred ? `${deferred} deferred` : "",
    ]
      .filter(Boolean)
      .join(" · ");
    return [{
      key: nextKey(),
      kind: "result",
      tone: good ? "ok" : "warn",
      text: `run ${o.subtype || "ended"} · ${o.num_turns ?? 0} turns · ${cost}`,
      detail: detail || undefined,
      deferred,
    }];
  }
  return [];
}

/* ---- bootstrap: same-origin token hand-off so the console self-connects (no paste) ---- */
export async function getBootstrapToken(): Promise<string | null> {
  // Unauthenticated by design: the control plane only answers this to a same-origin request
  // (Host/Origin-guarded). A cross-origin page is rejected, so it can't read the token.
  try {
    const res = await fetch("/api/bootstrap", { cache: "no-store" });
    if (!res.ok) return null;
    const d = await res.json();
    return typeof d?.token === "string" && d.token ? d.token : null;
  } catch {
    return null;
  }
}

/* ---- token persistence (sessionStorage: a secret, cleared when the tab closes) ---- */
const TOKEN_KEY = "redstrike.controlToken";
export function loadToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) || "";
  } catch {
    return "";
  }
}
export function saveToken(t: string): void {
  try {
    if (t) sessionStorage.setItem(TOKEN_KEY, t);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* private mode / blocked */
  }
}
