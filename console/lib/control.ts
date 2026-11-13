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

import { agentRoster } from "./data";

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
  can_disconnect: boolean;// console-held cred (env/key) — false for a CLI login detected on disk
  login_running: boolean; // a login flow is in progress
}
export interface LoginStatus {
  ok: boolean;
  running: boolean;
  output: string;         // what the provider CLI printed (the URL/code to follow), ANSI-stripped
  url?: string | null;    // the OAuth URL, extracted clean from the CLI output
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

export async function getCoverage(token: string, id: string): Promise<CoverageLedger | null> {
  // Authoritative, file-backed per-category state (coverage_ledger.json), rewritten live
  // by the engine. Backend returns {categories:[]} when the file doesn't exist yet.
  try {
    const d = await request<any>(`/api/engagements/${encodeURIComponent(id)}/coverage`, token);
    return d && Array.isArray(d.categories) ? (d as CoverageLedger) : null;
  } catch {
    return null;
  }
}

export const approve = (token: string, id: string, body: { ids?: string[]; all?: boolean }) =>
  request<CliResult>(`/api/engagements/${encodeURIComponent(id)}/approve`, token, { method: "POST", body: JSON.stringify(body) });

export const stopRun = (token: string, id: string) =>
  request<CliResult>(`/api/engagements/${encodeURIComponent(id)}/stop`, token, { method: "POST", body: "{}" });

export const deleteEngagement = (token: string, id: string) =>
  request<CliResult>(`/api/engagements/${encodeURIComponent(id)}/delete`, token, { method: "POST", body: "{}" });

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

// submit the OAuth code the user pasted back from the authorization page (written to the
// login process's stdin so the CLI can finish the handshake)
export const submitLoginCode = (token: string, provider: string, code: string) =>
  request<{ ok: boolean; submitted?: boolean; error?: string }>(
    `/api/auth/${encodeURIComponent(provider)}/login/code`, token,
    { method: "POST", body: JSON.stringify({ code }) });

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
// dispatch = the orchestrator handing work to a named skill/subagent; return = a subagent's
// result coming back to the orchestrator (both drive the orchestration dispatch log)
export type RunEventKind = "run" | "system" | "tool" | "dispatch" | "return" | "step" | "result" | "error";
export interface RunEvent {
  key: string;
  kind: RunEventKind;
  text: string;
  detail?: string;
  tone?: RunEventTone;
  deferred?: number; // result events: how many actions were deferred for approval
  costUsd?: number;  // result events: the engine's list-price API-equivalent cost — notional on a subscription (not billed)
}

let _seq = 0;
const nextKey = () => `ev-${Date.now().toString(36)}-${(_seq++).toString(36)}`;

const clip = (v: string) => {
  const s = v.replace(/\s+/g, " ").trim();
  return s.length > 90 ? s.slice(0, 89) + "…" : s;
};

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

// run-boundary marker teed by autorun.py: "# --- redstrike autonomous run <iso> ---"
function markerEvents(s: string): RunEvent[] {
  const text = s.replace(/^#+\s*/, "").replace(/-{2,}/g, "").trim() || "run";
  return [{ key: nextKey(), kind: "run", text, tone: "muted" }];
}

// Non-JSON line. In stream-json mode the engine emits only JSON, so a plain-text line here
// is almost always an error claude printed to stderr (e.g. "Error: Session ID … is already
// in use.") before it could stream anything — the kind of failure that otherwise leaves the
// run stuck at the boundary marker with nothing shown. Surface those; skip other chatter.
function plainLineEvents(s: string): RunEvent[] {
  if (/^\s*(error|exception|traceback|fatal|panic)\b/i.test(s) || /\berror:/i.test(s)) {
    return [{ key: nextKey(), kind: "error", tone: "warn", text: s.length > 180 ? s.slice(0, 179) + "…" : s }];
  }
  return []; // chatty non-JSON line — skip, exactly like the CLI does
}

/** Parse one line of the tailed autorun.jsonl into zero or more render-ready events.
 *  (An `assistant` line can carry several tool_use blocks → several events.) */
export function parseRunLine(line: string): RunEvent[] {
  const s = line.trim();
  if (!s) return [];
  if (s.startsWith("#")) return markerEvents(s);
  let o: any;
  try {
    o = JSON.parse(s);
  } catch {
    return plainLineEvents(s);
  }
  return eventsOf(o);
}

/** Render-ready events for one already-parsed autorun.jsonl object. */
function eventsOf(o: any): RunEvent[] {
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
      if (!b || b.type !== "tool_use") continue;
      const inp = b.input || {};
      if (b.name === "Skill") {
        // name the skill being run, not the generic tool
        out.push({ key: nextKey(), kind: "dispatch", text: String(inp.skill || "skill"), detail: inp.args ? clip(String(inp.args)) : undefined });
      } else if (b.name === "Agent" || b.name === "Task") {
        out.push({ key: nextKey(), kind: "dispatch", text: String(inp.subagent_type || "agent"), detail: inp.description ? clip(String(inp.description)) : undefined });
      } else {
        const si = shortInput(inp);
        out.push({ key: nextKey(), kind: "tool", text: b.name || "tool", detail: si || undefined });
      }
    }
    return out;
  }
  if (t === "result") {
    const deferred = Array.isArray(o.deferred_tool_use) ? o.deferred_tool_use.length : o.deferred_tool_use ? 1 : 0;
    const denied = (o.permission_denials || []).length;
    const good = o.subtype === "success";
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
      // An autonomous run LOOPS (invoke → return → resume), so this `result` ends one ENGINE
      // INVOCATION, not necessarily the whole run — label it as such so a mid-run result isn't
      // misread as the run finishing. Whether the RUN is still live is shown by the pid-driven
      // "streaming"/"ended" indicator, not by this line.
      text: `invocation ${o.subtype || "ended"} · ${o.num_turns ?? 0} turns`,
      detail: detail || undefined,
      deferred,
      costUsd: typeof o.total_cost_usd === "number" ? o.total_cost_usd : undefined,
    }];
  }
  return [];
}

/* ============================================================================
   Orchestration — a live view of the engine's run, folded from the SAME stream.
   Steps come from the engine's task list (TaskCreate/TaskUpdate); agents from
   Skill invocations + subagent (Agent/Task) spawns — and, when the engine works a
   step WITHOUT invoking a skill for it, from the step itself, so the task flow
   never lags the task queue. Subagent internals are not in the stream (they run
   opaquely), so an agent is shown spawned → running → returned.
   ========================================================================== */
export type TaskStatus = "pending" | "running" | "done" | "error";
export interface RunTask {
  uid: string;          // the tool_use id of the TaskCreate that made it
  n?: number;           // the engine's "Task #N" number, once the result reveals it
  subject: string;
  activeForm?: string;  // present-continuous label the engine shows while it's active
  status: TaskStatus;
}
export type AgentRole = "orchestrator" | "skill" | "executor" | "reviewer";
export interface RunAgent {
  uid: string;
  name: string;         // skill id / subagent type (a step node: the skill it runs, else its subject)
  role: AgentRole;
  task?: string;
  status: "running" | "done" | "error";
  spawned?: boolean;    // a subagent (Agent/Task tool) — it genuinely RETURNS at its tool_result
  taskUid?: string;     // the engine task this node is working
  fromTask?: boolean;   // made from the task list: no skill call has been seen for that step yet
}
// `cur` = the engine task currently in progress (fold bookkeeping, not rendered)
export interface OrchState { tasks: RunTask[]; agents: RunAgent[]; cur?: string; }
export const emptyOrch = (): OrchState => ({ tasks: [], agents: [] });

const STATUS_MAP: Record<string, TaskStatus> = {
  pending: "pending", todo: "pending",
  in_progress: "running", running: "running", active: "running", started: "running",
  completed: "done", complete: "done", done: "done", finished: "done",
  cancelled: "error", canceled: "error", failed: "error", error: "error", blocked: "error",
};
const isReviewer = (name: string) => /-?verify$/i.test(name);

// Framework skill slugs, longest first, so a step node can be named for the skill it runs.
const SKILL_SLUGS = agentRoster.map((a) => a.slug).sort((a, b) => b.length - a.length);
const slugify = (v: string) => v.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
/** "Run JS analysis on the bundles" → "redstrike-js-analysis" (whole-token match), else null. */
function skillForSubject(subject: string): string | null {
  const s = `-${slugify(subject)}-`;
  const hit = SKILL_SLUGS.find((slug) => s.includes(`-${slug}-`));
  return hit ? `redstrike-${hit}` : null;
}
/** Is this skill named in the task's subject? ("redstrike-osint" ↔ "Passive OSINT recon") */
const skillMatchesTask = (skill: string, task: RunTask) =>
  `-${slugify(task.subject)}-`.includes(`-${slugify(skill.replace(/^redstrike-/i, ""))}-`);
/** work done in the orchestrator's own context: a skill or step node (not the hub, not a subagent) */
const inContext = (a: RunAgent) => a.role !== "orchestrator" && !a.spawned;

/** A task went in_progress: the engine moved on to this step. */
function startTask(s: OrchState, task: RunTask) {
  s.cur = task.uid;
  for (const a of s.agents) {
    if (!inContext(a) || a.status !== "running" || a.taskUid === task.uid) continue;
    // a skill invoked just before this step began, not yet tied to a step, and named for it
    // → it's this step's skill (engines often load the skill, then mark the task started)
    if (!a.taskUid && !a.fromTask && skillMatchesTask(a.name, task)) { a.taskUid = task.uid; continue; }
    // anything else still "running" in-context belongs to an earlier step: the engine moved on.
    // (Without this, a finished skill stayed the only active node while the queue had already
    // advanced — the graph only learned about work from skill calls.)
    a.status = "done";
  }
  if (s.agents.some((a) => inContext(a) && a.taskUid === task.uid && a.status === "running")) return;
  // nothing is working this step yet → show the step itself so the flow matches the queue
  const uid = `task-${task.uid}`;
  const again = s.agents.find((a) => a.uid === uid);
  if (again) { again.status = "running"; return; } // the same step resumed (e.g. next invocation)
  s.agents.push({
    uid, name: skillForSubject(task.subject) ?? task.subject, role: "skill",
    task: task.activeForm || task.subject, status: "running", taskUid: task.uid, fromTask: true,
  });
}

/** A task left in_progress (completed / failed): its in-context node ends with it. */
function endTask(s: OrchState, task: RunTask) {
  for (const a of s.agents) {
    if (inContext(a) && a.taskUid === task.uid && a.status === "running") a.status = task.status === "error" ? "error" : "done";
  }
  if (s.cur === task.uid) s.cur = undefined;
}

// a task-list transition worth narrating in the dispatch log (started / done / failed)
type StepNote = { task: RunTask; phase: "start" | "done" | "error" };

function applyTaskUpdate(s: OrchState, inp: any, notes: StepNote[]): boolean {
  // The engine's TaskUpdate input shape isn't pinned, so match defensively and
  // fall back to the latest still-open task when we can't key it precisely.
  const n = Number(inp?.n ?? inp?.task ?? inp?.task_id ?? inp?.taskId ?? inp?.id ?? inp?.number);
  const st = STATUS_MAP[String(inp?.status ?? inp?.state ?? "").toLowerCase()];
  let task = Number.isFinite(n) ? s.tasks.find((x) => x.n === n) : undefined;
  if (!task && inp?.subject) task = s.tasks.find((x) => x.subject === inp.subject);
  if (!task) task = [...s.tasks].reverse().find((x) => x.status !== "done");
  if (!task) return false;
  const before = task.status;
  let changed = false;
  if (st && task.status !== st) {
    task.status = st;
    changed = true;
    notes.push({ task, phase: st === "running" ? "start" : st === "error" ? "error" : "done" });
  }
  if (inp?.activeForm) {
    const af = String(inp.activeForm);
    if (task.activeForm !== af) {
      task.activeForm = af;
      changed = true;
      for (const a of s.agents) if (a.fromTask && a.taskUid === task.uid) a.task = af; // keep the step caption live
    }
  }
  if (task.status === "running" && before !== "running") startTask(s, task);
  else if (before === "running" && task.status !== "running") endTask(s, task);
  return changed;
}

/** A Skill call: skills run INLINE (one at a time, in the orchestrator's own context). */
function startSkill(s: OrchState, uid: string, skill: string, args: unknown) {
  const caption = args ? String(args) : undefined;
  const role: AgentRole = isReviewer(skill) ? "reviewer" : "skill";
  // the current step is shown by a step node → this skill IS that step's work: take the node over
  const step = s.cur ? s.agents.find((a) => a.fromTask && a.taskUid === s.cur && a.status === "running") : undefined;
  if (step) {
    step.name = skill;
    step.role = role;
    step.fromTask = false;
    if (caption) step.task = caption;
    return;
  }
  // otherwise a new skill supersedes whatever in-context work was running. A skill's own
  // tool_result returns at once (it only loads), so it ends by supersede / step end / run end.
  for (const a of s.agents) if (inContext(a) && a.status === "running") a.status = "done";
  s.agents.push({ uid, name: skill, role, task: caption, status: "running", taskUid: s.cur });
}

/** Fold one already-parsed autorun.jsonl object into the orchestration accumulator (mutates
 *  `s`). Returns whether anything visible changed — most lines (assistant text, ordinary tool
 *  calls and their results) don't, and the caller skips a re-render for those — plus the
 *  subagents that just RETURNED to the orchestrator on this line. */
function foldRunObject(o: any, s: OrchState): { changed: boolean; returned: RunAgent[]; steps: StepNote[] } {
  let changed = false;
  const returned: RunAgent[] = [];
  const steps: StepNote[] = [];
  const type = o?.type;
  if (type === "assistant") {
    for (const b of o.message?.content || []) {
      if (!b || b.type !== "tool_use") continue;
      const uid = String(b.id || nextKey());
      const name = String(b.name || "");
      const inp = b.input || {};
      if (name === "TaskCreate") {
        s.tasks.push({ uid, subject: String(inp.subject || "step"), activeForm: inp.activeForm ? String(inp.activeForm) : undefined, status: "pending" });
        changed = true;
      } else if (name === "TaskUpdate" || name === "TaskStatus") {
        if (applyTaskUpdate(s, inp, steps)) changed = true;
      } else if (name === "Skill") {
        const skill = String(inp.skill || "skill");
        if (skill === "redstrike") {
          if (!s.agents.some((a) => a.role === "orchestrator")) {
            s.agents.push({ uid, name: "redstrike", role: "orchestrator", task: "engagement orchestrator", status: "running" });
            changed = true;
          }
        } else {
          startSkill(s, uid, skill, inp.args);
          changed = true;
        }
      } else if (name === "Agent" || name === "Task") {
        const sub = String(inp.subagent_type || inp.description || "agent");
        s.agents.push({
          uid, name: sub, role: isReviewer(sub) ? "reviewer" : "executor",
          task: inp.description ? String(inp.description) : undefined, status: "running", spawned: true, taskUid: s.cur,
        });
        changed = true;
      }
    }
  } else if (type === "user") {
    const content = o.message?.content;
    if (Array.isArray(content)) {
      for (const b of content) {
        if (!b || b.type !== "tool_result") continue;
        const ref = String(b.tool_use_id || "");
        // a subagent's tool_result IS its report back to the orchestrator
        const ag = s.agents.find((a) => a.uid === ref && a.status === "running");
        if (ag?.spawned) {
          ag.status = b.is_error ? "error" : "done";
          returned.push(ag);
          changed = true;
        }
        // Only a TaskCreate's own result carries its "Task #N". Look the task up FIRST so a
        // large unrelated tool output (scanner dumps, fetched pages) is never stringified and
        // regex-scanned — that was the dominant per-line cost when replaying a long run.
        const task = s.tasks.find((x) => x.uid === ref);
        if (task && task.n == null) {
          const txt = typeof b.content === "string" ? b.content : JSON.stringify(b.content ?? "");
          const m = /Task #(\d+)/.exec(txt);
          if (m) { task.n = Number(m[1]); changed = true; }
        }
      }
    }
  } else if (type === "result") {
    for (const a of s.agents) if (a.status === "running") { a.status = "done"; changed = true; }
    for (const t2 of s.tasks) if (t2.status === "running") { t2.status = "done"; changed = true; }
    s.cur = undefined;
  }
  return { changed, returned, steps };
}

/** Ingest one raw autorun.jsonl line: parse it ONCE, fold it into the orchestration
 *  accumulator (mutates `s`), and return its render-ready events plus whether the
 *  orchestration view changed — so the caller can skip a re-render when it didn't. */
export function ingestRunLine(line: string, s: OrchState): { events: RunEvent[]; orchChanged: boolean } {
  const t = line.trim();
  if (!t) return { events: [], orchChanged: false };
  if (t.startsWith("#")) return { events: markerEvents(t), orchChanged: false };
  let o: any;
  try {
    o = JSON.parse(t);
  } catch {
    return { events: plainLineEvents(t), orchChanged: false };
  }
  const { changed, returned, steps } = foldRunObject(o, s);
  const events = eventsOf(o);
  // the engine's own task list moving: narrate it, so inline work shows in the dispatch log too
  for (const { task, phase } of steps) {
    events.push({
      key: nextKey(), kind: "step", text: task.subject,
      tone: phase === "start" ? "cyan" : phase === "done" ? "ok" : "warn",
      detail: phase === "start" ? "started" : phase === "done" ? "done" : "failed",
    });
  }
  // A subagent reporting back → a "return" line in the dispatch log. Stateless parsing can't
  // tell a subagent's tool_result from any other tool's; the fold knows who was dispatched.
  for (const a of returned) {
    const err = a.status === "error";
    events.push({
      key: nextKey(), kind: "return", text: a.name, tone: err ? "warn" : "ok",
      detail: err ? "returned an error" : a.task ? clip(a.task) : undefined,
    });
  }
  return { events, orchChanged: changed };
}

/* ---- coverage ledger (per-category status, file-backed, authoritative) ---- */
export interface CoverageCategory {
  id: string; name: string; phase?: string;
  skills?: string[]; status?: string; reason?: string; findings_count?: number;
}
export interface CoverageLedger {
  engagement?: string; generated_at?: string; active_phases?: string[];
  categories: CoverageCategory[];
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
