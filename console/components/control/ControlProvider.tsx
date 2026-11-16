"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import * as api from "@/lib/control";
import type { ControlStatus, PendingItem, RunEvent, InitBody, RunBody, CliResult, AuthSnapshot, SetAuthBody, LoginStatus, OrchState, CoverageLedger } from "@/lib/control";
import { ControlError, loadToken, saveToken, ingestRunLine, emptyOrch, getCoverage } from "@/lib/control";

// Connection state machine:
//   unknown → haven't probed yet
//   offline → nothing answering /api (read-only console.py, or the plane is down)
//   locked  → plane is up but no valid token yet (401)
//   ready   → /api/status returned 200
export type Conn = "unknown" | "offline" | "locked" | "ready";

const MAX_EVENTS = 500; // cap the in-memory run log
const EMPTY_ENGAGEMENTS: string[] = [];
const EMPTY_RUNS: Record<string, number> = {};

// The control context: connection, status, selection, slow-changing run state and actions.
// The HOT per-line stream state (events + orchestration) lives in a separate context — see
// `useRunStream` — so a busy run only re-renders the views that actually draw the stream,
// not every `useControl()` consumer (sidebar, launch panel, approvals, …) on every line.
interface ControlCtx {
  conn: Conn;
  token: string;
  status: ControlStatus | null;
  engagements: string[];
  runs: Record<string, number>;
  activeId: string;
  setActiveId: (id: string) => void;
  running: boolean;
  coverage: CoverageLedger | null;
  pending: PendingItem[];
  lastError: string;
  busy: boolean;
  connect: (token: string) => Promise<boolean>;
  disconnect: () => void;
  refresh: () => Promise<void>;
  doInit: (body: InitBody) => Promise<CliResult | null>;
  doRun: (body: RunBody) => Promise<boolean>;
  doRunFor: (id: string, body: RunBody) => Promise<boolean>;
  doApprove: (ids: string[] | "all") => Promise<boolean>;
  doResume: () => Promise<boolean>;
  doStop: () => Promise<void>;
  doDelete: (id: string) => Promise<boolean>;
  clearEvents: () => void;
  auth: AuthSnapshot | null;
  refreshAuth: () => Promise<void>;
  setProviderAuth: (provider: string, body: SetAuthBody) => Promise<boolean>;
  disconnectProvider: (provider: string) => Promise<void>;
  setModel: (provider: string, model: string) => Promise<boolean>;
  startLogin: (provider: string) => Promise<LoginStatus | null>;
  pollLogin: (provider: string) => Promise<LoginStatus | null>;
  submitLoginCode: (provider: string, code: string) => Promise<boolean>;
}

interface RunStreamCtx {
  events: RunEvent[];
  orch: OrchState;
}

const Ctx = createContext<ControlCtx | null>(null);
const StreamCtx = createContext<RunStreamCtx | null>(null);

function msgOf(e: unknown): string {
  if (e instanceof ControlError) return e.message;
  return e instanceof Error ? e.message : String(e);
}

const isHidden = () => typeof document !== "undefined" && document.visibilityState === "hidden";

const capEvents = (a: RunEvent[]) => (a.length > MAX_EVENTS ? a.slice(a.length - MAX_EVENTS) : a);

/** useState whose setter drops a value structurally identical to the current one. The polls
 *  (status / approvals / coverage) usually return the same JSON; without this every poll made
 *  a new reference and re-rendered every consumer even though nothing changed. */
function useStableState<T>(initial: T): [T, (next: T) => void] {
  const [val, setVal] = useState<T>(initial);
  const sig = useRef<string>(JSON.stringify(initial));
  const set = useCallback((next: T) => {
    const s = JSON.stringify(next);
    if (s === sig.current) return;
    sig.current = s;
    setVal(next);
  }, []);
  return [val, set];
}

export function ControlProvider({ children }: { children: React.ReactNode }) {
  const [conn, setConn] = useState<Conn>("unknown");
  const [token, setToken] = useState("");
  const [status, setStatus] = useStableState<ControlStatus | null>(null);
  const [activeId, setActiveIdState] = useState("");
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [orch, setOrch] = useState<OrchState>(emptyOrch);
  const [coverage, setCoverage] = useStableState<CoverageLedger | null>(null);
  const [pending, setPending] = useStableState<PendingItem[]>([]);
  const orchRef = useRef<OrchState>(emptyOrch()); // mutable accumulator folded per stream line
  const [lastError, setLastError] = useState("");
  const [busy, setBusy] = useState(false);
  const [auth, setAuthState] = useState<AuthSnapshot | null>(null);
  const [lastRunConfig, setLastRunConfig] = useState<RunBody>({ allow: [], max_turns: 200, max_budget: 20 });

  const tokenRef = useRef(token);
  tokenRef.current = token;
  const activeIdRef = useRef(activeId);
  activeIdRef.current = activeId;
  const streamAbort = useRef<AbortController | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // latest status + startStream, read from inside the stream's async body without stale closures
  const statusRef = useRef<ControlStatus | null>(null);
  statusRef.current = status;
  const startStreamRef = useRef<((id: string) => void) | null>(null);

  // Stream → render batching. Lines are folded into refs as they arrive (cheap); React state
  // is updated at most once per animation frame. A replay of a long run is thousands of lines
  // in a burst — this turns thousands of renders (each copying the event array) into a few.
  const pendingEvents = useRef<RunEvent[]>([]); // events parsed since the last flush
  const orchDirty = useRef(false);              // orchRef changed since the last flush
  const replaceOnFlush = useRef(false);         // next flush REPLACES the view (fresh replay) instead of appending
  const resultFor = useRef<string | null>(null); // an invocation `result` arrived for this engagement
  const flushRaf = useRef<number | null>(null);

  const engagements = status?.engagements ?? EMPTY_ENGAGEMENTS;
  const runs = status?.runs ?? EMPTY_RUNS;
  const running = !!(activeId && runs[activeId] != null);

  /* ---- probing / connection ---- */
  const probe = useCallback(async (tok: string): Promise<Conn> => {
    try {
      const st = await api.getStatus(tok);
      setStatus(st);
      setConn("ready");
      setLastError("");
      setActiveIdState((cur) => cur || Object.keys(st.runs)[0] || st.engagements[0] || "");
      return "ready";
    } catch (e) {
      if (e instanceof ControlError && e.kind === "unauthorized") {
        setConn("locked");
        if (tok) setLastError("Token rejected."); // empty-token presence probe → no scary message
        return "locked";
      }
      if (e instanceof ControlError && e.kind === "forbidden") {
        setConn("offline");
        setLastError("Blocked: request host/origin is not localhost.");
        return "offline";
      }
      setConn("offline");
      setStatus(null);
      return "offline";
    }
  }, [setStatus]);

  const refresh = useCallback(async () => {
    if (!tokenRef.current) return;
    try {
      const st = await api.getStatus(tokenRef.current);
      setStatus(st);
      setConn("ready");
    } catch (e) {
      if (e instanceof ControlError && e.kind === "unauthorized") setConn("locked");
      else if (e instanceof ControlError && (e.kind === "offline" || e.kind === "network")) setConn("offline");
    }
  }, [setStatus]);

  const refreshApprovals = useCallback(async (id: string) => {
    if (!tokenRef.current || !id) {
      setPending([]);
      return;
    }
    try {
      const p = await api.getApprovals(tokenRef.current, id);
      if (activeIdRef.current === id) setPending(p); // drop a late answer for a de-selected engagement
    } catch {
      /* keep the last-known list on a transient error */
    }
  }, [setPending]);

  const refreshCoverage = useCallback(async (id: string) => {
    const c = await getCoverage(tokenRef.current, id);
    if (activeIdRef.current === id) setCoverage(c);
  }, [setCoverage]);

  /* ---- stream → render flush ---- */
  const flushStream = useCallback(() => {
    flushRaf.current = null;
    const replace = replaceOnFlush.current;
    replaceOnFlush.current = false;
    if (replace || orchDirty.current) {
      orchDirty.current = false;
      const o = orchRef.current;
      // snapshot the mutable accumulator — fresh arrays AND fresh items, since the fold
      // mutates task/agent objects in place (a status flip must read as a new value)
      setOrch({ tasks: o.tasks.map((t) => ({ ...t })), agents: o.agents.map((a) => ({ ...a })) });
    }
    const batch = pendingEvents.current;
    pendingEvents.current = [];
    if (replace) setEvents(capEvents(batch));
    else if (batch.length) setEvents((prev) => capEvents(prev.length ? prev.concat(batch) : batch));
    const rid = resultFor.current;
    if (rid) {
      // One engine INVOCATION finished. An autonomous run LOOPS — the engine resumes with
      // another invocation (and another `result` later), so a result is NOT run-over. Re-poll
      // status (keeps `running`/pid authoritative) + approvals (catch deferrals), but KEEP
      // TAILING so the next invocation streams in instead of freezing the log at "run success".
      // Deduped per flush, so a replay that crosses many invocations polls once, not N times.
      resultFor.current = null;
      void refresh();
      void refreshApprovals(rid);
    }
  }, [refresh, refreshApprovals]);

  const scheduleFlush = useCallback(() => {
    if (flushRaf.current != null) return;
    // Hidden tab: keep folding into refs but don't render — the visibilitychange handler
    // flushes everything in ONE pass when the operator comes back to the tab.
    if (isHidden()) return;
    flushRaf.current = requestAnimationFrame(flushStream);
  }, [flushStream]);

  // drop anything buffered for the current view (a superseded stream, or a reset)
  const dropBuffered = useCallback(() => {
    if (flushRaf.current != null) {
      cancelAnimationFrame(flushRaf.current);
      flushRaf.current = null;
    }
    pendingEvents.current = [];
    orchDirty.current = false;
    replaceOnFlush.current = false;
    resultFor.current = null;
  }, []);

  // clear the run log + orchestration view immediately (engagement switch, fresh launch)
  const resetStreamView = useCallback(() => {
    dropBuffered();
    orchRef.current = emptyOrch();
    setOrch(emptyOrch());
    setEvents([]);
  }, [dropBuffered]);

  /* ---- SSE stream lifecycle ---- */
  const stopStream = useCallback(() => {
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current);
      reconnectTimer.current = null;
    }
    dropBuffered();
    if (streamAbort.current) {
      streamAbort.current.abort();
      streamAbort.current = null;
    }
  }, [dropBuffered]);

  const startStream = useCallback(
    (id: string) => {
      stopStream();
      // The backend REPLAYS the current run from the top on connect, and folding isn't
      // idempotent — so rebuild from empty each time. The accumulator resets now, but the
      // VISIBLE view is only replaced by the first flush of the replay, so a reconnect swaps
      // old→new in one paint instead of flashing an empty view while the replay is in flight.
      orchRef.current = emptyOrch();
      replaceOnFlush.current = true;
      const ac = new AbortController();
      streamAbort.current = ac;
      void (async () => {
        try {
          await api.openRunStream(
            tokenRef.current,
            id,
            (line) => {
              if (streamAbort.current !== ac) return; // superseded — drop late lines
              // fold EVERY line into the accumulator (incl. task/result lines the terminal
              // parser skips); state is rendered by the batched flush, not per line
              const { events: evs, orchChanged } = ingestRunLine(line, orchRef.current);
              if (orchChanged) orchDirty.current = true;
              if (evs.length) {
                const pe = pendingEvents.current;
                for (const ev of evs) pe.push(ev);
                // bound the buffer while a hidden tab isn't flushing (amortized trim)
                if (pe.length > MAX_EVENTS * 2) pe.splice(0, pe.length - MAX_EVENTS);
                if (evs.some((e) => e.kind === "result")) resultFor.current = id;
              }
              if (orchChanged || evs.length || replaceOnFlush.current) scheduleFlush();
            },
            ac.signal,
          );
        } catch (e) {
          if (e instanceof ControlError && e.kind === "unauthorized") {
            setConn("locked");
            return;
          }
        }
        if (ac.signal.aborted || streamAbort.current !== ac) return;
        // A stream that ended without a single line still owes the view its reset (e.g. the
        // run log is gone) — apply it so the view never shows a previous replay as current.
        if (replaceOnFlush.current) scheduleFlush();
        // The backend closed the stream — either because there's no run log YET (the engine is
        // still booting right after launch, so the tail returns "no-run" immediately) or because
        // a long run hit the tail's deadline. If this is still the active stream (not superseded
        // or aborted by us) AND a run is live for this engagement, reopen shortly so the live view
        // keeps following WITHOUT a manual refresh. The backend replays the current run from the
        // top on reconnect, so re-folding from empty stays correct. If no run is live, we stop.
        let stillLive = false;
        try {
          const st = await api.getStatus(tokenRef.current);
          setStatus(st);
          setConn("ready");
          stillLive = st.runs[id] != null;
        } catch {
          /* leave stillLive false — a probe failure shouldn't spin a reconnect loop */
        }
        if (stillLive && !ac.signal.aborted && streamAbort.current === ac) {
          reconnectTimer.current = setTimeout(() => {
            if (!ac.signal.aborted && streamAbort.current === ac) startStreamRef.current?.(id);
          }, 1200);
        }
      })();
    },
    [stopStream, scheduleFlush, setStatus],
  );
  startStreamRef.current = startStream;

  /* ---- boot: auto-connect via same-origin token hand-off, else presence probe ---- */
  useEffect(() => {
    void (async () => {
      const saved = loadToken();
      if (saved) {
        setToken(saved);
        if ((await probe(saved)) === "ready") return;
      }
      // self-connect: the control plane hands its token to its own (same-origin) page — no paste
      const boot = await api.getBootstrapToken();
      if (boot) {
        setToken(boot);
        saveToken(boot);
        if ((await probe(boot)) === "ready") return;
      }
      void probe(""); // 401 → plane up (locked, manual entry); network/404 → offline
    })();
  }, [probe]);

  /* ---- polls (paused while the tab is hidden; caught up on return — see below) ---- */
  // status: tracks live run pids
  useEffect(() => {
    if (conn !== "ready") return;
    const t = setInterval(() => {
      if (!isHidden()) void refresh();
    }, 5000);
    return () => clearInterval(t);
  }, [conn, refresh]);

  // approvals for the active engagement
  useEffect(() => {
    if (conn !== "ready" || !activeId) {
      setPending([]);
      return;
    }
    void refreshApprovals(activeId);
    const t = setInterval(() => {
      if (!isHidden()) void refreshApprovals(activeId);
    }, 4000);
    return () => clearInterval(t);
  }, [conn, activeId, refreshApprovals, setPending]);

  // the coverage ledger (authoritative per-category run state)
  useEffect(() => {
    if (conn !== "ready" || !activeId) {
      setCoverage(null);
      return;
    }
    void refreshCoverage(activeId);
    const t = setInterval(() => {
      if (!isHidden()) void refreshCoverage(activeId);
    }, 4000);
    return () => clearInterval(t);
  }, [conn, activeId, refreshCoverage, setCoverage]);

  // back in view: render whatever the stream folded while hidden in ONE pass, and catch the
  // paused polls up immediately instead of waiting for their next tick
  useEffect(() => {
    if (typeof document === "undefined") return;
    const onVisible = () => {
      if (isHidden()) return;
      const catchUp = conn === "ready";
      // the catch-up below re-reads status + approvals anyway, so absorb a `result` that
      // arrived while hidden instead of letting the flush fetch them a second time
      if (catchUp) resultFor.current = null;
      if (pendingEvents.current.length || orchDirty.current || replaceOnFlush.current || resultFor.current) scheduleFlush();
      if (!catchUp) return;
      void refresh();
      if (activeId) {
        void refreshApprovals(activeId);
        void refreshCoverage(activeId);
      }
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, [conn, activeId, refresh, refreshApprovals, refreshCoverage, scheduleFlush]);

  /* ---- (re)open the stream on connect/select so a refresh or late join replays the
     current run; it reopens when a run starts/stops (runPid flips). The backend returns
     immediately when there's no run log, so this never holds an idle socket. ---- */
  const runPid = status?.runs?.[activeId];
  useEffect(() => {
    if (conn === "ready" && activeId) {
      startStream(activeId);
      return () => stopStream();
    }
    return;
  }, [conn, activeId, runPid, startStream, stopStream]);

  /* ---- tear down the stream on unmount ---- */
  useEffect(() => () => stopStream(), [stopStream]);

  /* ---- actions ---- */
  const connect = useCallback(
    async (tok: string) => {
      const t = tok.trim();
      setToken(t);
      saveToken(t);
      const c = await probe(t);
      return c === "ready";
    },
    [probe],
  );

  const disconnect = useCallback(() => {
    stopStream();
    resetStreamView();
    setToken("");
    saveToken("");
    setStatus(null);
    setPending([]);
    setLastError("");
    setConn("locked");
  }, [stopStream, resetStreamView, setStatus, setPending]);

  const setActiveId = useCallback(
    (id: string) => {
      stopStream();
      resetStreamView(); // the run log is per-engagement
      setCoverage(null);
      setActiveIdState(id);
    },
    [stopStream, resetStreamView, setCoverage],
  );

  const doInit = useCallback(
    async (body: InitBody): Promise<CliResult | null> => {
      setBusy(true);
      setLastError("");
      try {
        const before = new Set(statusRef.current?.engagements ?? []);
        const r = await api.initEngagement(tokenRef.current, body);
        if (!r.ok) setLastError((r.stderr || r.error || "init failed").trim());
        // Refresh the engagement list AND resolve the id of the one just scaffolded, so a
        // "create & launch" can start the run on the FIRST click. The backend's init doesn't
        // echo the id, and the component's `engagements` closure is stale this tick, so diff a
        // freshly-fetched list against the pre-init one instead of relying on a slug guess.
        try {
          const st = await api.getStatus(tokenRef.current);
          setStatus(st);
          setConn("ready");
          if (r.ok && !r.engagement) {
            const added = st.engagements.filter((e) => !before.has(e));
            if (added.length === 1) r.engagement = added[0];
          }
        } catch {
          /* couldn't refresh — caller falls back to its slug match */
        }
        return r;
      } catch (e) {
        setLastError(msgOf(e));
        return null;
      } finally {
        setBusy(false);
      }
    },
    [setStatus],
  );

  // Launch a run against an EXPLICIT engagement id — lets a fresh "create & launch"
  // start the run the same tick it scaffolds, before the new id has become `activeId`.
  const doRunFor = useCallback(
    async (id: string, body: RunBody): Promise<boolean> => {
      if (!id) {
        setLastError("Select an engagement first.");
        return false;
      }
      setBusy(true);
      setLastError("");
      try {
        if (!body.resume) resetStreamView();
        const r = await api.runEngagement(tokenRef.current, id, body);
        setLastRunConfig({ allow: body.allow, max_turns: body.max_turns, max_budget: body.max_budget });
        await refresh(); // pid shows up fast → the stream effect opens the tail
        return !!r.ok;
      } catch (e) {
        if (e instanceof ControlError && e.kind === "conflict") setLastError("A run is already in progress for this engagement.");
        else setLastError(msgOf(e));
        return false;
      } finally {
        setBusy(false);
      }
    },
    [refresh, resetStreamView],
  );

  const doRun = useCallback((body: RunBody) => doRunFor(activeId, body), [doRunFor, activeId]);

  const doApprove = useCallback(
    async (ids: string[] | "all"): Promise<boolean> => {
      if (!activeId) return false;
      setBusy(true);
      setLastError("");
      try {
        const body = ids === "all" ? { all: true } : { ids };
        const r = await api.approve(tokenRef.current, activeId, body);
        if (!r.ok) setLastError((r.stderr || "approve failed").trim());
        await refreshApprovals(activeId);
        return !!r.ok;
      } catch (e) {
        setLastError(msgOf(e));
        return false;
      } finally {
        setBusy(false);
      }
    },
    [activeId, refreshApprovals],
  );

  const doResume = useCallback(() => doRun({ ...lastRunConfig, resume: true }), [doRun, lastRunConfig]);

  const doStop = useCallback(async () => {
    if (!activeId) return;
    setBusy(true);
    try {
      await api.stopRun(tokenRef.current, activeId);
      await refresh();
    } catch (e) {
      setLastError(msgOf(e));
    } finally {
      setBusy(false);
    }
  }, [activeId, refresh]);

  const doDelete = useCallback(
    async (id: string): Promise<boolean> => {
      if (!id) return false;
      setBusy(true);
      setLastError("");
      try {
        const r = await api.deleteEngagement(tokenRef.current, id);
        if (!r.ok) {
          setLastError((r.error || r.stderr || "delete failed").trim());
          return false;
        }
        if (id === activeId) setActiveId(""); // we were viewing it — clear the live selection
        await refresh();
        return true;
      } catch (e) {
        if (e instanceof ControlError && e.kind === "conflict") setLastError("A run is in progress — stop it first.");
        else setLastError(msgOf(e));
        return false;
      } finally {
        setBusy(false);
      }
    },
    [activeId, refresh, setActiveId],
  );

  const clearEvents = useCallback(() => {
    pendingEvents.current = []; // don't let a pending flush re-append what was just cleared
    setEvents([]);
  }, []);

  /* ---- LLM provider auth ---- */
  const refreshAuth = useCallback(async () => {
    if (!tokenRef.current) return;
    try {
      setAuthState(await api.getAuth(tokenRef.current));
    } catch {
      /* transient — keep the last-known snapshot */
    }
  }, []);

  const setProviderAuth = useCallback(async (provider: string, body: SetAuthBody): Promise<boolean> => {
    try {
      setAuthState(await api.setProviderAuth(tokenRef.current, provider, body));
      setLastError("");
      return true;
    } catch (e) {
      setLastError(msgOf(e));
      return false;
    }
  }, []);

  const disconnectProvider = useCallback(async (provider: string) => {
    try {
      setAuthState(await api.disconnectProvider(tokenRef.current, provider));
    } catch (e) {
      setLastError(msgOf(e));
    }
  }, []);

  const setModel = useCallback(async (provider: string, model: string): Promise<boolean> => {
    try {
      setAuthState(await api.setModel(tokenRef.current, provider, model));
      return true;
    } catch (e) {
      setLastError(msgOf(e));
      return false;
    }
  }, []);

  const startLogin = useCallback(async (provider: string): Promise<LoginStatus | null> => {
    try {
      return await api.startLogin(tokenRef.current, provider);
    } catch (e) {
      setLastError(msgOf(e));
      return null;
    }
  }, []);

  const pollLogin = useCallback(async (provider: string): Promise<LoginStatus | null> => {
    try {
      const s = await api.getLoginStatus(tokenRef.current, provider);
      if (s.connected) void refreshAuth();
      return s;
    } catch {
      return null;
    }
  }, [refreshAuth]);

  const submitLoginCode = useCallback(async (provider: string, code: string): Promise<boolean> => {
    try {
      const r = await api.submitLoginCode(tokenRef.current, provider, code);
      if (!r.ok) setLastError(r.error || "could not submit the code");
      return !!r.ok;
    } catch (e) {
      setLastError(msgOf(e));
      return false;
    }
  }, []);

  // load provider auth once the plane is reachable
  useEffect(() => {
    if (conn === "ready") void refreshAuth();
  }, [conn, refreshAuth]);

  // Memoized so consumers re-render only when something they can see actually changed —
  // not on every provider render (which, during a run, happens once per stream flush).
  const value = useMemo<ControlCtx>(
    () => ({
      conn,
      token,
      status,
      engagements,
      runs,
      activeId,
      setActiveId,
      running,
      coverage,
      pending,
      lastError,
      busy,
      connect,
      disconnect,
      refresh,
      doInit,
      doRun,
      doRunFor,
      doApprove,
      doResume,
      doStop,
      doDelete,
      clearEvents,
      auth,
      refreshAuth,
      setProviderAuth,
      disconnectProvider,
      setModel,
      startLogin,
      pollLogin,
      submitLoginCode,
    }),
    [
      conn, token, status, engagements, runs, activeId, setActiveId, running, coverage, pending,
      lastError, busy, connect, disconnect, refresh, doInit, doRun, doRunFor, doApprove, doResume,
      doStop, doDelete, clearEvents, auth, refreshAuth, setProviderAuth, disconnectProvider,
      setModel, startLogin, pollLogin, submitLoginCode,
    ],
  );

  const streamValue = useMemo<RunStreamCtx>(() => ({ events, orch }), [events, orch]);

  return (
    <Ctx.Provider value={value}>
      <StreamCtx.Provider value={streamValue}>{children}</StreamCtx.Provider>
    </Ctx.Provider>
  );
}

export function useControl(): ControlCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useControl must be used within ControlProvider");
  return ctx;
}

/** The live run's hot state — the raw event log and the folded orchestration view. Only the
 *  views that draw the stream should read this; it changes up to once per animation frame
 *  while a run is streaming. */
export function useRunStream(): RunStreamCtx {
  const ctx = useContext(StreamCtx);
  if (!ctx) throw new Error("useRunStream must be used within ControlProvider");
  return ctx;
}
