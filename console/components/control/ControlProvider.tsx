"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import * as api from "@/lib/control";
import type { ControlStatus, PendingItem, RunEvent, InitBody, RunBody, CliResult, AuthSnapshot, SetAuthBody, LoginStatus } from "@/lib/control";
import { ControlError, loadToken, saveToken, parseRunLine } from "@/lib/control";

// Connection state machine:
//   unknown → haven't probed yet
//   offline → nothing answering /api (read-only console.py, or the plane is down)
//   locked  → plane is up but no valid token yet (401)
//   ready   → /api/status returned 200
export type Conn = "unknown" | "offline" | "locked" | "ready";

const MAX_EVENTS = 500; // cap the in-memory run log

interface ControlCtx {
  conn: Conn;
  token: string;
  status: ControlStatus | null;
  engagements: string[];
  runs: Record<string, number>;
  activeId: string;
  setActiveId: (id: string) => void;
  running: boolean;
  events: RunEvent[];
  pending: PendingItem[];
  lastError: string;
  busy: boolean;
  connect: (token: string) => Promise<boolean>;
  disconnect: () => void;
  refresh: () => Promise<void>;
  doInit: (body: InitBody) => Promise<CliResult | null>;
  doRun: (body: RunBody) => Promise<boolean>;
  doApprove: (ids: string[] | "all") => Promise<boolean>;
  doResume: () => Promise<boolean>;
  doStop: () => Promise<void>;
  clearEvents: () => void;
  auth: AuthSnapshot | null;
  refreshAuth: () => Promise<void>;
  setProviderAuth: (provider: string, body: SetAuthBody) => Promise<boolean>;
  disconnectProvider: (provider: string) => Promise<void>;
  setModel: (provider: string, model: string) => Promise<boolean>;
  startLogin: (provider: string) => Promise<LoginStatus | null>;
  pollLogin: (provider: string) => Promise<LoginStatus | null>;
}

const Ctx = createContext<ControlCtx | null>(null);

function msgOf(e: unknown): string {
  if (e instanceof ControlError) return e.message;
  return e instanceof Error ? e.message : String(e);
}

export function ControlProvider({ children }: { children: React.ReactNode }) {
  const [conn, setConn] = useState<Conn>("unknown");
  const [token, setToken] = useState("");
  const [status, setStatus] = useState<ControlStatus | null>(null);
  const [activeId, setActiveIdState] = useState("");
  const [events, setEvents] = useState<RunEvent[]>([]);
  const [pending, setPending] = useState<PendingItem[]>([]);
  const [lastError, setLastError] = useState("");
  const [busy, setBusy] = useState(false);
  const [auth, setAuthState] = useState<AuthSnapshot | null>(null);
  const [lastRunConfig, setLastRunConfig] = useState<RunBody>({ allow: [], max_turns: 200, max_budget: 20 });

  const tokenRef = useRef(token);
  tokenRef.current = token;
  const streamAbort = useRef<AbortController | null>(null);

  const engagements = status?.engagements ?? [];
  const runs = status?.runs ?? {};
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
  }, []);

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
  }, []);

  const refreshApprovals = useCallback(async (id: string) => {
    if (!tokenRef.current || !id) {
      setPending([]);
      return;
    }
    try {
      setPending(await api.getApprovals(tokenRef.current, id));
    } catch {
      /* keep the last-known list on a transient error */
    }
  }, []);

  /* ---- SSE stream lifecycle ---- */
  const stopStream = useCallback(() => {
    if (streamAbort.current) {
      streamAbort.current.abort();
      streamAbort.current = null;
    }
  }, []);

  const startStream = useCallback(
    (id: string) => {
      stopStream();
      const ac = new AbortController();
      streamAbort.current = ac;
      void (async () => {
        try {
          await api.openRunStream(
            tokenRef.current,
            id,
            (line) => {
              const evs = parseRunLine(line);
              if (!evs.length) return;
              setEvents((prev) => {
                const next = [...prev, ...evs];
                return next.length > MAX_EVENTS ? next.slice(next.length - MAX_EVENTS) : next;
              });
              if (evs.some((e) => e.kind === "result")) {
                // this invocation finished — close the tail and settle status + approvals
                ac.abort();
                if (streamAbort.current === ac) streamAbort.current = null;
                void refresh();
                void refreshApprovals(id);
              }
            },
            ac.signal,
          );
        } catch (e) {
          if (e instanceof ControlError && e.kind === "unauthorized") setConn("locked");
        }
      })();
    },
    [stopStream, refresh, refreshApprovals],
  );

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

  /* ---- poll status while connected (tracks live run pids) ---- */
  useEffect(() => {
    if (conn !== "ready") return;
    const t = setInterval(() => void refresh(), 5000);
    return () => clearInterval(t);
  }, [conn, refresh]);

  /* ---- poll approvals for the active engagement ---- */
  useEffect(() => {
    if (conn !== "ready" || !activeId) {
      setPending([]);
      return;
    }
    void refreshApprovals(activeId);
    const t = setInterval(() => void refreshApprovals(activeId), 4000);
    return () => clearInterval(t);
  }, [conn, activeId, refreshApprovals]);

  /* ---- (re)start the stream whenever the active engagement has a live run ---- */
  const runPid = status?.runs?.[activeId];
  useEffect(() => {
    if (conn === "ready" && activeId && runPid != null) {
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
    setToken("");
    saveToken("");
    setStatus(null);
    setEvents([]);
    setPending([]);
    setLastError("");
    setConn("locked");
  }, [stopStream]);

  const setActiveId = useCallback(
    (id: string) => {
      stopStream();
      setEvents([]); // the run log is per-engagement
      setActiveIdState(id);
    },
    [stopStream],
  );

  const doInit = useCallback(
    async (body: InitBody): Promise<CliResult | null> => {
      setBusy(true);
      setLastError("");
      try {
        const r = await api.initEngagement(tokenRef.current, body);
        if (!r.ok) setLastError((r.stderr || r.error || "init failed").trim());
        await refresh();
        return r;
      } catch (e) {
        setLastError(msgOf(e));
        return null;
      } finally {
        setBusy(false);
      }
    },
    [refresh],
  );

  const doRun = useCallback(
    async (body: RunBody): Promise<boolean> => {
      if (!activeId) {
        setLastError("Select an engagement first.");
        return false;
      }
      setBusy(true);
      setLastError("");
      try {
        if (!body.resume) setEvents([]);
        const r = await api.runEngagement(tokenRef.current, activeId, body);
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
    [activeId, refresh],
  );

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

  const clearEvents = useCallback(() => setEvents([]), []);

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

  // load provider auth once the plane is reachable
  useEffect(() => {
    if (conn === "ready") void refreshAuth();
  }, [conn, refreshAuth]);

  const value: ControlCtx = {
    conn,
    token,
    status,
    engagements,
    runs,
    activeId,
    setActiveId,
    running,
    events,
    pending,
    lastError,
    busy,
    connect,
    disconnect,
    refresh,
    doInit,
    doRun,
    doApprove,
    doResume,
    doStop,
    clearEvents,
    auth,
    refreshAuth,
    setProviderAuth,
    disconnectProvider,
    setModel,
    startLogin,
    pollLogin,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useControl(): ControlCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useControl must be used within ControlProvider");
  return ctx;
}
