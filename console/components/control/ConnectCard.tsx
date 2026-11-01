"use client";

import { useState } from "react";
import { KeyRound, PlugZap, RefreshCw, Lock, AlertTriangle, Loader2, Unplug } from "lucide-react";
import { useControl } from "./ControlProvider";
import { Card } from "@/components/ui/primitives";
import { cx } from "@/lib/format";

export function ConnectCard() {
  const { conn, lastError, connect, disconnect, refresh, runs } = useControl();
  const [tok, setTok] = useState("");
  const [working, setWorking] = useState(false);

  const submit = async () => {
    if (!tok.trim()) return;
    setWorking(true);
    await connect(tok);
    setWorking(false);
    setTok("");
  };

  /* ---- connected: a slim status bar ---- */
  if (conn === "ready") {
    const liveRuns = Object.keys(runs).length;
    return (
      <Card className="flex flex-col gap-2 p-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2 text-sm">
          <span className="grid h-7 w-7 place-items-center rounded-lg bg-emerald-500/15 text-emerald-400">
            <PlugZap size={16} />
          </span>
          <span className="font-medium">Control plane connected</span>
          <span className="text-xs text-muted">
            · 127.0.0.1 · {liveRuns} live run{liveRuns === 1 ? "" : "s"}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => void refresh()}
            className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-line bg-card px-2.5 text-xs font-medium text-muted transition hover:text-fg"
          >
            <RefreshCw size={13} /> Refresh
          </button>
          <button
            onClick={disconnect}
            className="inline-flex h-8 items-center gap-1.5 rounded-lg border border-line bg-card px-2.5 text-xs font-medium text-muted transition hover:border-brand/40 hover:text-fg"
          >
            <Unplug size={13} /> Disconnect
          </button>
        </div>
      </Card>
    );
  }

  /* ---- offline: the plane isn't running ---- */
  if (conn === "offline") {
    return (
      <Card className="p-5">
        <div className="flex items-start gap-3">
          <span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-amber-500/15 text-amber-400">
            <AlertTriangle size={17} />
          </span>
          <div className="min-w-0">
            <h2 className="text-sm font-semibold">Control plane not detected</h2>
            <p className="mt-1 text-sm text-muted">
              This console is being served read-only. To launch and steer engagements from here, start the opt-in control
              plane in a terminal — it prints an access token you paste below:
            </p>
            <pre className="scroll-thin mt-3 overflow-x-auto rounded-lg border border-line bg-card2 p-3 text-xs">
              <code>python scripts/console_control.py --enable-control</code>
            </pre>
            {lastError && <p className="mt-2 text-xs text-rose-400">{lastError}</p>}
            <button
              onClick={() => void refresh()}
              className="mt-3 inline-flex h-9 items-center gap-1.5 rounded-lg border border-line bg-card px-3 text-sm font-medium transition hover:border-brand/40"
            >
              <RefreshCw size={14} /> Retry
            </button>
          </div>
        </div>
      </Card>
    );
  }

  /* ---- locked / unknown: enter the token ---- */
  return (
    <Card className="p-5">
      <div className="flex items-start gap-3">
        <span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-lg bg-brand/15 text-brand">
          <Lock size={17} />
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="text-sm font-semibold">
            {conn === "unknown" ? "Connect to the control plane" : "Control plane detected — enter the access token"}
          </h2>
          <p className="mt-1 text-sm text-muted">
            Paste the bearer token <code className="rounded bg-card2 px-1 py-0.5 text-[11px]">console_control.py</code> printed
            when it started. It is sent in the <code className="rounded bg-card2 px-1 py-0.5 text-[11px]">Authorization</code>{" "}
            header (never a cookie) and kept only for this browser tab.
          </p>
          <div className="mt-3 flex flex-col gap-2 sm:flex-row">
            <div className="relative flex-1">
              <KeyRound size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
              <input
                type="password"
                value={tok}
                onChange={(e) => setTok(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && void submit()}
                placeholder="Bearer token"
                autoComplete="off"
                className="h-9 w-full rounded-lg border border-line bg-card2 pl-8 pr-2 text-sm outline-none placeholder:text-muted focus:border-brand/50"
              />
            </div>
            <button
              onClick={() => void submit()}
              disabled={working || !tok.trim()}
              className={cx(
                "inline-flex h-9 items-center justify-center gap-1.5 rounded-lg bg-brand px-4 text-sm font-medium text-brand-fg transition hover:brightness-110",
                (working || !tok.trim()) && "cursor-not-allowed opacity-60",
              )}
            >
              {working ? <Loader2 size={14} className="animate-spin" /> : <PlugZap size={14} />} Connect
            </button>
          </div>
          {lastError && <p className="mt-2 text-xs text-rose-400">{lastError}</p>}
        </div>
      </div>
    </Card>
  );
}
