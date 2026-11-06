"use client";

import { useEffect } from "react";
import Link from "next/link";
import { Radio, Rocket, Square, Loader2 } from "lucide-react";
import { useControl } from "./ControlProvider";
import { ApprovalsPanel } from "./ApprovalsPanel";
import { RunStream } from "./RunStream";

/**
 * Live-run steering for a single engagement, shown inside the engagement detail.
 * Keeps the control plane's active engagement in sync with the one on screen, then
 * surfaces run status + the approvals queue + the raw run log. Degrades to a hint
 * when the control plane is offline or the engagement isn't one it can run.
 */
export function LiveRun({ engagementId, onLaunch }: { engagementId: string; onLaunch: () => void }) {
  const { conn, engagements, activeId, setActiveId, running, busy, pending, doStop } = useControl();
  const known = engagements.includes(engagementId);

  useEffect(() => {
    if (known && engagementId && engagementId !== activeId) setActiveId(engagementId);
  }, [known, engagementId, activeId, setActiveId]);

  if (conn !== "ready") {
    return (
      <p className="rounded-lg border border-dashed border-line bg-card2 px-3 py-2.5 text-xs text-muted">
        Connect the control plane in{" "}
        <Link href="/settings" className="text-fg underline-offset-2 hover:underline">
          Settings → Agent runtimes
        </Link>{" "}
        to launch and steer runs from here.
      </p>
    );
  }

  if (!known) {
    return (
      <p className="rounded-lg border border-dashed border-line bg-card2 px-3 py-2.5 text-xs text-muted">
        This engagement isn’t on the connected control plane, so it can’t be run from here. Scaffold it with
        “New engagement”, or load its data for a read-only view.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        {running ? (
          <>
            <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400">
              <Radio size={12} className="animate-pulse" /> Run in progress
            </span>
            <button
              onClick={() => void doStop()}
              disabled={busy}
              className="ml-auto inline-flex h-8 items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 text-xs font-medium text-rose-400 transition hover:bg-rose-500/20 disabled:opacity-60"
            >
              {busy ? <Loader2 size={13} className="animate-spin" /> : <Square size={12} />} Stop
            </button>
          </>
        ) : (
          <>
            <span className="text-xs text-muted">Idle — no run in progress.</span>
            <button
              onClick={onLaunch}
              className="ml-auto inline-flex h-8 items-center gap-1.5 rounded-lg bg-brand px-3 text-xs font-medium text-brand-fg transition hover:brightness-110"
            >
              <Rocket size={13} /> Launch run
            </button>
          </>
        )}
      </div>

      {(running || pending.length > 0) && <ApprovalsPanel />}
      <RunStream />
    </div>
  );
}
