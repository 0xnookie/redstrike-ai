"use client";

import { useState } from "react";
import { Trash2, Loader2, X } from "lucide-react";
import { useControl } from "./ControlProvider";
import { useConsole } from "@/lib/store";
import { cx } from "@/lib/format";

/**
 * Delete a control-plane engagement (removes its directory on disk). Only shown for a
 * real engagement the connected control plane knows about; refuses while it's running.
 * Two-click confirm; on success it re-reads the console's engagement list.
 */
export function DeleteEngagementButton({ id }: { id: string }) {
  const { conn, engagements, runs, busy, doDelete } = useControl();
  const { reloadEngagements } = useConsole();
  const [confirm, setConfirm] = useState(false);
  const [working, setWorking] = useState(false);

  // only a real control-plane engagement can be deleted from here
  if (conn !== "ready" || !engagements.includes(id)) return null;

  const isRunning = runs[id] != null;

  if (isRunning) {
    return (
      <span
        className="inline-flex h-8 cursor-not-allowed items-center gap-1.5 rounded-full border border-line px-3 text-xs text-faint"
        title="Stop the run before deleting this engagement"
      >
        <Trash2 size={13} /> Delete
      </span>
    );
  }

  if (!confirm) {
    return (
      <button
        onClick={() => setConfirm(true)}
        className="inline-flex h-8 items-center gap-1.5 rounded-full border border-line px-3 text-xs font-medium text-muted transition hover:border-rose-500/40 hover:text-rose-400"
      >
        <Trash2 size={13} /> Delete
      </button>
    );
  }

  const onDelete = async () => {
    setWorking(true);
    const ok = await doDelete(id);
    setWorking(false);
    if (ok) {
      setConfirm(false);
      await reloadEngagements();
    }
  };

  return (
    <span className="inline-flex items-center gap-1.5">
      <button
        onClick={() => void onDelete()}
        disabled={working || busy}
        className={cx(
          "inline-flex h-8 items-center gap-1.5 rounded-full border border-rose-500/40 bg-rose-500/10 px-3 text-xs font-medium text-rose-400 transition hover:bg-rose-500/20",
          (working || busy) && "cursor-not-allowed opacity-60",
        )}
      >
        {working ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />} Confirm delete
      </button>
      <button
        onClick={() => setConfirm(false)}
        aria-label="Cancel delete"
        className="grid h-8 w-8 place-items-center rounded-full border border-line text-muted transition hover:text-fg"
      >
        <X size={13} />
      </button>
    </span>
  );
}
